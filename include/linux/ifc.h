/*
*
* /linux/include/linux/ifc.h
*
* Author: Thomas Pasquier <tfjmp2@cam.ac.uk>
*
* Copyright (C) 2015 University of Cambridge
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License version 2, as
* published by the Free Software Foundation.
*
*/
#ifndef _LINUX_IFC_H
#define _LINUX_IFC_H

#ifdef CONFIG_SECURITY_IFC

#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/bsearch.h>
#include <uapi/linux/ifc.h>
#include <uapi/linux/camflow.h>
#include <linux/crypto.h>

struct ifc_bridge{
  bool spawner;
  bool bridge;
  pid_t remote_pid;
};

struct ifc_struct{
  struct ifc_context context;
  struct ifc_bridge bridge;
};

int ifc_create_bridge(pid_t parent_pid, char **argv[]);
int ifc_bridge_send_message(void* data, size_t size);
int ifc_bridge_init(void);

extern atomic64_t ifc_tag_count;
extern struct crypto_cipher *ifc_tfm;

static inline void ifc_save_tag(tag_t tag){
  // TODO
}

static inline uint64_t ifc_next_tag_count( void ){
  uint64_t tag = (uint64_t)atomic64_inc_return(&ifc_tag_count);
  ifc_save_tag(tag);
  return tag;
}

static inline void ifc_set_tag_count(uint64_t count){
  atomic64_set(&ifc_tag_count, count);
}

static inline tag_t ifc_create_tag(void){
  /*uint64_t in = ifc_next_tag_count();
  uint64_t out = 0;
  crypto_cipher_encrypt_one(ifc_tfm, (u8*)&out, (u8*)&in);
  return out;*/
  return ifc_next_tag_count();
}

static inline bool ifc_tag_valid(tag_t tag){
  tag_t counter = atomic64_read(&ifc_tag_count);
  if(tag>counter)
    return false;
  return true;
}

static int ifc_compare(const void *lhs, const void *rhs) {
    uint64_t lhs_integer = *(const uint64_t *)(lhs);
    uint64_t rhs_integer = *(const uint64_t *)(rhs);

    if (lhs_integer < rhs_integer) return -1;
    if (lhs_integer > rhs_integer) return 1;
    return 0;
}

static inline void ifc_sort_label(struct ifc_label* label){
  sort(label->array, label->size, sizeof(uint64_t), &ifc_compare, NULL);
}

static inline bool ifc_is_subset(struct ifc_label* sub, struct ifc_label* set){
  int i=0, j=0;

  if(sub->size == 0) // empty set is subset of everything
    return true;

  if(set->size < sub->size)
    return false;

  while( i < sub->size && j < set->size)
  {
    if( set->array[j] < sub->array[i] ){
      j++;
    }else if( set->array[j] == sub->array[i] ){
      j++;
      i++;
    }else if( set->array[j] > sub->array[i] ){
      return false;
    }
  }

  if(i < sub->size)
    return false;
  return true;
}

static inline bool ifc_can_flow(struct ifc_context *from, struct ifc_context* to){
  if(from->trusted==IFC_TRUSTED || to->trusted==IFC_TRUSTED){
    return true;
  }
  if(!ifc_is_subset(&from->secrecy, &to->secrecy)){
    return false;
  }
  if(!ifc_is_subset(&to->integrity, &from->integrity)){
    return false;
  }
  return true;
}

static inline bool ifc_contains_value(struct ifc_label* label, tag_t value){
  if(bsearch(&value, label->array, label->size, sizeof(uint64_t), &ifc_compare)==NULL){
    return false;
  }
  return true;
}

static inline bool ifc_is_labelled(struct ifc_context* context){
  if(context->secrecy.size > 0 || context->integrity.size > 0)
    return true;
  return false;
}

static inline int ifc_add_privilege(struct ifc_context* context, uint8_t type, tag_t tag){
  struct ifc_label* privilege=NULL;

  switch(type){
    case IFC_SECRECY_P:
      privilege = &context->secrecy_p;
      break;
    case IFC_INTEGRITY_P:
      privilege = &context->integrity_p;
      break;
    case IFC_SECRECY_N:
      privilege = &context->secrecy_n;
      break;
    case IFC_INTEGRITY_N:
      privilege = &context->integrity_n;
      break;
  }

  if(privilege==NULL)
    return -EINVAL;

  if(privilege->size +1 >= IFC_LABEL_MAX_SIZE) // label is full
    return -ENOMEM;

  if(ifc_contains_value(privilege, tag)) // aleady contains tag
    return -EINVAL;

  privilege->array[privilege->size] = tag;
  privilege->size++;
  ifc_sort_label(privilege);
  return 0;
}

static inline int ifc_remove_privilege(struct ifc_context* context, uint8_t type, tag_t tag){
  struct ifc_label* privilege=NULL;
  int i = 0;

  switch(type){
    case IFC_SECRECY_P:
      privilege = &context->secrecy_p;
      break;
    case IFC_INTEGRITY_P:
      privilege = &context->integrity_p;
      break;
    case IFC_SECRECY_N:
      privilege = &context->secrecy_n;
      break;
    case IFC_INTEGRITY_N:
      privilege = &context->integrity_n;
      break;
  }

  if(privilege==NULL)
    return -EINVAL;

  if(privilege->size <= 0) // label is empty
    return -EINVAL;

  if(!ifc_contains_value(privilege, tag)) // does not contains the privilege to be removed
    return -EINVAL;

  /* remove the tag */
  for(i=0; i < privilege->size; i++){
    if(privilege->array[i]==tag)
      break;
  }
  for(;i < privilege->size-1; i++){
    privilege->array[i]=privilege->array[i+1];
  }
  privilege->size--;
  return 0;
}

static inline int ifc_add_tag(struct ifc_context* context, uint8_t type, tag_t tag){
  struct ifc_label* label=NULL;
  struct ifc_label* privilege=NULL;

  switch(type){
    case IFC_SECRECY:
      label = &context->secrecy;
      privilege = &context->secrecy_p;
      break;
    case IFC_INTEGRITY:
      label = &context->integrity;
      privilege = &context->integrity_p;
      break;
  }

  if(privilege==NULL || label==NULL)
    return -EINVAL;

  if(label->size + 1 >= IFC_LABEL_MAX_SIZE) // label is full
    return -ENOMEM;

  if(ifc_contains_value(label, tag)) // aleady contains tag
    return -EINVAL;

  if(!ifc_contains_value(privilege, tag)) // not appropriate privilege
    return -EPERM;

  label->array[label->size]=tag;
  label->size++;
  ifc_sort_label(label);
  return 0;
}

static inline int ifc_add_tag_no_check(struct ifc_context* context, uint8_t type, tag_t tag){
  struct ifc_label* label=NULL;

  switch(type){
    case IFC_SECRECY:
      label = &context->secrecy;
      break;
    case IFC_INTEGRITY:
      label = &context->integrity;
      break;
  }

  if(label==NULL)
    return -EINVAL;

  if(label->size >= IFC_LABEL_MAX_SIZE) // label is full
    return -ENOMEM;

  label->array[label->size]=tag;
  label->size++;
  ifc_sort_label(label);
  return 0;
}

static inline int ifc_remove_tag(struct ifc_context* context, uint8_t type, tag_t tag){
  struct ifc_label* label=NULL;
  struct ifc_label* privilege=NULL;
  int i = 0;

  switch(type){
    case IFC_SECRECY:
      label = &context->secrecy;
      privilege = &context->secrecy_n;
      break;
    case IFC_INTEGRITY:
      label = &context->integrity;
      privilege = &context->integrity_n;
      break;
  }

  if(privilege==NULL || label==NULL)
    return -EINVAL;

  if(label->size <= 0) // label is empty
    return -EINVAL;

  if(!ifc_contains_value(label, tag)) // the tag is not there to removed
    return -EINVAL;

  if(!ifc_contains_value(privilege, tag)) // does not have the proper privileges
    return -EPERM;

  /* remove the tag */
  for(i=0; i < label->size; i++){
    if(label->array[i]==tag)
      break;
  }
  for(;i < label->size-1; i++){
    label->array[i]=label->array[i+1];
  }
  label->size--;
  return 0;
}

static inline int ifc_remove_tag_no_check(struct ifc_context* context, uint8_t type, tag_t tag){
  struct ifc_label* label=NULL;
  int i = 0;

  switch(type){
    case IFC_SECRECY:
      label = &context->secrecy;
      break;
    case IFC_INTEGRITY:
      label = &context->integrity;
      break;
  }

  if(label==NULL)
    return -EINVAL;

  if(label->size <= 0) // label is empty
    return -EINVAL;

  if(!ifc_contains_value(label, tag)) // the tag is not there to removed
    return -EINVAL;

  /* remove the tag */
  for(i=0; i < label->size; i++){
    if(label->array[i]==tag)
      break;
  }
  for(;i < label->size-1; i++){
    label->array[i]=label->array[i+1];
  }
  label->size--;
  return 0;
}

static inline void print_label(struct ifc_label* label){
  int i;
  for(i=0; i < label->size; i++){
    printk(KERN_INFO "%llu", label->array[i]);
  }
}

static inline int ifc_merge_context(struct ifc_context* main, struct ifc_context* to_add){
  int i;

  // too conservative TODO change this
  if(main->secrecy.size + to_add->secrecy.size > IFC_LABEL_MAX_SIZE)
      return -ENOMEM;
  if(main->secrecy.size + to_add->secrecy.size > IFC_LABEL_MAX_SIZE)
      return -ENOMEM;

  for(i=0; i<to_add->secrecy.size; i++){
    if(!ifc_contains_value(&main->secrecy, to_add->secrecy.array[i])){
      main->secrecy.array[main->secrecy.size]=to_add->secrecy.array[i];
      main->secrecy.size++;
    }
  }
  ifc_sort_label(&main->secrecy);

  for(i=0; i<to_add->integrity.size; i++){
    if(!ifc_contains_value(&main->integrity, to_add->integrity.array[i])){
      main->secrecy.array[main->integrity.size]=to_add->integrity.array[i];
      main->integrity.size++;
    }
  }
  ifc_sort_label(&main->integrity);
  return 0;
}

static inline void print_context(struct ifc_context* context){
  if(context->trusted==IFC_TRUSTED){
    printk(KERN_INFO "TRUSTED");
  }
  printk(KERN_INFO "SECRECY");
  print_label(&context->secrecy);
  printk(KERN_INFO "INTEGRITY");
  print_label(&context->integrity);
}

#endif
#endif
