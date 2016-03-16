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

#include <linux/sort.h>
#include <linux/bsearch.h>
#include <uapi/linux/ifc.h>
#include <linux/crypto.h>

extern atomic64_t ifc_tag_count;
extern struct crypto_cipher *ifc_tfm;

static inline void save_tag(uint64_t tag){
  // TODO
}

static inline uint64_t ifc_next_tag_count( void ){
  uint64_t tag = (uint64_t)atomic64_inc_return(&ifc_tag_count);
  save_tag(tag);
  return tag;
}

static inline void ifc_set_tag_count(uint64_t count){
  atomic64_set(&ifc_tag_count, count);
}

static inline uint64_t ifc_create_tag(void){
  uint64_t in = ifc_next_tag_count();
  uint64_t out = 0;
  crypto_cipher_encrypt_one(ifc_tfm, (u8*)&out, (u8*)&in);
  return out;
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

static inline bool ifc_is_subset(struct ifc_label* set, struct ifc_label* sub){
  int i=0, j=0;
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

static inline bool ifc_contains_value(struct ifc_label* label, uint64_t value){
  if(bsearch(&value, label->array, label->size, sizeof(uint64_t), &ifc_compare)==NULL){
    return false;
  }
  return true;
}

static inline bool is_labelled(struct ifc_context* context){
  if(context->secrecy.size > 0 || context->integrity.size > 0)
    return true;
  return false;
}

static inline bool ifc_add_tag(struct ifc_context* context, uint8_t type, uint64_t tag){
  struct ifc_label* label=NULL;
  struct ifc_label* privilege=NULL;

  switch(type){
    case IFC_SECRECY:
      label = &context->secrecy;
      break;
    case IFC_INTEGRITY:
      label = &context->integrity;
      privilege = &context->integrity_p;
      break;
  }

  if(label->size >= IFC_LABEL_MAX_SIZE) // label is full
    return false;

  if(ifc_contains_value(label, tag)) // aleady contains tag
    return false;

  if(privilege!=NULL){
    if(!ifc_contains_value(privilege, tag)) // not appropriate privilege
      return false;
  }
  label->array[label->size]=tag;
  label->size++;
  ifc_sort_label(label);
  return true;
}

static inline bool ifc_remove_tag(struct ifc_context* context, uint8_t type, uint64_t tag){
  struct ifc_label* label=NULL;
  struct ifc_label* privilege=NULL;
  int i = 0;

  switch(type){
    case IFC_SECRECY:
      label = &context->secrecy;
      privilege = &context->integrity_p;
      break;
    case IFC_INTEGRITY:
      label = &context->integrity;
      break;
  }

  if(label->size <= 0) // label is empty
    return false;

  if(!ifc_contains_value(label, tag)) // the tag is not there to removed
    return false;

  if(privilege!=NULL){
    if(!ifc_contains_value(privilege, tag)) // does not have the proper privileges
      return false;
  }

  /* remove the tag */
  for(i=0; i < label->size; i++){
    if(label->array[i]==tag)
      break;
  }
  for(;i < label->size-1; i++){
    label->array[i]=label->array[i+1];
  }
  label->size--;
  return true;
}

#endif
