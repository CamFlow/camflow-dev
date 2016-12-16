/*
*
* Author: Thomas Pasquier <thomas.pasquier@cl.cam.ac.uk>
*
* Copyright (C) 2015 University of Cambridge
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License version 2, as
* published by the Free Software Foundation; either version 2 of the License, or
*	(at your option) any later version.
*
*/
#ifndef _LINUX_PROVENANCE_H
#define _LINUX_PROVENANCE_H

#ifdef CONFIG_SECURITY_PROVENANCE

#include <linux/slab.h>
#include <linux/types.h>
#include <linux/bug.h>
#include <linux/socket.h>
#include <linux/camflow.h>
#include <uapi/linux/mman.h>
#include <uapi/linux/camflow.h>
#include <uapi/linux/provenance.h>
#include <uapi/linux/stat.h>
#include <linux/fs.h>

#include "camflow_utils.h"
#include "provenance_filter.h"
#include "provenance_relay.h"

#define ASSIGN_NODE_ID 0

#define prov_next_relation_id() ((uint64_t)atomic64_inc_return(&prov_relation_id))
#define prov_next_node_id() ((uint64_t)atomic64_inc_return(&prov_node_id))
#define free_provenance(prov) kmem_cache_free(provenance_cache, prov)

extern atomic64_t prov_relation_id;
extern atomic64_t prov_node_id;
extern struct kmem_cache *provenance_cache;

enum provenance_mutex_lock_class {
  PROVENANCE_MUTEX_TASK,
  PROVENANCE_MUTEX_INODE,
  PROVENANCE_MUTEX_BPRM,
};

#define get_mutex(n) &(n->node_info.lprov.l)
#define lock_node(n, class) mutex_lock_nested(get_mutex(n), class)
#define unlock_node(n) mutex_unlock(get_mutex(n))
#define init_mutex_node(n) mutex_init(get_mutex(n))

static inline void put_prov(prov_msg_t* n){
  if(likely(n!=NULL)){
    unlock_node(n);
  }
}

static inline prov_msg_t* alloc_provenance(uint64_t ntype, gfp_t gfp)
{
  prov_msg_t* prov =  kmem_cache_zalloc(provenance_cache, gfp);
  if(!prov){
    return NULL;
  }
  init_mutex_node(prov);
  prov_type(prov)=ntype;
  return prov;
}

extern uint32_t prov_machine_id;
extern uint32_t prov_boot_id;

static inline void set_node_id(prov_msg_t* node, uint64_t nid){
  if(nid==ASSIGN_NODE_ID){
    node_identifier(node).id=prov_next_node_id();
  }else{
    node_identifier(node).id=nid;
  }
  node_identifier(node).boot_id=prov_boot_id;
  node_identifier(node).machine_id=prov_machine_id;
}

static inline void copy_node_info(prov_identifier_t* dest, prov_identifier_t* src){
  memcpy(dest, src, sizeof(prov_identifier_t));
}

static inline void __record_node(prov_msg_t* node){
  if(filter_node(node) || provenance_is_recorded(node)){ // filtered or already recorded
    return;
  }

  set_recorded(node);
  if(unlikely(node_identifier(node).machine_id!=prov_machine_id)){
    node_identifier(node).machine_id=prov_machine_id;
  }
  prov_write(node);
}

static inline void __record_relation(uint64_t type,
                                      prov_identifier_t* from,
                                      prov_identifier_t* to,
                                      prov_msg_t* relation,
                                      uint8_t allowed,
                                      struct file *file){
  prov_type(relation)=type;
  relation_identifier(relation).id = prov_next_relation_id();
  relation_identifier(relation).boot_id = prov_boot_id;
  relation_identifier(relation).machine_id = prov_machine_id;
  relation->relation_info.allowed=allowed;
  copy_node_info(&relation->relation_info.snd, from);
  copy_node_info(&relation->relation_info.rcv, to);
  if(file!=NULL){
    relation->relation_info.set = FILE_INFO_SET;
  	relation->relation_info.offset = file->f_pos;
  }
  prov_write(relation);
}

static inline void __update_version(uint64_t type, prov_msg_t* prov){
  prov_msg_t old_prov;
  prov_msg_t relation;

  if(filter_update_node(type, prov)){ // the relation is filtered out
    goto out;
  }

  memset(&relation, 0, sizeof(prov_msg_t));
  memcpy(&old_prov, prov, sizeof(prov_msg_t));
  node_identifier(prov).version++;
  clear_recorded(prov);
  if(node_identifier(prov).type == ACT_TASK){
    __record_relation(RL_VERSION_PROCESS, &(old_prov.msg_info.identifier), &(prov->msg_info.identifier), &relation, FLOW_ALLOWED, NULL);
  }else{
    __record_relation(RL_VERSION, &(old_prov.msg_info.identifier), &(prov->msg_info.identifier), &relation, FLOW_ALLOWED, NULL);
  }

out:
  return;
}

static inline void __propagate(uint64_t type,
                            prov_msg_t* from,
                            prov_msg_t* to,
                            prov_msg_t* relation,
                            uint8_t allowed){

  if(!provenance_does_propagate(from)){
    goto out;
  }

  if( filter_propagate_node(to) ){
    goto out;
  }

  if( filter_propagate_relation(type, allowed) ){ // is it filtered
    goto out;
  }

  set_tracked(to);// receiving node become tracked
  set_propagate(to); // continue to propagate
  if(!prov_bloom_empty(prov_taint(from))){
    prov_bloom_merge(prov_taint(to), prov_taint(from));
    prov_bloom_merge(prov_taint(relation), prov_taint(from));
  }
out:
  return;
}

static inline void record_relation(uint64_t type,
                                    prov_msg_t* from,
                                    prov_msg_t* to,
                                    uint8_t allowed,
                                    struct file *file){
  prov_msg_t relation;

  if( unlikely(from==NULL || to==NULL) ){ // should not occur
    return;
  }

  if(!provenance_is_tracked(from) && !provenance_is_tracked(to) && !prov_all ){
    return;
  }

  // one of the node should not appear in the record, ignore the relation
  if(filter_node(from) || filter_node(to)){
    return;
  }

  // should the relation appear
  if(filter_relation(type, allowed)){
    goto out;
  }
  memset(&relation, 0, sizeof(prov_msg_t));
  __record_node(from);
  __propagate(type, from, to, &relation, allowed);
  __record_node(to);
  __update_version(type, to);
  __record_node(to);
  __record_relation(type, &(from->msg_info.identifier), &(to->msg_info.identifier), &relation, allowed, file);
out:
  return;
}
#endif
#endif /* _LINUX_PROVENANCE_H */
