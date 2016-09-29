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
#include <uapi/linux/ifc.h>
#include <uapi/linux/mman.h>
#include <uapi/linux/camflow.h>
#include <uapi/linux/provenance.h>
#include <uapi/linux/stat.h>

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

static inline struct prov_msg_t* prov_from_pid(pid_t pid){
  struct task_struct *dest = find_task_by_vpid(pid);
  if(!dest)
    return NULL;
  return __task_cred(dest)->provenance;
}

static inline prov_msg_t* alloc_provenance(uint32_t ntype, gfp_t gfp)
{
  prov_msg_t* prov =  kmem_cache_zalloc(provenance_cache, gfp);
  if(!prov){
    return NULL;
  }

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

static inline void record_node(prov_msg_t* node){
  if(filter_node(node)){
    return;
  }

  set_recorded(node);
  prov_write(node);
}

static inline void copy_node_info(prov_identifier_t* dest, prov_identifier_t* src){
  memcpy(dest, src, sizeof(prov_identifier_t));
}

static inline void record_relation(uint32_t type, prov_msg_t* from, prov_msg_t* to, uint8_t allowed);

static inline void prov_update_version(prov_msg_t* prov){
  prov_msg_t old_prov;
  memcpy(&old_prov, prov, sizeof(prov_msg_t));
  node_identifier(prov).version++;
  clear_recorded(prov);
  if(node_identifier(prov).type == MSG_TASK){
    record_relation(RL_VERSION_PROCESS, &old_prov, prov, FLOW_ALLOWED);
  }else{
    record_relation(RL_VERSION, &old_prov, prov, FLOW_ALLOWED);
  }
}

static inline void record_relation(uint32_t type, prov_msg_t* from, prov_msg_t* to, uint8_t allowed){
  prov_msg_t relation;

  if(filter_relation(type, from, to, allowed)){
    return;
  }

  memset(&relation, 0, sizeof(prov_msg_t));
  /* propagate tracked */
  if( !filter_propagate_relation(type, from, to, allowed) ){ // it is not filtered
    set_tracked(to);// receiving node become tracked
    set_propagate(to); // continue to propagate
    prov_bloom_merge(prov_taint(to), prov_taint(from));
    prov_bloom_merge(prov_taint(&relation), prov_taint(from));
  }

  if(should_update_node(type, to)){ // it is none of the above types
    prov_update_version(to);
  }

  if( !provenance_is_recorded(from) ){
    record_node(from);
  }

  if( !provenance_is_recorded(to) ){
    record_node(to);
  }

  prov_type((&relation))=MSG_RELATION;
  relation_identifier((&relation)).id = prov_next_relation_id();
  relation_identifier((&relation)).boot_id = prov_boot_id;
  relation_identifier((&relation)).machine_id = prov_machine_id;
  relation.relation_info.type=type;
  relation.relation_info.allowed=allowed;
  copy_node_info(&relation.relation_info.snd, &from->node_info.identifier);
  copy_node_info(&relation.relation_info.rcv, &to->node_info.identifier);
  prov_write(&relation);
}

// incoming packet
static inline void record_pck_to_inode(prov_msg_t* pck, prov_msg_t* inode){
  prov_msg_t relation;

  memset(&relation, 0, sizeof(prov_msg_t));

  if(should_update_node(RL_WRITE, inode)){
    prov_update_version(inode);
  }

  if( !provenance_is_recorded(inode) ){
    record_node(inode);
  }

  prov_write(pck);

  prov_type((&relation))=MSG_RELATION;
  relation_identifier((&relation)).id = prov_next_relation_id();
  relation_identifier((&relation)).boot_id = prov_boot_id;
  relation_identifier((&relation)).machine_id = prov_machine_id;
  relation.relation_info.type=RL_RCV;
  relation.relation_info.allowed=FLOW_ALLOWED;
  copy_node_info(&relation.relation_info.snd, &pck->node_info.identifier);
  copy_node_info(&relation.relation_info.rcv, &inode->node_info.identifier);
  prov_write(&relation);
}

// outgoing packet
static inline void record_inode_to_pck(prov_msg_t* inode, prov_msg_t* pck){
  prov_msg_t relation;

  memset(&relation, 0, sizeof(prov_msg_t));

  if( !provenance_is_recorded(inode) ){
    record_node(inode);
  }

  prov_write(pck);

  prov_type((&relation))=MSG_RELATION;
  relation_identifier((&relation)).id = prov_next_relation_id();
  relation_identifier((&relation)).boot_id = prov_boot_id;
  relation_identifier((&relation)).machine_id = prov_machine_id;
  relation.relation_info.type=RL_SND;
  relation.relation_info.allowed=FLOW_ALLOWED;
  copy_node_info(&relation.relation_info.snd, &inode->node_info.identifier);
  copy_node_info(&relation.relation_info.rcv, &pck->node_info.identifier);
  prov_write(&relation);
}

static inline void provenance_mark_as_opaque(const char* name){
  struct inode* in;
  prov_msg_t* prov;

  in = file_name_to_inode(name);
  if(!in){
    printk(KERN_ERR "Provenance: could not find %s file.", name);
  }else{
    prov = inode_get_provenance(in);
    if(prov){
      set_opaque(prov);
    }
  }
}
#endif
#endif /* _LINUX_PROVENANCE_H */
