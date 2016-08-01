/*
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
#ifndef _LINUX_PROVENANCE_H
#define _LINUX_PROVENANCE_H

#ifdef CONFIG_SECURITY_PROVENANCE

#include <linux/slab.h>
#include <linux/types.h>
#include <linux/bug.h>
#include <linux/relay.h>
#include <linux/socket.h>
#include <linux/camflow.h>
#include <uapi/linux/ifc.h>
#include <uapi/linux/mman.h>
#include <uapi/linux/camflow.h>
#include <uapi/linux/provenance.h>
#include <uapi/linux/stat.h>

#include "camflow_utils.h"
#include "provenance_filter.h"

#define ASSIGN_NODE_ID 0

#define prov_next_edgeid() ((uint64_t)atomic64_inc_return(&prov_edge_id))
#define prov_next_nodeid() ((uint64_t)atomic64_inc_return(&prov_node_id))
#define free_provenance(prov) kmem_cache_free(provenance_cache, prov)
#define free_long_provenance(prov) kmem_cache_free(long_provenance_cache, prov)

extern atomic64_t prov_edge_id;
extern atomic64_t prov_node_id;
extern struct rchan *prov_chan;
extern struct rchan *long_prov_chan;
extern struct kmem_cache *provenance_cache;
extern struct kmem_cache *long_provenance_cache;

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
    node_identifier(node).id=prov_next_nodeid();
  }else{
    node_identifier(node).id=nid;
  }
  node_identifier(node).boot_id=prov_boot_id;
  node_identifier(node).machine_id=prov_machine_id;
}

static inline long_prov_msg_t* alloc_long_provenance(uint32_t ntype, gfp_t gfp)
{
  long_prov_msg_t* prov =  kmem_cache_zalloc(long_provenance_cache, gfp);
  if(!prov){
    return NULL;
  }

  prov_type(prov)=ntype;
  return prov;
}

static inline void prov_write(prov_msg_t* msg)
{
  if(prov_chan==NULL) // not set yet
  {
    printk(KERN_ERR "Provenance: trying to write before nchan ready\n");
    return;
  }
  relay_write(prov_chan, msg, sizeof(prov_msg_t));
}

static inline void long_prov_write(long_prov_msg_t* msg){
  if(long_prov_chan==NULL) // not set yet
  {
    printk(KERN_ERR "Provenance: trying to write before nchan ready\n");
    return;
  }
  /* create a new node to containe the info */
  node_identifier(msg).id=prov_next_nodeid();
  node_identifier(msg).boot_id=prov_boot_id;
  node_identifier(msg).machine_id=prov_machine_id;
  relay_write(long_prov_chan, msg, sizeof(long_prov_msg_t));
}

static inline int prov_print(const char *fmt, ...)
{
  long_prov_msg_t* msg;
  int length;
  va_list args;
  va_start(args, fmt);

  msg = (long_prov_msg_t*)kzalloc(sizeof(long_prov_msg_t), GFP_KERNEL);

  /* set message type */
  prov_type(msg)=MSG_STR;
  msg->str_info.length = vscnprintf(msg->str_info.str, 4096, fmt, args);
  long_prov_write(msg);
  va_end(args);
  length = msg->str_info.length;
  kfree(msg);
  return length;
}

static inline void record_node(prov_msg_t* node){
  if(filter_node(node)){
    return;
  }

  node_kern(node).recorded=NODE_RECORDED;
  prov_write(node);
}

static inline void copy_node_info(prov_identifier_t* dest, prov_identifier_t* src){
  memcpy(dest, src, sizeof(prov_identifier_t));
}

static inline void record_edge(uint32_t type, prov_msg_t* from, prov_msg_t* to, uint8_t allowed){
  prov_msg_t edge;

  if(filter_edge(type, from, to, allowed)){
    return;
  }

  /* propagate tracked */
  if(node_kern(from).propagate > 0 && node_kern(from).tracked){
    node_kern(to).tracked = NODE_TRACKED; // receiving node become tracked
    // update receiving propagation depth
    if(node_kern(from).propagate - 1 > node_kern(to).propagate){
      node_kern(to).propagate = node_kern(from).propagate - 1;
    }
  }

  if(!(node_kern(from).recorded == NODE_RECORDED) )
    record_node(from);

  if(!(node_kern(to).recorded == NODE_RECORDED) )
    record_node(to);


  prov_type((&edge))=MSG_EDGE;
  edge_identifier((&edge)).id = prov_next_edgeid();
  edge_identifier((&edge)).boot_id = prov_boot_id;
  edge_identifier((&edge)).machine_id = prov_machine_id;
  edge.edge_info.type=type;
  edge.edge_info.allowed=allowed;
  copy_node_info(&edge.edge_info.snd, &from->node_info.identifier);
  copy_node_info(&edge.edge_info.rcv, &to->node_info.identifier);
  prov_write(&edge);
}

static inline void long_record_edge(uint32_t type, long_prov_msg_t* from, prov_msg_t* to, uint8_t allowed){
  prov_msg_t edge;

  if(unlikely(!prov_enabled)) // capture is not enabled, ignore
    return;
  // don't record if to or from are opaque
  if( unlikely(provenance_is_opaque(from) || provenance_is_opaque(to)) )
    return;

  if(!(node_kern(from).recorded == NODE_RECORDED) )
    record_node(to);

  prov_type((&edge))=MSG_EDGE;
  edge_identifier((&edge)).id = prov_next_edgeid();
  edge_identifier((&edge)).boot_id = prov_boot_id;
  edge_identifier((&edge)).machine_id = prov_machine_id;
  edge.edge_info.type=type;
  edge.edge_info.allowed=allowed;
  copy_node_info(&edge.edge_info.snd, &from->node_info.identifier);
  copy_node_info(&edge.edge_info.rcv, &to->node_info.identifier);
  prov_write(&edge);
}

static inline void prov_update_version(prov_msg_t* prov){
  prov_msg_t old_prov;
  memcpy(&old_prov, prov, sizeof(prov_msg_t));
  node_identifier(prov).version++;
  node_kern(prov).recorded = NODE_UNRECORDED;
  if(node_identifier(prov).type == MSG_TASK)
    record_edge(ED_VERSION_PROCESS, &old_prov, prov, FLOW_ALLOWED);
  else
    record_edge(ED_VERSION, &old_prov, prov, FLOW_ALLOWED);
}

#ifdef CONFIG_SECURITY_IFC
static inline void prov_record_ifc(prov_msg_t* prov, struct ifc_context *context){
	long_prov_msg_t* ifc_prov = NULL;

  ifc_prov = alloc_long_provenance(MSG_IFC, GFP_KERNEL);
  memcpy(&(ifc_prov->ifc_info.context), context, sizeof(struct ifc_context));
  long_prov_write(ifc_prov);
  // TODO connect via edge to entity/activity
  free_long_provenance(ifc_prov);
}
#endif

static inline void provenance_mark_as_opaque(const char* name){
  struct inode* in;
  prov_msg_t* prov;

  in = file_name_to_inode(name);
  if(!in){
    printk(KERN_ERR "Provenance: could not find %s file.", name);
  }else{
    prov = inode_get_provenance(in);
    if(prov){
      printk(KERN_ERR "Provenance: prov was ready.");
      node_kern(prov).opaque=NODE_OPAQUE;
    }
  }
}

static inline void prov_copy_inode_mode(prov_msg_t* iprov, struct inode *inode){
  uint32_t type = MSG_INODE_UNKNOWN;
  iprov->inode_info.mode=inode->i_mode;

  if(S_ISBLK(inode->i_mode)){
    type=MSG_INODE_BLOCK;
  }else if(S_ISCHR(inode->i_mode)){
    type=MSG_INODE_CHAR;
  }else if(S_ISDIR(inode->i_mode)){
    type=MSG_INODE_DIRECTORY;
  }else if(S_ISFIFO(inode->i_mode)){
    type=MSG_INODE_FIFO;
  }else if(S_ISLNK(inode->i_mode)){
    type=MSG_INODE_LINK;
  }else if(S_ISREG(inode->i_mode)){
    type=MSG_INODE_FILE;
  }else if(S_ISSOCK(inode->i_mode)){
    type=MSG_INODE_SOCKET;
  }
  node_identifier(iprov).type=type;
}
#endif
#endif /* _LINUX_PROVENANCE_H */
