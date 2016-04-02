/*
*
* /linux/include/linux/provenance.h
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
#include <uapi/linux/ifc.h>
#include <uapi/linux/mman.h>
#include <uapi/linux/provenance.h>
#include <uapi/linux/camflow.h>

#define ASSIGN_NODE_ID 0

extern atomic64_t prov_evt_count;

static inline struct prov_msg_t* prov_from_pid(pid_t pid){
  struct task_struct *dest = find_task_by_vpid(pid);
  if(!dest)
    return NULL;
  return __task_cred(dest)->provenance;
}

static inline uint64_t prov_next_evtid( void ){
  return (uint64_t)atomic64_inc_return(&prov_evt_count);
}

extern atomic64_t prov_node_id;

static inline uint64_t prov_next_nodeid( void )
{
  return (uint64_t)atomic64_inc_return(&prov_node_id);
}

extern struct rchan *prov_chan;
extern struct rchan *long_prov_chan;
extern bool prov_enabled;
extern bool prov_all;
extern struct kmem_cache *provenance_cache;
extern struct kmem_cache *long_provenance_cache;

static inline prov_msg_t* alloc_provenance(uint8_t ntype, gfp_t gfp)
{
  prov_msg_t* prov =  kmem_cache_zalloc(provenance_cache, gfp);
  if(!prov){
    return NULL;
  }

  prov->msg_info.message_type=ntype;
  return prov;
}

static inline void set_node_id(prov_msg_t* node, uint64_t nid){
  if(nid==ASSIGN_NODE_ID){
    node->node_info.node_id=prov_next_nodeid();
  }else{
    node->node_info.node_id=nid;
  }
}

static inline long_prov_msg_t* alloc_long_provenance(uint8_t ntype, gfp_t gfp)
{
  long_prov_msg_t* prov =  kmem_cache_zalloc(long_provenance_cache, gfp);
  if(!prov){
    return NULL;
  }
  prov->msg_info.message_type=ntype;
  return prov;
}

static inline void free_provenance(prov_msg_t* prov){
  kmem_cache_free(provenance_cache, prov);
}

static inline void free_long_provenance(long_prov_msg_t* prov){
  kmem_cache_free(long_provenance_cache, prov);
}

extern uint32_t prov_boot_id;
static inline void prov_write(prov_msg_t* msg)
{
  if(prov_chan==NULL) // not set yet
  {
    printk(KERN_ERR "Provenance: trying to write before nchan ready\n");
    return;
  }
  msg->msg_info.event_id=prov_next_evtid(); /* assign an event id */
  msg->msg_info.boot_id=prov_boot_id;
  relay_write(prov_chan, msg, sizeof(prov_msg_t));
}

static inline void long_prov_write(long_prov_msg_t* msg){
  if(long_prov_chan==NULL) // not set yet
  {
    printk(KERN_ERR "Provenance: trying to write before nchan ready\n");
    return;
  }
  msg->msg_info.event_id=prov_next_evtid(); /* assign an event id */
  msg->msg_info.boot_id=prov_boot_id;
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
  msg->str_info.message_type=MSG_STR;
  msg->str_info.length = vscnprintf(msg->str_info.str, 4096, fmt, args);
  long_prov_write(msg);
  va_end(args);
  length = msg->str_info.length;
  kfree(msg);
  return length;
}

static inline void record_node(prov_msg_t* prov){
  if(!prov_enabled) // capture is not enabled, ignore
    return;

  prov->node_info.recorded=NODE_RECORDED;
  prov_write(prov);
}

static inline bool provenance_is_tracked(prov_msg_t* node){
  if(prov_all)
    return true; // log everything but opaque
  if(node->node_info.tracked == NODE_TRACKED)
    return true; // log tracked node, except if opaque
  return false;
}

static inline bool provenance_is_name_recorded(prov_msg_t* node){
  if(node->node_info.name_recorded == NAME_RECORDED)
    return true;
  return false;
}

static inline void record_edge(uint8_t type, prov_msg_t* from, prov_msg_t* to, uint8_t allowed){
  prov_msg_t edge;

  if(unlikely(!prov_enabled)) // capture is not enabled, ignore
    return;
  // don't record if to or from are opaque
  if(unlikely(from->node_info.opaque == NODE_OPAQUE || to->node_info.opaque == NODE_OPAQUE))
    return;

  // ignore if not tracked
  if(!provenance_is_tracked(from) && !provenance_is_tracked(to))
    return;

  if(!(from->node_info.recorded == NODE_RECORDED) )
    record_node(from);

  if(!(to->node_info.recorded == NODE_RECORDED) )
    record_node(to);

  edge.edge_info.message_type=MSG_EDGE;
  edge.edge_info.snd_id=from->node_info.node_id;
  edge.edge_info.rcv_id=to->node_info.node_id;
  edge.edge_info.allowed=allowed;
  edge.edge_info.type=type;
  prov_write(&edge);
}

static inline void prov_update_version(prov_msg_t* prov){
  prov_msg_t old_prov;
  memcpy(&old_prov, prov, sizeof(prov_msg_t));
  prov->node_info.version++;
  prov->node_info.recorded = NODE_UNRECORDED;
  record_edge(ED_VERSION, &old_prov, prov, FLOW_ALLOWED);
}

#ifdef CONFIG_SECURITY_IFC
static inline void prov_record_ifc(prov_msg_t* prov, struct ifc_context *context){
	long_prov_msg_t* ifc_prov = NULL;

  ifc_prov = alloc_long_provenance(MSG_IFC, GFP_KERNEL);
  ifc_prov->ifc_info.node_id = prov->node_info.node_id;
  ifc_prov->ifc_info.version = prov->node_info.version;
  memcpy(&(ifc_prov->ifc_info.context), context, sizeof(struct ifc_context));
  long_prov_write(ifc_prov);
  free_long_provenance(ifc_prov);
}
#endif

#endif
#endif /* _LINUX_PROVENANCE_H */
