/*
*
* Author: Thomas Pasquier <tfjmp@seas.harvard.edu>
*
* Copyright (C) 2016 Harvard University
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License version 2, as
* published by the Free Software Foundation; either version 2 of the License, or
*	(at your option) any later version.
*
*/
#ifndef _LINUX_PROVENANCE_LONG_H
#define _LINUX_PROVENANCE_LONG_H

#include <linux/file.h>
#include <uapi/linux/provenance.h>

#include "provenance_net.h"

#define free_long_provenance(prov) kmem_cache_free(long_provenance_cache, prov)
extern struct kmem_cache *long_provenance_cache;

extern uint32_t prov_machine_id;
extern uint32_t prov_boot_id;

static inline long_prov_msg_t* alloc_long_provenance(uint32_t ntype, gfp_t gfp)
{
  long_prov_msg_t* prov =  kmem_cache_zalloc(long_provenance_cache, gfp);
  if(!prov){
    return NULL;
  }
  prov_type(prov)=ntype;
  /* create a new node to containe the info */
  node_identifier(prov).id=prov_next_node_id();
  node_identifier(prov).boot_id=prov_boot_id;
  node_identifier(prov).machine_id=prov_machine_id;
  return prov;
}

static inline void __w_long_record_node(long_prov_msg_t* node){
  if(provenance_is_recorded(node) ){
    return;
  }
  set_recorded(node);
  long_prov_write(node);
}

static inline void __w_long_record_relation(uint32_t type, long_prov_msg_t* from, prov_msg_t* to, uint8_t allowed){
  prov_msg_t relation;

  if(unlikely(!prov_enabled)){ // capture is not enabled, ignore
    return;
  }
  // don't record if to or from are opaque
  if( unlikely(provenance_is_opaque(to)) ){
    return;
  }
  __w_long_record_node(from);
  __w_record_node(to);

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

#ifdef CONFIG_SECURITY_IFC
static inline void prov_record_ifc(prov_msg_t* prov, struct ifc_context *context){
	long_prov_msg_t* ifc_prov = NULL;

  ifc_prov = alloc_long_provenance(MSG_IFC, GFP_KERNEL);
  memcpy(&(ifc_prov->ifc_info.context), context, sizeof(struct ifc_context));
  long_prov_write(ifc_prov);
  // TODO connect via relation to entity/activity
  free_long_provenance(ifc_prov);
}
#endif

static inline int prov_print(const char *fmt, ...)
{
  long_prov_msg_t* msg;
  int length;
  va_list args;
  va_start(args, fmt);

  msg = (long_prov_msg_t*)kzalloc(sizeof(long_prov_msg_t),  GFP_NOFS);

  /* set message type */
  prov_type(msg)=MSG_STR;
  msg->str_info.length = vscnprintf(msg->str_info.str, 4096, fmt, args);
  long_prov_write(msg);
  va_end(args);
  length = msg->str_info.length;
  kfree(msg);
  return length;
}

static inline void __w_record_node_name(prov_msg_t* node, char* name){
	long_prov_msg_t *fname_prov = alloc_long_provenance(MSG_FILE_NAME, GFP_KERNEL);
	strlcpy(fname_prov->file_name_info.name, name, PATH_MAX);
	fname_prov->file_name_info.length=strlen(fname_prov->file_name_info.name);

	__w_long_record_relation(RL_NAMED, fname_prov, node, FLOW_ALLOWED);
	set_name_recorded(node);
	free_long_provenance(fname_prov);
}

static inline void record_inode_name_from_dentry(struct dentry *dentry, prov_msg_t* iprov){
  char *buffer;
	char *ptr;

  if( !provenance_is_recorded(iprov) ){
    return;
  }

  buffer = (char*)kzalloc(PATH_MAX, GFP_NOFS);
	ptr = dentry_path_raw(dentry, buffer, PATH_MAX);
	__w_record_node_name(iprov, ptr);
	kfree(buffer);
}

static inline void record_inode_name(struct inode *inode, prov_msg_t* iprov){
	struct dentry* dentry;

	if( provenance_is_name_recorded(iprov) ){
		return;
	}
	dentry = d_find_alias(inode);

	if(!dentry){ // we did not find a dentry, not sure if it should ever happen
		return;
	}
	record_inode_name_from_dentry(dentry, iprov);
	dput(dentry);
}

static inline void record_task_name(struct task_struct *task, prov_msg_t* tprov){
	const struct cred *cred;
	struct mm_struct *mm;
 	struct file *exe_file;
	char *buffer;
	char *ptr;

  if( !provenance_is_recorded(tprov) ){
    return;
  }

	// name already recorded
	if(provenance_is_name_recorded(tprov)){
		return;
	}

	if(filter_node(tprov)){
		return;
	}

	cred = get_task_cred(task);
	if(!cred){
		return;
	}

	mm = get_task_mm(task);
	if (!mm){
 		goto out;
	}
	exe_file = get_mm_exe_file(mm);
	mmput(mm);

	if(exe_file){
		buffer = (char*)kzalloc(PATH_MAX, GFP_KERNEL);
		ptr = file_path(exe_file, buffer, PATH_MAX);
		fput(exe_file);
		__w_record_node_name(tprov, ptr);
		kfree(buffer);
	}

out:
	put_cred(cred);
}

static inline void provenance_record_address(prov_msg_t* skprov, struct sockaddr *address, int addrlen){
	long_prov_msg_t* addr_info = NULL;

  if( !provenance_is_recorded(skprov) ){
    return;
  }

	if(provenance_is_name_recorded(skprov)){
    return;
  }


  addr_info = alloc_long_provenance(MSG_ADDR, GFP_KERNEL);
  addr_info->address_info.length=addrlen;
  memcpy(&(addr_info->address_info.addr), address, addrlen);
	__w_long_record_relation(RL_NAMED, addr_info, skprov, FLOW_ALLOWED);
  free_long_provenance(addr_info);
	set_name_recorded(skprov);
}

#endif
