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

extern uint32_t prov_machine_id;
extern uint32_t prov_boot_id;

static long_prov_msg_t* alloc_long_provenance(uint64_t ntype, gfp_t priority)
{
  long_prov_msg_t *tmp = (long_prov_msg_t *)kzalloc(sizeof(long_prov_msg_t), priority);

  prov_type(tmp) = ntype;
  node_identifier(tmp).id = prov_next_node_id();
  node_identifier(tmp).boot_id = prov_boot_id;
  node_identifier(tmp).machine_id = prov_machine_id;
  return tmp;
}

static inline void __long_record_node(long_prov_msg_t* node)
{
  if (provenance_is_recorded(node)) {
    return;
  }
  set_recorded(node);
  long_prov_write(node);
}

static inline void __long_record_relation(uint64_t type, long_prov_msg_t* from, prov_msg_t* to, uint8_t allowed)
{
  prov_msg_t relation;

  if (unlikely(!prov_enabled)) { // capture is not enabled, ignore
    return;
  }
  // don't record if to or from are opaque
  if (unlikely(provenance_is_opaque(to))) {
    return;
  }
  __long_record_node(from);
  __record_node(to);
  memset(&relation, 0, sizeof(prov_msg_t));
  __record_relation(type, &(from->msg_info.identifier), &(to->msg_info.identifier), &relation, allowed, NULL);
}

static inline int prov_print(const char *fmt, ...)
{
  long_prov_msg_t *msg = alloc_long_provenance(ENT_STR, GFP_KERNEL); // revert back to cache if causes performance issue
  int length;
  va_list args;

  va_start(args, fmt);

  msg->str_info.length = vscnprintf(msg->str_info.str, 4096, fmt, args);
  long_prov_write(msg);
  va_end(args);
  length = msg->str_info.length;
  kfree(msg);
  return length;
}

static inline void __record_node_name(struct provenance *node, char* name)
{
	long_prov_msg_t *fname_prov;

  fname_prov = alloc_long_provenance(ENT_FILE_NAME, GFP_KERNEL);
	strlcpy(fname_prov->file_name_info.name, name, PATH_MAX);
	fname_prov->file_name_info.length = strlen(fname_prov->file_name_info.name);
  if (prov_type(prov_msg(node)) == ACT_TASK) {
    spin_lock_nested(prov_lock(node), PROVENANCE_LOCK_TASK);
    __long_record_relation(RL_NAMED_PROCESS, fname_prov, prov_msg(node), FLOW_ALLOWED);
    set_name_recorded(prov_msg(node));
    spin_unlock(prov_lock(node));
  } else{
    spin_lock_nested(prov_lock(node), PROVENANCE_LOCK_INODE);
    __long_record_relation(RL_NAMED, fname_prov, prov_msg(node), FLOW_ALLOWED);
    set_name_recorded(prov_msg(node));
    spin_unlock(prov_lock(node));
  }
  kfree(fname_prov);
}

static inline void record_inode_name_from_dentry(struct dentry *dentry, struct provenance *prov)
{
  char *buffer;
	char *ptr;
  if (provenance_is_name_recorded(prov_msg(prov)) || !provenance_is_recorded(prov_msg(prov))) {
		return;
	}
  buffer = (char *)kzalloc(PATH_MAX, GFP_NOFS);
	ptr = dentry_path_raw(dentry, buffer, PATH_MAX);
	__record_node_name(prov, ptr);
	kfree(buffer);
}

static inline void record_inode_name(struct inode *inode, struct provenance *prov)
{
	struct dentry *dentry;

	if (provenance_is_name_recorded(prov_msg(prov)) || !provenance_is_recorded(prov_msg(prov))) {
		return;
	}
	dentry = d_find_alias(inode);

	if (!dentry) { // we did not find a dentry, not sure if it should ever happen
		return;
	}
	record_inode_name_from_dentry(dentry, prov);
	dput(dentry);
}

static inline void record_task_name(struct task_struct *task, struct provenance *prov)
{
	const struct cred *cred;
	struct mm_struct *mm;
	struct file *exe_file;
	char *buffer;
	char *ptr;

  if (provenance_is_name_recorded(prov_msg(prov)) || !provenance_is_recorded(prov_msg(prov))) {
		return;
	}

	cred = get_task_cred(task);
	if (!cred) {
		return;
	}

	mm = get_task_mm(task);
	if (!mm) {
		goto out;
	}
	exe_file = get_mm_exe_file(mm);
	mmput(mm);

	if (exe_file) {
		buffer = (char *)kzalloc(PATH_MAX, GFP_KERNEL);
		ptr = file_path(exe_file, buffer, PATH_MAX);
		fput(exe_file);
		__record_node_name(prov, ptr);
		kfree(buffer);
	}

out:
	put_cred(cred);
}

static inline void provenance_record_address(struct sockaddr *address, int addrlen, struct provenance *prov)
{
	long_prov_msg_t *addr_info;

  if (provenance_is_name_recorded(prov_msg(prov)) || !provenance_is_recorded(prov_msg(prov))) {
    return;
  }

  addr_info = alloc_long_provenance(ENT_ADDR, GFP_KERNEL);
  addr_info->address_info.length = addrlen;
  memcpy(&(addr_info->address_info.addr), address, addrlen);
	__long_record_relation(RL_NAMED, addr_info, prov_msg(prov), FLOW_ALLOWED);
  kfree(addr_info);
	set_name_recorded(prov_msg(prov));
}

static inline void record_write_xattr(uint64_t type,
				      prov_msg_t *iprov,
				      prov_msg_t *cprov,
				      const char *name,
				      const void *value,
				      size_t size,
				      int flags,
				      uint8_t allowed){
  long_prov_msg_t *xattr = alloc_long_provenance(ENT_XATTR, GFP_KERNEL);
  prov_msg_t relation;

  memset(&relation, 0, sizeof(prov_msg_t));

  memcpy(xattr->xattr_info.name, name, PROV_XATTR_NAME_SIZE-1);
  xattr->xattr_info.name[PROV_XATTR_NAME_SIZE-1] = '\0';

  if (value != NULL) {
    if (size < PROV_XATTR_VALUE_SIZE) {
      xattr->xattr_info.size = size;
      memcpy(xattr->xattr_info.value, value, size);
    } else{
      xattr->xattr_info.size = PROV_XATTR_VALUE_SIZE;
      memcpy(xattr->xattr_info.value, value, PROV_XATTR_VALUE_SIZE);
    }
    xattr->xattr_info.flags = flags;
  }

  __record_node(cprov);
  __record_relation(type, &(cprov->msg_info.identifier), &(xattr->msg_info.identifier), &relation, allowed, NULL);
  __update_version(type, iprov);
  __long_record_relation(type, xattr, iprov, allowed);
  kfree(xattr);
}

static inline void record_read_xattr(uint64_t type, prov_msg_t* cprov, prov_msg_t *iprov, const char* name, uint8_t allowed)
{
  long_prov_msg_t *xattr = alloc_long_provenance(ENT_XATTR, GFP_KERNEL);
  prov_msg_t relation;

  memset(&relation, 0, sizeof(prov_msg_t));

  memcpy(xattr->xattr_info.name, name, PROV_XATTR_NAME_SIZE-1);
  xattr->xattr_info.name[PROV_XATTR_NAME_SIZE-1] = '\0';

  __record_node(iprov);
  __record_relation(type, &(iprov->msg_info.identifier), &(xattr->msg_info.identifier), &relation, allowed, NULL);
  __update_version(type, cprov);
  __long_record_relation(type, xattr, cprov, allowed);
  kfree(xattr);
}
#endif
