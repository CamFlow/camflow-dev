/*
 *
 * Author: Thomas Pasquier <tfjmp@seas.harvard.edu>
 *
 * Copyright (C) 2016 Harvard University
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 */
#ifndef _LINUX_PROVENANCE_LONG_H
#define _LINUX_PROVENANCE_LONG_H

#include <linux/file.h>
#include <uapi/linux/provenance.h>

#include "provenance_net.h"

extern uint32_t prov_machine_id;
extern uint32_t prov_boot_id;

static union long_prov_elt *alloc_long_provenance(uint64_t ntype)
{
	union long_prov_elt *tmp = kzalloc(sizeof(union long_prov_elt), GFP_ATOMIC);

	if (!tmp)
		return NULL;

	prov_type(tmp) = ntype;
	node_identifier(tmp).id = prov_next_node_id();
	node_identifier(tmp).boot_id = prov_boot_id;
	node_identifier(tmp).machine_id = prov_machine_id;
	return tmp;
}

static inline void __long_record_node(union long_prov_elt *node)
{
	if (provenance_is_recorded(node))
		return;
	set_recorded(node);
	long_prov_write(node);
}

static inline void __long_record_relation(uint64_t type, union long_prov_elt *from, union prov_elt *to, uint8_t allowed)
{
	union prov_elt relation;

	if (unlikely(!prov_enabled)) // capture is not enabled, ignore
		return;
	// don't record if to or from are opaque
	if (unlikely(provenance_is_opaque(to)))
		return;
	__long_record_node(from);
	__record_node(to);
	memset(&relation, 0, sizeof(union prov_elt));
	__prepare_relation(type, &(from->msg_info.identifier), &(to->msg_info.identifier), &relation, NULL);
	prov_write(&relation);
}

static inline void record_node_name(struct provenance *node, const char *name)
{
	union long_prov_elt *fname_prov;

	if (provenance_is_name_recorded(prov_elt(node)) || !provenance_is_recorded(prov_elt(node)))
		return;
	fname_prov = alloc_long_provenance(ENT_FILE_NAME);
	if (!fname_prov) {
		pr_err("Provenance: recod name failed to allocate memory\n");
		return;
	}
	strlcpy(fname_prov->file_name_info.name, name, PATH_MAX);
	fname_prov->file_name_info.length = strnlen(fname_prov->file_name_info.name, PATH_MAX);
	if (prov_type(prov_elt(node)) == ACT_TASK) {
		spin_lock_nested(prov_lock(node), PROVENANCE_LOCK_TASK);
		__long_record_relation(RL_NAMED_PROCESS, fname_prov, prov_elt(node), FLOW_ALLOWED);
		set_name_recorded(prov_elt(node));
		spin_unlock(prov_lock(node));
	} else{
		spin_lock_nested(prov_lock(node), PROVENANCE_LOCK_INODE);
		__long_record_relation(RL_NAMED, fname_prov, prov_elt(node), FLOW_ALLOWED);
		set_name_recorded(prov_elt(node));
		spin_unlock(prov_lock(node));
	}
	kfree(fname_prov);
}

static inline void record_inode_name_from_dentry(struct dentry *dentry, struct provenance *prov)
{
	char *buffer;
	char *ptr;

	if (provenance_is_name_recorded(prov_elt(prov)) || !provenance_is_recorded(prov_elt(prov)))
		return;
	// should not sleep
	buffer = kcalloc(PATH_MAX, sizeof(char), GFP_ATOMIC);
	if (!buffer) {
		pr_err("Provenance: could not allocate memory\n");
		return;
	}
	ptr = dentry_path_raw(dentry, buffer, PATH_MAX);
	record_node_name(prov, ptr);
	kfree(buffer);
}

static inline void record_inode_name(struct inode *inode, struct provenance *prov)
{
	struct dentry *dentry;

	if (provenance_is_name_recorded(prov_elt(prov)) || !provenance_is_recorded(prov_elt(prov)))
		return;
	dentry = d_find_alias(inode);
	if (!dentry) // we did not find a dentry, not sure if it should ever happen
		return;
	record_inode_name_from_dentry(dentry, prov);
	dput(dentry);
}

static inline void record_task_name(struct task_struct *task, struct provenance *prov)
{
	const struct cred *cred;
	struct provenance *fprov;
	struct mm_struct *mm;
	struct file *exe_file;
	char *buffer;
	char *ptr;

	if (provenance_is_name_recorded(prov_elt(prov)) || !provenance_is_recorded(prov_elt(prov)))
		return;
	cred = get_task_cred(task);
	if (!cred)
		return;
	mm = get_task_mm(task);
	if (!mm)
		goto out;
	exe_file = get_mm_exe_file(mm);
	mmput_async(mm);
	if (exe_file) {
		fprov = file_inode(exe_file)->i_provenance;
		if (provenance_is_opaque(prov_elt(fprov))) {
			set_opaque(prov_elt(prov));
			goto out;
		}
		// should not sleep
		buffer = kcalloc(PATH_MAX, sizeof(char), GFP_ATOMIC);
		if (!buffer) {
			pr_err("Provenance: could not allocate memory\n");
			fput(exe_file);
			goto out;
		}
		ptr = file_path(exe_file, buffer, PATH_MAX);
		fput(exe_file);
		record_node_name(prov, ptr);
		kfree(buffer);
	}
out:
	put_cred(cred);
}

static inline void provenance_record_address(struct sockaddr *address, int addrlen, struct provenance *prov)
{
	union long_prov_elt *addr_info;

	if (provenance_is_name_recorded(prov_elt(prov)) || !provenance_is_recorded(prov_elt(prov)))
		return;
	addr_info = alloc_long_provenance(ENT_ADDR);
	if (!addr_info)
		return;
	addr_info->address_info.length = addrlen;
	memcpy(&(addr_info->address_info.addr), address, addrlen);
	__long_record_relation(RL_NAMED, addr_info, prov_elt(prov), FLOW_ALLOWED);
	kfree(addr_info);
	set_name_recorded(prov_elt(prov));
}

static inline int record_write_xattr(uint64_t type,
				     struct provenance *iprov,
				     struct provenance *cprov,
				     const char *name,
				     const void *value,
				     size_t size,
				     int flags,
				     uint8_t allowed)
{
	union long_prov_elt *xattr = alloc_long_provenance(ENT_XATTR);
	union prov_elt relation;
	int rc = 0;

	if (!xattr)
		return 0;
	memset(&relation, 0, sizeof(union prov_elt));
	memcpy(xattr->xattr_info.name, name, PROV_XATTR_NAME_SIZE - 1);
	xattr->xattr_info.name[PROV_XATTR_NAME_SIZE - 1] = '\0';
	if (value) {
		if (size < PROV_XATTR_VALUE_SIZE) {
			xattr->xattr_info.size = size;
			memcpy(xattr->xattr_info.value, value, size);
		} else{
			xattr->xattr_info.size = PROV_XATTR_VALUE_SIZE;
			memcpy(xattr->xattr_info.value, value, PROV_XATTR_VALUE_SIZE);
		}
		xattr->xattr_info.flags = flags;
	}
	__record_node(prov_elt(cprov));
	__prepare_relation(type, &(prov_elt(cprov)->msg_info.identifier), &(xattr->msg_info.identifier), &relation, NULL);
	prov_write(&relation);
	rc = __update_version(type, iprov);
	if (rc < 0)
		return rc;
	__long_record_relation(type, xattr, prov_elt(iprov), allowed);
	kfree(xattr);
	cprov->has_outgoing = true;
	return rc;
}

static inline int record_read_xattr(uint64_t type,
				    struct provenance *cprov,
				    struct provenance *iprov,
				    const char *name,
				    uint8_t allowed)
{
	union long_prov_elt *xattr = alloc_long_provenance(ENT_XATTR);
	union prov_elt relation;
	int rc = 0;

	if (!xattr)
		return 0;
	memset(&relation, 0, sizeof(union prov_elt));
	memcpy(xattr->xattr_info.name, name, PROV_XATTR_NAME_SIZE - 1);
	xattr->xattr_info.name[PROV_XATTR_NAME_SIZE - 1] = '\0';
	__record_node(prov_elt(iprov));
	__prepare_relation(type, &(prov_elt(iprov)->msg_info.identifier), &(xattr->msg_info.identifier), &relation, NULL);
	prov_write(&relation);
	rc = __update_version(type, cprov);
	if (rc < 0)
		return rc;
	__long_record_relation(type, xattr, prov_elt(cprov), allowed);
	kfree(xattr);
	iprov->has_outgoing = true;
	return rc;
}

static inline void record_packet_content(union prov_elt *pck, const struct sk_buff *skb)
{
	union long_prov_elt *cnt = alloc_long_provenance(ENT_PCKCNT);

	cnt->pckcnt_info.length = skb_end_offset(skb);
	if (cnt->pckcnt_info.length > PATH_MAX) {
		cnt->pckcnt_info.truncated = PROV_TRUNCATED;
		memcpy(cnt->pckcnt_info.content, skb->head, PATH_MAX);
	} else
		memcpy(cnt->pckcnt_info.content, skb->head, cnt->pckcnt_info.length);
	__long_record_node(cnt);
	__long_record_relation(RL_READ, cnt, pck, FLOW_ALLOWED);
}

static inline int record_log(union prov_elt *cprov, const char __user *buf, size_t count)
{
	union long_prov_elt *str;

	str = alloc_long_provenance(ENT_STR);
	if (!str)
		return -ENOMEM;
	if (copy_from_user(str->str_info.str, buf, count))
		return -EAGAIN;
	str->str_info.str[count] = '\0'; // make sure the string is null terminated
	str->str_info.length = count;
	__long_record_relation(RL_SAID, str, cprov, FLOW_ALLOWED);
	kfree(str);
	return count;
}
#endif
