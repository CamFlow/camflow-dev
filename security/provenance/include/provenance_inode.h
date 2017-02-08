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
#ifndef CONFIG_SECURITY_PROVENANCE_INODE
#define CONFIG_SECURITY_PROVENANCE_INODE
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/namei.h>

#include "provenance_long.h"    // for record_inode_name
#include "provenance_secctx.h"  // for record_inode_name

#define is_inode_dir(inode) S_ISDIR(inode->i_mode)
#define is_inode_socket(inode) S_ISSOCK(inode->i_mode)
#define is_inode_file(inode) S_ISREG(inode->i_mode)

static inline struct inode *file_name_to_inode(const char *name)
{
	struct path path;
	struct inode *inode;

	if (kern_path(name, LOOKUP_FOLLOW, &path)) {
		printk(KERN_ERR "Provenance: Failed file look up (%s).", name);
		return NULL;
	}
	inode = path.dentry->d_inode;
	path_put(&path);
	return inode;
}

static inline void record_inode_type(uint16_t mode, struct provenance *prov)
{
	uint64_t type = ENT_INODE_UNKNOWN;

	if (S_ISBLK(mode))
		type = ENT_INODE_BLOCK;
	else if (S_ISCHR(mode))
		type = ENT_INODE_CHAR;
	else if (S_ISDIR(mode))
		type = ENT_INODE_DIRECTORY;
	else if (S_ISFIFO(mode))
		type = ENT_INODE_FIFO;
	else if (S_ISLNK(mode))
		type = ENT_INODE_LINK;
	else if (S_ISREG(mode))
		type = ENT_INODE_FILE;
	else if (S_ISSOCK(mode))
		type = ENT_INODE_SOCKET;
	spin_lock_nested(prov_lock(prov), PROVENANCE_LOCK_INODE);
	prov_msg(prov)->inode_info.mode = mode;
	prov_type(prov_msg(prov)) = type;
	spin_unlock(prov_lock(prov));
}

static inline void provenance_mark_as_opaque(const char *name)
{
	struct inode *in;
	union prov_msg *prov;

	in = file_name_to_inode(name);
	if (!in)
		printk(KERN_ERR "Provenance: could not find %s file.", name);
	else{
		prov = in->i_provenance;
		if (prov)
			set_opaque(prov);
	}
}

static inline void refresh_inode_provenance(struct inode *inode)
{
	struct provenance *prov = inode->i_provenance;

	// will not be recorded
	if( provenance_is_opaque(prov_msg(prov)) )
		return;

	record_inode_name(inode, prov);
	if(unlikely(prov_type(prov_msg(prov))==ENT_INODE_UNKNOWN))
		record_inode_type(inode->i_mode, prov);
	prov_msg(prov)->inode_info.uid = __kuid_val(inode->i_uid);
	prov_msg(prov)->inode_info.gid = __kgid_val(inode->i_gid);
	security_inode_getsecid(inode, &(prov_msg(prov)->inode_info.secid));
}

static inline struct provenance *dentry_provenance(struct dentry *dentry)
{
	struct inode *inode = d_backing_inode(dentry);

	if (inode == NULL)
		return NULL;
	return inode->i_provenance;
}

static inline struct provenance *file_provenance(struct file *file)
{
	struct inode *inode = file_inode(file);

	if (inode == NULL)
		return NULL;
	return inode->i_provenance;
}

static inline struct provenance *branch_mmap(union prov_msg *iprov, union prov_msg *cprov)
{
	//used for private MMAP
	struct provenance *prov;
	union prov_msg relation;

	if (unlikely(iprov == NULL || cprov == NULL)) // should not occur
		return NULL;
	if (!provenance_is_tracked(iprov) && !provenance_is_tracked(cprov) && !prov_all)
		return NULL;
	if (!should_record_relation(RL_MMAP, cprov, iprov, FLOW_ALLOWED))
		return NULL;
	prov = alloc_provenance(ENT_INODE_MMAP, GFP_KERNEL);

	prov_msg(prov)->inode_info.uid = iprov->inode_info.uid;
	prov_msg(prov)->inode_info.gid = iprov->inode_info.gid;
	memcpy(prov_msg(prov)->inode_info.sb_uuid, iprov->inode_info.sb_uuid, 16 * sizeof(uint8_t));
	prov_msg(prov)->inode_info.mode = iprov->inode_info.mode;
	__record_node(iprov);
	memset(&relation, 0, sizeof(union prov_msg));
	__propagate(RL_MMAP, iprov, prov_msg(prov), &relation, FLOW_ALLOWED);
	__record_node(prov_msg(prov));
	__record_relation(RL_MMAP, &(iprov->msg_info.identifier), &(prov_msg(prov)->msg_info.identifier), &relation, FLOW_ALLOWED, NULL);
	return prov;
}
#endif
