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
#ifndef _PROVENANCE_INODE_H
#define _PROVENANCE_INODE_H

#include <linux/file.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/xattr.h>

#include "provenance_policy.h"
#include "provenance_filter.h"

#define is_inode_dir(inode) S_ISDIR(inode->i_mode)
#define is_inode_socket(inode) S_ISSOCK(inode->i_mode)
#define is_inode_file(inode) S_ISREG(inode->i_mode)

static inline void update_inode_type(uint16_t mode, struct provenance *prov)
{
	union prov_elt old_prov;
	uint64_t type = ENT_INODE_UNKNOWN;
	unsigned long irqflags;

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
	spin_lock_irqsave_nested(prov_lock(prov), irqflags, PROVENANCE_LOCK_INODE);
	if (prov_elt(prov)->inode_info.mode != 0
	    && prov_elt(prov)->inode_info.mode != mode
	    && provenance_is_recorded(prov_elt(prov))) {
		if (filter_update_node(type))
			goto out;
		memcpy(&old_prov, prov_elt(prov), sizeof(union prov_elt));
		/* we update the info of the new version and record it */
		prov_elt(prov)->inode_info.mode = mode;
		prov_type(prov_elt(prov)) = type;
		node_identifier(prov_elt(prov)).version++;
		clear_recorded(prov_elt(prov));

		/* we record a version edge */
		write_relation(RL_VERSION, &old_prov, prov_elt(prov), NULL);
		prov->has_outgoing = false; // we update there is no more outgoing edge
		prov->saved = false;
	}
out:
	prov_elt(prov)->inode_info.mode = mode;
	prov_type(prov_elt(prov)) = type;
	spin_unlock_irqrestore(prov_lock(prov), irqflags);
}

static inline void provenance_mark_as_opaque(const char *name)
{
	struct path path;
	struct provenance *prov;

	if (kern_path(name, LOOKUP_FOLLOW, &path)) {
		pr_err("Provenance: Failed file look up (%s).", name);
		return;
	}
	prov = path.dentry->d_inode->i_provenance;
	if (prov)
		set_opaque(prov_elt(prov));
}

static inline int record_inode_name_from_dentry(struct dentry *dentry, struct provenance *prov)
{
	char *buffer;
	char *ptr;
	int rc;

	if (provenance_is_name_recorded(prov_elt(prov)) ||
	    !provenance_is_recorded(prov_elt(prov)))
		return 0;
	// should not sleep
	buffer = kcalloc(PATH_MAX, sizeof(char), GFP_ATOMIC);
	if (!buffer)
		return -ENOMEM;
	ptr = dentry_path_raw(dentry, buffer, PATH_MAX);
	if (IS_ERR(ptr))
		return PTR_ERR(ptr);
	rc = record_node_name(prov, ptr);
	kfree(buffer);
	return rc;
}

static inline int record_inode_name(struct inode *inode, struct provenance *prov)
{
	struct dentry *dentry;
	int rc;

	if (provenance_is_name_recorded(prov_elt(prov)) || !provenance_is_recorded(prov_elt(prov)))
		return 0;
	dentry = d_find_alias(inode);
	if (!dentry) // we did not find a dentry, not sure if it should ever happen
		return 0;
	rc = record_inode_name_from_dentry(dentry, prov);
	dput(dentry);
	return rc;
}

static inline void refresh_inode_provenance(struct inode *inode, bool may_sleep)
{
	struct provenance *prov = inode->i_provenance;

	// will not be recorded
	if (provenance_is_opaque(prov_elt(prov)))
		return;
	if (may_sleep)
		record_inode_name(inode, prov);
	prov_elt(prov)->inode_info.ino = inode->i_ino;
	node_uid(prov_elt(prov)) = __kuid_val(inode->i_uid);
	node_gid(prov_elt(prov)) = __kgid_val(inode->i_gid);
	security_inode_getsecid(inode, &(prov_elt(prov)->inode_info.secid));
	update_inode_type(inode->i_mode, prov);
}

static inline struct provenance *branch_mmap(struct provenance *iprov, struct provenance *cprov)
{
	struct provenance *prov;

	if (!provenance_is_tracked(prov_elt(iprov)) && !provenance_is_tracked(prov_elt(cprov)) && !prov_policy.prov_all)
		return NULL;
	prov = alloc_provenance(ENT_INODE_MMAP, GFP_ATOMIC);
	if (!prov)
		return NULL;
	set_tracked(prov_elt(prov));
	node_uid(prov_elt(prov)) = prov_elt(iprov)->inode_info.uid;
	node_gid(prov_elt(prov)) = prov_elt(iprov)->inode_info.gid;
	prov_elt(prov)->inode_info.mode = prov_elt(iprov)->inode_info.mode;
	prov_elt(prov)->inode_info.ino = prov_elt(iprov)->inode_info.ino;
	memcpy(prov_elt(prov)->inode_info.sb_uuid, prov_elt(iprov)->inode_info.sb_uuid, 16 * sizeof(uint8_t));
	return prov;
}

static inline int inode_init_provenance(struct inode *inode, struct dentry *opt_dentry)
{
	struct provenance *prov = inode->i_provenance;
	union prov_elt *buf;
	struct dentry *dentry;
	int rc = 0;

	if (prov->initialised)
		return 0;
	spin_lock_nested(prov_lock(prov), PROVENANCE_LOCK_INODE);
	if (prov->initialised) {
		spin_unlock(prov_lock(prov));
		return 0;
	}       else
		prov->initialised = true;
	spin_unlock(prov_lock(prov));
	update_inode_type(inode->i_mode, prov);
	if (!(inode->i_opflags & IOP_XATTR)) // xattr not supported on this inode
		return 0;
	if (opt_dentry)
		dentry = dget(opt_dentry);
	else
		dentry = d_find_alias(inode);
	if (!dentry)
		return 0;
	buf = kmalloc(sizeof(union prov_elt), GFP_NOFS);
	if (!buf) {
		prov->initialised = false;
		dput(dentry);
		return -ENOMEM;
	}
	rc = __vfs_getxattr(dentry, inode, XATTR_NAME_PROVENANCE, buf, sizeof(union prov_elt));
	dput(dentry);
	if (rc < 0) {
		if (rc != -ENODATA && rc != -EOPNOTSUPP) {
			prov->initialised = false;
			goto free_buf;
		} else {
			rc = 0;
			goto free_buf;
		}
	}
	memcpy(prov_elt(prov), buf, sizeof(union prov_elt));
	rc = 0;
free_buf:
	kfree(buf);
	return rc;
}

static inline struct provenance *inode_provenance(struct inode *inode, bool may_sleep)
{
	struct provenance *prov = inode->i_provenance;

	might_sleep_if(may_sleep);
	if (!prov->initialised && may_sleep)
		inode_init_provenance(inode, NULL);
	refresh_inode_provenance(inode, may_sleep);
	return prov;
}

static inline struct provenance *dentry_provenance(struct dentry *dentry)
{
	struct inode *inode = d_backing_inode(dentry);
	struct provenance *prov;

	if (!inode)
		return NULL;
	prov = inode->i_provenance;
	inode_init_provenance(inode, dentry);
	return prov;
}

static inline struct provenance *file_provenance(struct file *file)
{
	struct inode *inode = file_inode(file);

	if (!inode)
		return NULL;
	return inode_provenance(inode, true);
}

static inline void save_provenance(struct dentry *dentry)
{
	struct inode *inode;
	struct provenance *prov;
	union prov_elt buf;

	if (!dentry)
		return;
	inode = d_backing_inode(dentry);
	if (!inode)
		return;
	prov = inode->i_provenance;
	if (!prov)
		return;
	spin_lock(prov_lock(prov));
	if (!prov->initialised || prov->saved) { // not initialised or already saved
		spin_unlock(prov_lock(prov));
		return;
	}
	memcpy(&buf, prov_elt(prov), sizeof(union prov_elt));
	prov->saved = true;
	spin_unlock(prov_lock(prov));
	clear_recorded(&buf);
	clear_name_recorded(&buf);
	if (!dentry)
		return;
	__vfs_setxattr_noperm(dentry, XATTR_NAME_PROVENANCE, &buf, sizeof(union prov_elt), 0);
}

static inline int record_write_xattr(uint64_t type,
				     struct provenance *iprov,
				     struct provenance *cprov,
				     const char *name,
				     const void *value,
				     size_t size,
				     int flags)
{
	union long_prov_elt *xattr;
	int rc = 0;

	if (!should_record_relation(type, prov_entry(cprov), prov_entry(iprov)))
		return 0;
	xattr = alloc_long_provenance(ENT_XATTR);
	if (!xattr)
		return -ENOMEM;
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

	rc = write_relation(type, prov_elt(cprov), xattr, NULL);
	if (rc < 0)
		goto out;
	rc = __update_version(type, iprov);
	if (rc < 0)
		goto out;

	if (type == RL_SETXATTR)
		rc = write_relation(RL_SETXATTR_INODE, xattr, prov_elt(iprov), NULL);
	else
		rc = write_relation(RL_RMVXATTR_INODE, xattr, prov_elt(iprov), NULL);
	cprov->has_outgoing = true;
out:
	free_long_provenance(xattr);
	return rc;
}

static inline int record_read_xattr(struct provenance *cprov,
				    struct provenance *iprov,
				    const char *name)
{
	union long_prov_elt *xattr;
	int rc = 0;

	if (!should_record_relation(RL_GETXATTR, prov_entry(iprov), prov_entry(cprov)))
		return 0;
	xattr = alloc_long_provenance(ENT_XATTR);
	if (!xattr)
		goto out;
	memcpy(xattr->xattr_info.name, name, PROV_XATTR_NAME_SIZE - 1);
	xattr->xattr_info.name[PROV_XATTR_NAME_SIZE - 1] = '\0';

	rc = write_relation(RL_GETXATTR_INODE, prov_elt(iprov), xattr, NULL);
	if (rc < 0)
		goto out;
	rc = __update_version(RL_GETXATTR, cprov);
	if (rc < 0)
		goto out;

	rc = write_relation(RL_GETXATTR, xattr, prov_elt(cprov), NULL);
	iprov->has_outgoing = true;
out:
	free_long_provenance(xattr);
	return rc;
}

static inline int close_inode(struct provenance *iprov)
{
	union prov_elt old_prov;
	int rc;

	if (!provenance_is_tracked(prov_elt(iprov)) && !prov_policy.prov_all)
		return 0;
	if (filter_node(prov_entry(iprov)))
		return 0;
	// persistent
	if (prov_type(prov_entry(iprov)) == ENT_INODE_FILE ||
	    prov_type(prov_entry(iprov)) == ENT_INODE_DIRECTORY)
		return 0;
	memcpy(&old_prov, prov_elt(iprov), sizeof(union prov_elt));
	node_identifier(prov_elt(iprov)).version++;
	clear_recorded(prov_elt(iprov));

	rc = write_relation(RL_CLOSED, &old_prov, prov_elt(iprov), NULL);
	iprov->has_outgoing = false;
	return rc;
}

#define FILE__EXECUTE   0x00000001UL
#define FILE__READ      0x00000002UL
#define FILE__APPEND    0x00000004UL
#define FILE__WRITE     0x00000008UL
#define DIR__SEARCH     0x00000010UL
#define DIR__WRITE      0x00000020UL
#define DIR__READ       0x00000040UL

static inline uint32_t file_mask_to_perms(int mode, unsigned int mask)
{
	uint32_t av = 0;

	if (!S_ISDIR(mode)) {
		if (mask & MAY_EXEC)
			av |= FILE__EXECUTE;
		if (mask & MAY_READ)
			av |= FILE__READ;
		if (mask & MAY_APPEND)
			av |= FILE__APPEND;
		else if (mask & MAY_WRITE)
			av |= FILE__WRITE;
	} else {
		if (mask & MAY_EXEC)
			av |= DIR__SEARCH;
		if (mask & MAY_WRITE)
			av |= DIR__WRITE;
		if (mask & MAY_READ)
			av |= DIR__READ;
	}

	return av;
}
#endif
