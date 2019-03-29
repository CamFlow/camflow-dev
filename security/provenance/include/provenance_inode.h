/*
 *
 * Author: Thomas Pasquier <thomas.pasquier@bristol.ac.uk>
 *
 * Copyright (C) 2015-2019 University of Cambridge, Harvard University, University of Bristol
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

#include "provenance_record.h"
#include "provenance_policy.h"
#include "provenance_filter.h"

#define is_inode_dir(inode)             S_ISDIR(inode->i_mode)
#define is_inode_socket(inode)          S_ISSOCK(inode->i_mode)
#define is_inode_file(inode)            S_ISREG(inode->i_mode)

/*!
 * @brief Update the type of the provenance inode node based on the mode of the inode, and create a version relation between old and new provenance node.
 *
 * Based on the mode of the inode, determine the type of the provenance inode node, choosing from:
 * ENT_INODE_BLOCK, ENT_INODE_CHAR, ENT_INODE_DIRECTORY, ENT_INODE_PIPE, ENT_INODE_LINK, ENT_INODE_FILE, ENT_INODE_SOCKET.
 * Create a new provenance node with the updated type, and a updated version and a RL_VERSION relation between them if certain criteria are met.
 * Otherwise, RL_VERSION relation is not needed and we simply update the node type and mode information.
 * The operation is done in a nested spin_lock to avoid concurrency.
 * The criteria are:
 * 1. The inode_info.mode is not 0 (when mode is zero, this is the first time we record the inode), and
 * 2. The inode_info.mode is not already up-to-date, and
 * 3. The inode is set to be recorded.
 * @param mode The new updated mode.
 * @param prov The provenance node to be updated.
 *
 */
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
		type = ENT_INODE_PIPE;
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
		memcpy(&old_prov, prov_elt(prov), sizeof(old_prov));
		// We update the info of the new version and record it.
		prov_elt(prov)->inode_info.mode = mode;
		prov_type(prov_elt(prov)) = type;
		node_identifier(prov_elt(prov)).version++;
		clear_recorded(prov_elt(prov));

		// We record a version edge.
		__write_relation(RL_VERSION, &old_prov, prov_elt(prov), NULL, 0);
		clear_has_outgoing(prov_elt(prov));
		clear_saved(prov_elt(prov));
	}
	prov_elt(prov)->inode_info.mode = mode;
	prov_type(prov_elt(prov)) = type;
	spin_unlock_irqrestore(prov_lock(prov), irqflags);
}

static inline void provenance_mark_as_opaque_dentry(const struct dentry *dentry)
{
	struct provenance *prov;

	if (IS_ERR(dentry))
		return;
	prov = dentry->d_inode->i_provenance;
	if (prov)
		set_opaque(prov_elt(prov));
}

/*!
 * @brief Set the provenance node to be opaque based on the name given in the argument.
 *
 * Based on the given name, we will perform a kernal path lookup and get the provenance information of that name.
 * Then we will set the provenance node as opaque.
 * @param name The name of the file object to be set opaque. Note that every object in Linux is a file.
 *
 */
static inline void provenance_mark_as_opaque(const char *name)
{
	struct path path;

	if (kern_path(name, LOOKUP_FOLLOW, &path)) {
		pr_err("Provenance: Failed file look up (%s).", name);
		return;
	}
	provenance_mark_as_opaque_dentry(path.dentry);
}

/*!
 * @brief Record the name of a provenance node from directory entry.
 *
 * Unless specific criteria are met,
 * the name of the provenance node is looked up through "dentry_path_raw" and function "record_node_name" is called,
 * to associate the name of the provenance to the provenance node itself as a relation.
 * The criteria to be met are:
 * 1. The name of the provenance node has been recorded already, or
 * 2. The provenance node itself has not been recorded.
 * @param dentry Pointer to dentry of the base directory.
 * @param prov The provenance node in question.
 * @return 0 if no error occurred. -ENOMEM if no memory to store the name of the provenance node. PTR_ERR if path lookup failed.
 *
 */
static inline int record_inode_name_from_dentry(struct dentry *dentry,
						struct provenance *prov,
						bool force)
{
	char *buffer;
	char *ptr;
	int rc;

	if (provenance_is_name_recorded(prov_elt(prov)) ||
	    !provenance_is_recorded(prov_elt(prov)))
		return 0;
	else {
        // Should not sleep.
        buffer = kcalloc(PATH_MAX, sizeof(char), GFP_ATOMIC);
        if (!buffer)
            return -ENOMEM;
        ptr = dentry_path_raw(dentry, buffer, PATH_MAX);
        if (IS_ERR(ptr))
            return PTR_ERR(ptr);
        rc = record_node_name(prov, ptr, force);
        kfree(buffer);
        return rc;
    }
}

/*!
 * @brief Record the name of the provenance node directly from the inode.
 *
 * Unless the name of the provenance node has already been recorded,
 * or that the provenance node itself is not recorded,
 * the function will attempt to create a name node for the provenance node by calling "record_inode_name_from_dentry".
 * To call that function, we will find a hashed alias of inode, which is a dentry struct, and then pass that information to the function.
 * @param inode The inode whose name we look up and assocaite it with the provenance node.
 * @param prov The provenance node in question.
 * @return 0 if no error occurred or if "dentry" returns NULL. Other error codes unknown.
 *
 */
static inline int record_inode_name(struct inode *inode, struct provenance *prov)
{
	struct dentry *dentry;
	int rc;

	if (provenance_is_name_recorded(prov_elt(prov)) || !provenance_is_recorded(prov_elt(prov)))
		return 0;
	else {
        dentry = d_find_alias(inode);
        if (!dentry)    // We did not find a dentry, not sure if it should ever happen.
            return 0;
        rc = record_inode_name_from_dentry(dentry, prov, false);
        dput(dentry);
        return rc;
    }
}

/*!
 * @brief Update provenance information of an inode node.
 *
 * Update provenance entry of an inode node unless that provenance node is set to be opaque.
 * The update operation includes:
 * 1. Record the name of the inode, which creates a named relation between the name node and the inode.
 * 2. Update i_ino information in inode_info structure.
 * 3. Update uid and gid information of the inode node.
 * 4. Update secid information of the inode node.
 * 5. Update the type of the inode node itself.
 * @param inode The inode in question whose provenance entry to be updated.
 *
 */
static inline void refresh_inode_provenance(struct inode *inode,
					    struct provenance *prov)
{
	if (provenance_is_opaque(prov_elt(prov)))
		return;
	record_inode_name(inode, prov);
	prov_elt(prov)->inode_info.ino = inode->i_ino;
	node_uid(prov_elt(prov)) = __kuid_val(inode->i_uid);
	node_gid(prov_elt(prov)) = __kgid_val(inode->i_gid);
	security_inode_getsecid(inode, &(prov_elt(prov)->inode_info.secid));
	update_inode_type(inode->i_mode, prov);
}

/*!
 * @brief Initialize the provenance of the inode.
 *
 * We do not initialize the inode if it has already been initialized, or failure occurred.
 * Provenance extended attributes are copied to the inode provenance in this function,
 * unless the inode does not support xattr.
 * inode struct contains @inode->i_provenance to store provenance.
 * @param inode The inode structure in which we initialize provenance.
 * @param opt_dentry The directory entry pointer.
 * @return 0 if no error occurred; -ENOMEM if no more memory to allocate for the provenance entry. Other error codes inherited or unknown.
 *
 */
static inline int inode_init_provenance(struct inode *inode,
					struct dentry *opt_dentry,
					struct provenance *prov)
{
	union prov_elt *buf;
	struct dentry *dentry;
	int rc = 0;

	if (provenance_is_initialized(prov_elt(prov)))
		return 0;
	spin_lock_nested(prov_lock(prov), PROVENANCE_LOCK_INODE);
	if (provenance_is_initialized(prov_elt(prov))) {
		spin_unlock(prov_lock(prov));
		return 0;
	} else
		set_initialized(prov_elt(prov));
	spin_unlock(prov_lock(prov));
	update_inode_type(inode->i_mode, prov);
	if (!(inode->i_opflags & IOP_XATTR))   // xattr not supported on this inode
		return 0;
	if (opt_dentry)
		dentry = dget(opt_dentry);
	else
		dentry = d_find_alias(inode);
	if (!dentry)
		return 0;
	buf = kmalloc(sizeof(union prov_elt), GFP_NOFS);
	if (!buf) {
		clear_initialized(prov_elt(prov));
		dput(dentry);
		return -ENOMEM;
	}
	rc = __vfs_getxattr(dentry, inode, XATTR_NAME_PROVENANCE, buf, sizeof(union prov_elt));
	dput(dentry);
	if (rc < 0) {
		if (rc != -ENODATA && rc != -EOPNOTSUPP) {
			clear_initialized(prov_elt(prov));
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

/*!
 * @brief This function returns the provenance of an inode.
 *
 * This function either initialize the provenance of the inode (if not initialized) and/or refreshes the provenance of the inode if needed.
 * If the function can sleep, provenance information of the inode should be refreshed.
 * @param inode The inode in question.
 * @param may_sleep Bool value signifies whether this function can sleep.
 * @return provenance struct pointer.
 *
 * @todo Error checking in this function should be included since "inode_init_provenance" can fail (i.e., non-zero return value).
 * @todo We may not want to update (call refresh_inode_provenance) all the time.
 */
static inline struct provenance *get_inode_provenance(struct inode *inode, bool may_sleep)
{
	struct provenance *iprov = inode->i_provenance;

	might_sleep_if(may_sleep);
	if (!provenance_is_initialized(prov_elt(iprov)) && may_sleep)
		inode_init_provenance(inode, NULL, iprov);
	if (may_sleep)
		refresh_inode_provenance(inode, iprov);
	return iprov;
}

/*!
 * @brief This function returns the provenance of the given directory entry based on its inode.
 *
 * This function ultimately calls "get_inode_provenance" function.
 * We find the inode of the dentry (if this dentry were to be opened as a file) by calling "d_backing_inode" function.
 * @param dentry The dentry whose provenance is to be returned.
 * @param may_sleep Bool value used in "get_inode_provenance" function (See above)
 * @return provenance struct pointer or NULL if inode does not exist.
 *
 */
static inline struct provenance *get_dentry_provenance(struct dentry *dentry, bool may_sleep)
{
	struct inode *inode = d_backing_inode(dentry);

	if (!inode)
		return NULL;
	return get_inode_provenance(inode, may_sleep);
}

/*!
 * @brief This function returns the provenance of the given file based on its inode.
 *
 * This function ultimately calls "get_inode_provenance" function.
 * We find the inode of the file by calling "file_inode" function.
 * @param file The file whose provenance is to be returned.
 * @param may_sleep Bool value used in "get_inode_provenance" function (See above)
 * @return provenance struct pointer or NULL if inode does not exist.
 *
 */
static inline struct provenance *get_file_provenance(struct file *file, bool may_sleep)
{
	struct inode *inode = file_inode(file);

	if (!inode)
		return NULL;
	return get_inode_provenance(inode, may_sleep);
}

static inline void save_provenance(struct dentry *dentry)
{
	struct provenance *prov;
	union prov_elt buf;

	if (!dentry)
		return;
	prov = get_dentry_provenance(dentry, false);
	if (!prov)
		return;
	spin_lock(prov_lock(prov));
	// not initialised or already saved
	if (!provenance_is_initialized(prov_elt(prov))
	    || provenance_is_saved(prov_elt(prov))) {
		spin_unlock(prov_lock(prov));
		return;
	}
	memcpy(&buf, prov_elt(prov), sizeof(union prov_elt));
	set_saved(prov_elt(prov));
	spin_unlock(prov_lock(prov));
	clear_recorded(&buf);
	clear_name_recorded(&buf);
	if (!dentry)
		return;
	__vfs_setxattr_noperm(dentry, XATTR_NAME_PROVENANCE, &buf, sizeof(union prov_elt), 0);
}

/*!
 * @brief This function records relations related to setting extended file attributes.
 *
 * xattr is a long provenance entry and is transient (i.e., freed after recorded).
 * Unless certain criteria are met, several relations are recorded when a process attempts to write xattr of a file:
 * 1. Record a RL_PROC_READ relation between a task process and its cred. Information flows from cred to the task process, and
 * 2. Record a given type @type of relation between the process and xattr provenance entry. Information flows from the task to the xattr, and
 * 3-1. If the given type is RL_SETXATTR, then record a RL_SETXATTR_INODE relation between xattr and the file inode. Information flows from xattr to inode;
 * 3-2. otherwise (the only other case is that the given type is RL_RMVXATTR_INODE), record a RL_RMVXATTR_INODE relation between xattr and the file inode. Information flows from xattr to inode.
 * The criteria to be met so as not to record the relations are:
 * 1. If any of the cred, task, and inode provenance are not tracked and if the capture all is not set, or
 * 2. If the relation @type should not be recorded, or
 * 3. Failure occurred.
 * xattr name and value pair is recorded in the long provenance entry.
 * @param type The type of relation to be recorded.
 * @param iprov The inode provenance entry.
 * @param tprov The task provenance entry.
 * @param cprov The cred provenance entry.
 * @param name The name of the extended attribute.
 * @param value The value of that attribute.
 * @param size The size of the value.
 * @param flags Flags passed by LSM hooks.
 * @return 0 if no error occurred; -ENOMEM if no memory can be allocated from long provenance cache to create a new long provenance entry. Other error codes from "record_relation" function or unknown.
 *
 */
static __always_inline int record_write_xattr(uint64_t type,
					      struct provenance *iprov,
					      struct provenance *tprov,
					      struct provenance *cprov,
					      const char *name,
					      const void *value,
					      size_t size,
					      const uint64_t flags)
{
	union long_prov_elt *xattr;
	int rc = 0;

	if (!provenance_is_tracked(prov_elt(iprov))
	    && !provenance_is_tracked(prov_elt(tprov))
	    && !provenance_is_tracked(prov_elt(cprov))
	    && !prov_policy.prov_all)
		return 0;
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
		} else {
			xattr->xattr_info.size = PROV_XATTR_VALUE_SIZE;
			memcpy(xattr->xattr_info.value, value, PROV_XATTR_VALUE_SIZE);
		}
	}
	rc = record_relation(RL_PROC_READ, prov_entry(cprov), prov_entry(tprov), NULL, 0);
	if (rc < 0)
		goto out;
	rc = record_relation(type, prov_entry(tprov), xattr, NULL, flags);
	if (rc < 0)
		goto out;
	if (type == RL_SETXATTR)
		rc = record_relation(RL_SETXATTR_INODE, xattr, prov_entry(iprov), NULL, flags);
	else
		rc = record_relation(RL_RMVXATTR_INODE, xattr, prov_entry(iprov), NULL, flags);
out:
	free_long_provenance(xattr);
	return rc;
}

/*!
 * @brief This function records relations related to reading extended file attributes.
 *
 * xattr is a long provenance entry and is transient (i.e., freed after recorded).
 * Unless certain criteria are met, several relations are recorded when a process attempts to read xattr of a file:
 * 1. Record a RL_GETXATTR_INODE relation between inode and xattr. Information flows from inode to xattr (to get xattr of an inode).
 * 2. Record a RL_GETXATTR relation between xattr and task process. Information flows from xattr to the task (task reads the xattr).
 * 3. Record a RL_PROC_WRITE relation between task and its cred. Information flows from task to its cred.
 * The criteria to be met so as not to record the relations are:
 * 1. If any of the cred, task, and inode provenance are not tracked and if the capture all is not set, or
 * 2. If the relation RL_GETXATTR should not be recorded, or
 * 3. Failure occurred.
 * @param cprov The cred provenance entry.
 * @param tprov The task provenance entry.
 * @param name The name of the extended attribute.
 * @return 0 if no error occurred; -ENOMEM if no memory can be allocated from long provenance cache to create a new long provenance entry. Other error codes from "record_relation" function or unknown.
 *
 */
static __always_inline int record_read_xattr(struct provenance *cprov,
					     struct provenance *tprov,
					     struct provenance *iprov,
					     const char *name)
{
	union long_prov_elt *xattr;
	int rc = 0;

	if (!provenance_is_tracked(prov_elt(iprov))
	    && !provenance_is_tracked(prov_elt(tprov))
	    && !provenance_is_tracked(prov_elt(cprov))
	    && !prov_policy.prov_all)
		return 0;
	if (!should_record_relation(RL_GETXATTR, prov_entry(iprov), prov_entry(cprov)))
		return 0;
	xattr = alloc_long_provenance(ENT_XATTR);
	if (!xattr) {
		rc = -ENOMEM;
		goto out;
	}
	memcpy(xattr->xattr_info.name, name, PROV_XATTR_NAME_SIZE - 1);
	xattr->xattr_info.name[PROV_XATTR_NAME_SIZE - 1] = '\0';

	rc = record_relation(RL_GETXATTR_INODE, prov_entry(iprov), xattr, NULL, 0);
	if (rc < 0)
		goto out;
	rc = record_relation(RL_GETXATTR, xattr, prov_entry(tprov), NULL, 0);
	if (rc < 0)
		goto out;
	rc = record_relation(RL_PROC_WRITE, prov_entry(tprov), prov_entry(cprov), NULL, 0);
out:
	free_long_provenance(xattr);
	return rc;
}

#define FILE__EXECUTE           0x00000001UL
#define FILE__READ              0x00000002UL
#define FILE__APPEND            0x00000004UL
#define FILE__WRITE             0x00000008UL
#define DIR__SEARCH             0x00000010UL
#define DIR__WRITE              0x00000020UL
#define DIR__READ               0x00000040UL

/*!
 * @brief Helper function to return permissions of a file/directory from mask.
 *
 * @param mode The mode of the inode.
 * @param mask The permission mask.
 * @return The permission of the file/directory/socket....
 *
 */
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
