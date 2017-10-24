/*
 *
 * Author: Thomas Pasquier <thomas.pasquier@cl.cam.ac.uk>
 *
 * Copyright (C) 2015 University of Cambridge
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 */
#include <linux/slab.h>
#include <linux/lsm_hooks.h>
#include <linux/msg.h>
#include <net/sock.h>
#include <net/af_unix.h>
#include <linux/binfmts.h>
#include <linux/random.h>
#include <linux/xattr.h>
#include <linux/file.h>
#include <linux/workqueue.h>

#include "provenance.h"
#include "provenance_net.h"
#include "provenance_inode.h"
#include "provenance_task.h"

#ifdef CONFIG_SECURITY_PROVENANCE_PERSISTENCE
struct save_work {
	struct work_struct work;
	struct dentry *dentry;
};

static void __do_prov_save(struct work_struct *pwork)
{
	struct save_work *w = container_of(pwork, struct save_work, work);
	struct dentry *dentry = w->dentry;

	if (!dentry)
		goto free_work;
	save_provenance(dentry);
free_work:
	kfree(w);
}

static struct workqueue_struct *prov_queue;
static inline void queue_save_provenance(struct provenance *provenance,
					 struct dentry *dentry)
{
	struct save_work *work;

	if (!prov_queue)
		return;
	// not initialised or already saved
	if (!provenance->initialised || provenance->saved)
		return;
	work = kmalloc(sizeof(struct save_work), GFP_ATOMIC);
	if (!work)
		return;
	work->dentry = dentry;
	INIT_WORK(&work->work, __do_prov_save);
	queue_work(prov_queue, &work->work);
}
#else
static inline void queue_save_provenance(struct provenance *provenance,
					 struct dentry *dentry)
{
}
#endif

/*
 * initialise the security for the init task
 */
static void cred_init_provenance(void)
{
	struct cred *cred = (struct cred*)current->real_cred;
	struct provenance *prov = alloc_provenance(ACT_TASK, GFP_KERNEL);

	if (!prov)
		panic("Provenance:  Failed to initialize initial task.\n");
	node_uid(prov_elt(prov)) = __kuid_val(cred->euid);
	node_gid(prov_elt(prov)) = __kgid_val(cred->egid);
	cred->provenance = prov;
}

/*
 * @cred points to the credentials.
 * @gfp indicates the atomicity of any memory allocations.
 * Only allocate sufficient memory and attach to @cred such that
 * cred_transfer() will not get ENOMEM.
 */
static int provenance_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{
	struct provenance *prov  = alloc_provenance(ACT_TASK, gfp);

	if (!prov)
		return -ENOMEM;

	node_uid(prov_elt(prov)) = __kuid_val(cred->euid);
	node_gid(prov_elt(prov)) = __kgid_val(cred->egid);

	cred->provenance = prov;
	return 0;
}

/*
 * @cred points to the credentials.
 * Deallocate and clear the cred->security field in a set of credentials.
 */
static void provenance_cred_free(struct cred *cred)
{
	if (cred->provenance) {
		terminate_task(cred->provenance);
		free_provenance(cred->provenance);
	}
	cred->provenance = NULL;
}

/*
 * @new points to the new credentials.
 * @old points to the original credentials.
 * @gfp indicates the atomicity of any memory allocations.
 * Prepare a new set of credentials by copying the data from the old set.
 */
static int provenance_cred_prepare(struct cred *new,
				   const struct cred *old,
				   gfp_t gfp)
{
	struct provenance *old_prov = old->provenance;
	struct provenance *prov = alloc_provenance(ACT_TASK, gfp);
	unsigned long irqflags;
	int rc;

	if (!prov)
		return -ENOMEM;
	//task_config_from_file(current);
	node_uid(prov_elt(prov)) = __kuid_val(new->euid);
	node_gid(prov_elt(prov)) = __kgid_val(new->egid);
	spin_lock_irqsave_nested(prov_lock(old_prov), irqflags, PROVENANCE_LOCK_TASK);
	prov->has_mmap = old_prov->has_mmap;
	rc = informs(RL_CLONE, old_prov, prov, NULL);
	spin_unlock_irqrestore(prov_lock(old_prov), irqflags);
	new->provenance = prov;
	return rc;
}

/*
 * @new points to the new credentials.
 * @old points to the original credentials.
 * Transfer data from original creds to new creds
 */
static void provenance_cred_transfer(struct cred *new, const struct cred *old)
{
	const struct provenance *old_prov = old->provenance;
	struct provenance *prov = new->provenance;

	*prov =  *old_prov;
}

/*
 * Update the module's state after setting one or more of the user
 * identity attributes of the current process.  The @flags parameter
 * indicates which of the set*uid system calls invoked this hook.if
 * @new is the set of credentials that will be installed.  Modifications
 * should be made to this rather than to @current->cred.
 * @old is the set of credentials that are being replaces
 * @flags contains one of the LSM_SETID_* values.
 * Return 0 on success.
 */
static int provenance_task_fix_setuid(struct cred *new,
				      const struct cred *old,
				      int flags)
{
	struct provenance *old_prov = old->provenance;
	struct provenance *prov = new->provenance;
	unsigned long irqflags;
	int rc;

	spin_lock_irqsave_nested(prov_lock(old_prov), irqflags, PROVENANCE_LOCK_TASK);
	rc = informs(RL_CHANGE, old_prov, prov, NULL);
	spin_unlock_irqrestore(prov_lock(old_prov), irqflags);
	return rc;
}

/*
 * Allocate and attach a security structure to @inode->i_security.  The
 * i_security field is initialized to NULL when the inode structure is
 * allocated.
 * @inode contains the inode structure.
 * Return 0 if operation was successful.
 */
static int provenance_inode_alloc_security(struct inode *inode)
{
	struct provenance *iprov = alloc_provenance(ENT_INODE_UNKNOWN, GFP_KERNEL);
	struct provenance *sprov;

	if (unlikely(!iprov))
		return -ENOMEM;
	sprov = inode->i_sb->s_provenance;
	memcpy(prov_elt(iprov)->inode_info.sb_uuid, prov_elt(sprov)->sb_info.uuid, 16 * sizeof(uint8_t));
	inode->i_provenance = iprov;
	refresh_inode_provenance(inode, true);
	return 0;
}

/*
 * @inode contains the inode structure.
 * Deallocate the inode security structure and set @inode->i_security to
 * NULL.
 */
static void provenance_inode_free_security(struct inode *inode)
{
	if (inode->i_provenance) {
		close_inode(inode->i_provenance);
		free_provenance(inode->i_provenance);
	}
	inode->i_provenance = NULL;
}

/*
 * Check permission to create a regular file.
 * @dir contains inode structure of the parent of the new file.
 * @dentry contains the dentry structure for the file to be created.
 * @mode contains the file mode of the file to be created.
 * Return 0 if permission is granted.
 */
static int provenance_inode_create(struct inode *dir,
				   struct dentry *dentry,
				   umode_t mode)
{
	struct provenance *cprov = get_current_provenance();
	struct provenance *iprov = dir->i_provenance;
	unsigned long irqflags;
	int rc;

	if (!iprov)
		return -ENOMEM;
	spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_TASK);
	spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_DIR);
	rc = generates(RL_WRITE, cprov, iprov, NULL);
	spin_unlock(prov_lock(iprov));
	spin_unlock_irqrestore(prov_lock(cprov), irqflags);
	return rc;
}

/*
 * Check permission before accessing an inode.  This hook is called by the
 * existing Linux permission function, so a security module can use it to
 * provide additional checking for existing Linux permission checks.
 * Notice that this hook is called when a file is opened (as well as many
 * other operations), whereas the file_security_ops permission hook is
 * called when the actual read/write operations are performed.
 * @inode contains the inode structure to check.
 * @mask contains the permission mask.
 * Return 0 if permission is granted.
 */
static int provenance_inode_permission(struct inode *inode, int mask)
{
	struct provenance *cprov = get_current_provenance();
	struct provenance *iprov = NULL;
	uint32_t perms;
	unsigned long irqflags;
	int rc = 0;

	if (!mask)
		return 0;
	if (unlikely(IS_PRIVATE(inode)))
		return 0;
	iprov = inode_provenance(inode, false);
	if (!iprov)
		return -ENOMEM;
	perms = file_mask_to_perms(inode->i_mode, mask);
	spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_TASK);
	spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
	if (is_inode_dir(inode)) {
		if ((perms & (DIR__WRITE)) != 0)
			rc = uses(RL_PERM_WRITE, iprov, cprov, NULL);
		if (rc < 0)
			goto out;
		if ((perms & (DIR__READ)) != 0)
			rc = uses(RL_PERM_READ, iprov, cprov, NULL);
		if (rc < 0)
			goto out;
		if ((perms & (DIR__SEARCH)) != 0)
			rc = uses(RL_PERM_EXEC, iprov, cprov, NULL);
	} else if (is_inode_socket(inode)) {
		if ((perms & (FILE__WRITE | FILE__APPEND)) != 0)
			rc = uses(RL_PERM_WRITE, iprov, cprov, NULL);
		if (rc < 0)
			goto out;
		if ((perms & (FILE__READ)) != 0)
			rc = uses(RL_PERM_READ, iprov, cprov, NULL);
	} else {
		if ((perms & (FILE__WRITE | FILE__APPEND)) != 0)
			rc = uses(RL_PERM_WRITE, iprov, cprov, NULL);
		if (rc < 0)
			goto out;
		if ((perms & (FILE__READ)) != 0)
			rc = uses(RL_PERM_READ, iprov, cprov, NULL);
		if (rc < 0)
			goto out;
		if ((perms & (FILE__EXECUTE)) != 0)
			rc = uses(RL_PERM_EXEC, iprov, cprov, NULL);
	}
out:
	spin_unlock(prov_lock(iprov));
	spin_unlock_irqrestore(prov_lock(cprov), irqflags);
	return rc;
}

/*
 * Check permission before creating a new hard link to a file.
 * @old_dentry contains the dentry structure for an existing
 * link to the file.
 * @dir contains the inode structure of the parent directory
 * of the new link.
 * @new_dentry contains the dentry structure for the new link.
 * Return 0 if permission is granted.
 */

static int provenance_inode_link(struct dentry *old_dentry,
				 struct inode *dir,
				 struct dentry *new_dentry)
{
	struct provenance *cprov = get_current_provenance();
	struct provenance *dprov = NULL;
	struct provenance *iprov;
	unsigned long irqflags;
	int rc;

	iprov = dentry_provenance(old_dentry);
	if (!iprov)
		return -ENOMEM;

	dprov = dir->i_provenance;
	if (!dprov)
		return -ENOMEM;
	spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_TASK);
	spin_lock_nested(prov_lock(dprov), PROVENANCE_LOCK_DIR);
	spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
	rc = generates(RL_LINK, cprov, dprov, NULL);
	if (rc < 0)
		goto out;
	rc = generates(RL_LINK, cprov, iprov, NULL);
	if (rc < 0)
		goto out;
	rc = derives(RL_LINK_INODE, dprov, iprov, NULL);
out:
	spin_unlock(prov_lock(iprov));
	spin_unlock(prov_lock(dprov));
	spin_unlock_irqrestore(prov_lock(cprov), irqflags);
	record_inode_name_from_dentry(new_dentry, iprov);
	return rc;
}

// TODO probably deal with unlink (useful for stream processing)

/*
 * Check for permission to rename a file or directory.
 * @old_dir contains the inode structure for parent of the old link.
 * @old_dentry contains the dentry structure of the old link.
 * @new_dir contains the inode structure for parent of the new link.
 * @new_dentry contains the dentry structure of the new link.
 * Return 0 if permission is granted.
 */
static int provenance_inode_rename(struct inode *old_dir,
				   struct dentry *old_dentry,
				   struct inode *new_dir,
				   struct dentry *new_dentry)
{
	return provenance_inode_link(old_dentry, new_dir, new_dentry);
}

/*
 * Check permission before setting file attributes.  Note that the kernel
 * call to notify_change is performed from several locations, whenever
 * file attributes change (such as when a file is truncated, chown/chmod
 * operations, transferring disk quotas, etc).
 * @dentry contains the dentry structure for the file.
 * @attr is the iattr structure containing the new file attributes.
 * Return 0 if permission is granted.
 */
static int provenance_inode_setattr(struct dentry *dentry, struct iattr *iattr)
{
	struct provenance *cprov = get_current_provenance();
	struct provenance *iprov;
	struct provenance *iattrprov;
	unsigned long irqflags;
	int rc;

	iprov = dentry_provenance(dentry);
	if (!iprov)
		return -ENOMEM;
	iattrprov = alloc_provenance(ENT_IATTR, GFP_KERNEL);
	if (!iattrprov)
		return -ENOMEM;

	prov_elt(iattrprov)->iattr_info.valid = iattr->ia_valid;
	prov_elt(iattrprov)->iattr_info.mode = iattr->ia_mode;
	node_uid(prov_elt(iattrprov)) = __kuid_val(iattr->ia_uid);
	node_gid(prov_elt(iattrprov)) = __kgid_val(iattr->ia_gid);
	prov_elt(iattrprov)->iattr_info.size = iattr->ia_size;
	prov_elt(iattrprov)->iattr_info.atime = iattr->ia_atime.tv_sec;
	prov_elt(iattrprov)->iattr_info.mtime = iattr->ia_mtime.tv_sec;
	prov_elt(iattrprov)->iattr_info.ctime = iattr->ia_ctime.tv_sec;

	spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_TASK);
	spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
	rc = generates(RL_SETATTR, cprov, iattrprov, NULL);
	if (rc < 0)
		goto out;
	rc = derives(RL_SETATTR_INODE, iattrprov, iprov, NULL);
out:
	queue_save_provenance(iprov, dentry);
	spin_unlock(prov_lock(iprov));
	spin_unlock_irqrestore(prov_lock(cprov), irqflags);
	free_provenance(iattrprov);
	return rc;
}

/*
 * Check permission before obtaining file attributes.
 * @path contains the path structure for the file.
 * Return 0 if permission is granted.
 */
static int provenance_inode_getattr(const struct path *path)
{
	struct provenance *cprov = get_current_provenance();
	struct provenance *iprov = dentry_provenance(path->dentry);
	unsigned long irqflags;
	int rc;

	if (!iprov)
		return -ENOMEM;

	spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_TASK);
	spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
	rc = uses(RL_GETATTR, iprov, cprov, NULL);
	spin_unlock(prov_lock(iprov));
	spin_unlock_irqrestore(prov_lock(cprov), irqflags);
	return rc;
}

/*
 * Check the permission to read the symbolic link.
 * @dentry contains the dentry structure for the file link.
 * Return 0 if permission is granted.
 */
static int provenance_inode_readlink(struct dentry *dentry)
{
	struct provenance *cprov = get_current_provenance();
	struct provenance *iprov = dentry_provenance(dentry);
	unsigned long irqflags;
	int rc;

	if (!iprov)
		return -ENOMEM;

	spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_TASK);
	spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
	rc = uses(RL_READLINK, iprov, cprov, NULL);
	spin_unlock(prov_lock(iprov));
	spin_unlock_irqrestore(prov_lock(cprov), irqflags);
	return rc;
}

static int provenance_inode_setxattr(struct dentry *dentry,
				     const char *name,
				     const void *value,
				     size_t size,
				     int flags)
{
	struct provenance *prov;
	union prov_elt *setting;

	if (strcmp(name, XATTR_NAME_PROVENANCE) == 0) { // provenance xattr
		if (size != sizeof(union prov_elt))
			return -ENOMEM;
		prov = dentry_provenance(dentry);
		setting = (union prov_elt*)value;

		if (provenance_is_tracked(setting))
			set_tracked(prov_elt(prov));
		else
			clear_tracked(prov_elt(prov));

		if (provenance_is_opaque(setting))
			set_opaque(prov_elt(prov));
		else
			clear_opaque(prov_elt(prov));

		if (provenance_does_propagate(setting))
			set_propagate(prov_elt(prov));
		else
			clear_propagate(prov_elt(prov));

		prov_bloom_merge(prov_taint(prov_elt(prov)), prov_taint(setting));
	}
	return 0;
}

/*
 * Update inode security field after successful setxattr operation.
 * @value identified by @name for @dentry.
 */
static void provenance_inode_post_setxattr(struct dentry *dentry,
					   const char *name,
					   const void *value,
					   size_t size,
					   int flags)
{
	struct provenance *cprov = get_current_provenance();
	struct provenance *iprov = dentry_provenance(dentry);
	unsigned long irqflags;

	if (strcmp(name, XATTR_NAME_PROVENANCE) == 0)
		return;

	if (!iprov)
		return;
	spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_TASK);
	spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
	if (provenance_is_opaque(prov_elt(cprov)) || provenance_is_opaque(prov_elt(iprov)))
		goto out;
	if (!provenance_is_tracked(prov_elt(cprov)) && !provenance_is_tracked(prov_elt(iprov)))
		goto out;
	record_write_xattr(RL_SETXATTR, iprov, cprov, name, value, size, flags);
out:
	queue_save_provenance(iprov, dentry);
	spin_unlock(prov_lock(iprov));
	spin_unlock_irqrestore(prov_lock(cprov), irqflags);
}

/*
 * Check permission before obtaining the extended attributes
 * identified by @name for @dentry.
 * Return 0 if permission is granted.
 */
static int provenance_inode_getxattr(struct dentry *dentry, const char *name)
{
	struct provenance *cprov = get_current_provenance();
	struct provenance *iprov = dentry_provenance(dentry);
	int rc = 0;
	unsigned long irqflags;

	if (strcmp(name, XATTR_NAME_PROVENANCE) == 0)
		return 0;

	if (!iprov)
		return -ENOMEM;
	spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_TASK);
	spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
	if (provenance_is_opaque(prov_elt(cprov)) || provenance_is_opaque(prov_elt(iprov)))
		goto out;
	if (!provenance_is_tracked(prov_elt(cprov)) && !provenance_is_tracked(prov_elt(iprov)))
		goto out;
	rc = record_read_xattr(cprov, iprov, name);
out:
	spin_unlock(prov_lock(iprov));
	spin_unlock_irqrestore(prov_lock(cprov), irqflags);
	return rc;
}

/*
 * Check permission before obtaining the list of extended attribute
 * names for @dentry.
 * Return 0 if permission is granted.
 */
static int provenance_inode_listxattr(struct dentry *dentry)
{
	struct provenance *cprov = get_current_provenance();
	struct provenance *iprov = dentry_provenance(dentry);
	unsigned long irqflags;
	int rc;

	if (!iprov)
		return -ENOMEM;
	spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_TASK);
	spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
	rc = uses(RL_LSTXATTR, iprov, cprov, NULL);
	spin_unlock(prov_lock(iprov));
	spin_unlock_irqrestore(prov_lock(cprov), irqflags);
	return rc;
}

/*
 * Check permission before removing the extended attribute
 * identified by @name for @dentry.
 * Return 0 if permission is granted.
 */
static int provenance_inode_removexattr(struct dentry *dentry, const char *name)
{
	struct provenance *cprov = get_current_provenance();
	struct provenance *iprov = dentry_provenance(dentry);
	unsigned long irqflags;
	int rc = 0;

	if (strcmp(name, XATTR_NAME_PROVENANCE) == 0)
		return -EPERM;

	if (!iprov)
		return -ENOMEM;

	spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_TASK);
	spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
	if (provenance_is_opaque(prov_elt(cprov)) || provenance_is_opaque(prov_elt(iprov)))
		goto out;
	if (!provenance_is_tracked(prov_elt(cprov)) && !provenance_is_tracked(prov_elt(iprov)))
		goto out;
	rc = record_write_xattr(RL_RMVXATTR, iprov, cprov, name, NULL, 0, 0);
out:
	queue_save_provenance(iprov, dentry);
	spin_unlock(prov_lock(iprov));
	spin_unlock_irqrestore(prov_lock(cprov), irqflags);
	return rc;
}

static int provenance_inode_getsecurity(struct inode *inode,
					const char *name,
					void **buffer,
					bool alloc)
{
	struct provenance *iprov = inode_provenance(inode, true);

	if (unlikely(!iprov))
		return -ENOMEM;
	if (strcmp(name, XATTR_PROVENANCE_SUFFIX))
		return -EOPNOTSUPP;
	if (!alloc)
		goto out;
	*buffer = kmalloc(sizeof(union prov_elt), GFP_KERNEL);
	memcpy(*buffer, prov_elt(iprov), sizeof(union prov_elt));
out:
	return sizeof(union prov_elt);
}

static int provenance_inode_listsecurity(struct inode *inode,
					 char *buffer,
					 size_t buffer_size)
{
	const int len = sizeof(XATTR_NAME_PROVENANCE);

	if (buffer && len <= buffer_size)
		memcpy(buffer, XATTR_NAME_PROVENANCE, len);
	return len;
}

/*
 * Check file permissions before accessing an open file.  This hook is
 * called by various operations that read or write files.  A security
 * module can use this hook to perform additional checking on these
 * operations, e.g.  to revalidate permissions on use to support privilege
 * bracketing or policy changes.  Notice that this hook is used when the
 * actual read/write operations are performed, whereas the
 * inode_security_ops hook is called when a file is opened (as well as
 * many other operations).
 * Caveat:  Although this hook can be used to revalidate permissions for
 * various system call operations that read or write files, it does not
 * address the revalidation of permissions for memory-mapped files.
 * Security modules must handle this separately if they need such
 * revalidation.
 * @file contains the file structure being accessed.
 * @mask contains the requested permissions.
 * Return 0 if permission is granted.
 */
static int provenance_file_permission(struct file *file, int mask)
{
	struct provenance *cprov = get_current_provenance();
	struct provenance *iprov = file_provenance(file);
	struct inode *inode = file_inode(file);
	uint32_t perms;
	unsigned long irqflags;
	int rc = 0;

	if (!iprov)
		return -ENOMEM;
	perms = file_mask_to_perms(inode->i_mode, mask);
	spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_TASK);
	spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
	if (is_inode_dir(inode)) {
		if ((perms & (DIR__WRITE)) != 0)
			rc = generates(RL_WRITE, cprov, iprov, file);
		if (rc < 0)
			goto out;
		if ((perms & (DIR__READ)) != 0)
			rc = uses(RL_READ, iprov, cprov, file);
		if (rc < 0)
			goto out;
		if ((perms & (DIR__SEARCH)) != 0)
			rc = uses(RL_SEARCH, iprov, cprov, file);
	} else if (is_inode_socket(inode)) {
		if ((perms & (FILE__WRITE | FILE__APPEND)) != 0)
			rc = generates(RL_SND, cprov, iprov, file);
		if (rc < 0)
			goto out;
		if ((perms & (FILE__READ)) != 0)
			rc = uses(RL_RCV, iprov, cprov, file);
	} else{
		if ((perms & (FILE__WRITE | FILE__APPEND)) != 0)
			rc = generates(RL_WRITE, cprov, iprov, file);
		if (rc < 0)
			goto out;
		if ((perms & (FILE__READ)) != 0)
			rc = uses(RL_READ, iprov, cprov, file);
		if (rc < 0)
			goto out;
		if ((perms & (FILE__EXECUTE)) != 0) {
			if (provenance_is_opaque(prov_elt(iprov)))
				set_opaque(prov_elt(cprov));
			else
				rc = uses(RL_EXEC, iprov, cprov, file);
		}
	}
out:
	queue_save_provenance(iprov, file_dentry(file));
	spin_unlock(prov_lock(iprov));
	spin_unlock_irqrestore(prov_lock(cprov), irqflags);
	return rc;
}

/*
 * Save open-time permission checking state for later use upon
 * file_permission, and recheck access if anything has changed
 * since inode_permission.
 */
static int provenance_file_open(struct file *file, const struct cred *cred)
{
	struct provenance *cprov = get_current_provenance();
	struct provenance *iprov = file_provenance(file);
	unsigned long irqflags;
	int rc;

	if (!iprov)
		return -ENOMEM;
	spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_TASK);
	spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
	rc = uses(RL_OPEN, iprov, cprov, file);
	spin_unlock(prov_lock(iprov));
	spin_unlock_irqrestore(prov_lock(cprov), irqflags);
	return rc;
}

/*
 * Check permissions for a mmap operation.  The @file may be NULL, e.g.
 * if mapping anonymous memory.
 * @file contains the file structure for file to map (may be NULL).
 * @reqprot contains the protection requested by the application.
 * @prot contains the protection that will be applied by the kernel.
 * @flags contains the operational flags.
 * Return 0 if permission is granted.
 */
static int provenance_mmap_file(struct file *file,
				unsigned long reqprot,
				unsigned long prot,
				unsigned long flags)
{
	struct provenance *cprov = get_current_provenance();
	struct provenance *iprov = NULL;
	struct provenance *bprov = NULL;
	unsigned long irqflags;
	int rc = 0;

	if (unlikely(!file))
		return 0;
	iprov = file_provenance(file);
	if (!iprov)
		return -ENOMEM;
	spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_TASK);
	spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
	rc = uses(RL_READ, iprov, cprov, file);
	if (rc < 0)
		goto out;
	if ((flags & MAP_TYPE) == MAP_SHARED) {
		cprov->has_mmap = 1;
		if ((prot & (PROT_WRITE)) != 0)
			rc = generates(RL_MMAP_WRITE, cprov, iprov, file);
		if (rc < 0)
			goto out;
		if ((prot & (PROT_READ)) != 0)
			rc = uses(RL_MMAP_READ, iprov, cprov, file);
		if (rc < 0)
			goto out;
		if ((prot & (PROT_EXEC)) != 0)
			rc = uses(RL_MMAP_EXEC, iprov, cprov, file);
	} else{
		bprov = branch_mmap(iprov, cprov);
		if (!bprov)
			goto out;
		rc = derives(RL_MMAP, iprov, bprov, file);
		if (rc < 0)
			goto out;
		if ((prot & (PROT_WRITE)) != 0)
			rc = generates(RL_MMAP_WRITE, cprov, bprov, file);
		if (rc < 0)
			goto out;
		if ((prot & (PROT_READ)) != 0)
			rc = uses(RL_MMAP_READ, bprov, cprov, file);
		if (rc < 0)
			goto out;
		if ((prot & (PROT_EXEC)) != 0)
			rc = uses(RL_MMAP_EXEC, bprov, cprov, file);
	}
out:
	spin_unlock(prov_lock(iprov));
	spin_unlock_irqrestore(prov_lock(cprov), irqflags);
	if (bprov) {
		close_inode(bprov);
		free_provenance(bprov);
	}
	return rc;
}

/*
 * @file contains the file structure.
 * @cmd contains the operation to perform.
 * @arg contains the operational arguments.
 * Check permission for an ioctl operation on @file.  Note that @arg
 * sometimes represents a user space pointer; in other cases, it may be a
 * simple integer value.  When @arg represents a user space pointer, it
 * should never be used by the security module.
 * Return 0 if permission is granted.
 */
static int provenance_file_ioctl(struct file *file,
				 unsigned int cmd,
				 unsigned long arg)
{
	struct provenance *cprov = get_current_provenance();
	struct provenance *iprov = file_provenance(file);
	unsigned long irqflags;
	int rc;

	if (!iprov)
		return -ENOMEM;
	spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_TASK);
	spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
	rc = generates(RL_WRITE, cprov, iprov, NULL);
	if (rc < 0)
		goto out;
	rc = uses(RL_READ, iprov, cprov, NULL);
out:
	queue_save_provenance(iprov, file_dentry(file));
	spin_unlock(prov_lock(iprov));
	spin_unlock_irqrestore(prov_lock(cprov), irqflags);
	return rc;
}

/* msg */

/*
 * Allocate and attach a security structure to the msg->security field.
 * The security field is initialized to NULL when the structure is first
 * created.
 * @msg contains the message structure to be modified.
 * Return 0 if operation was successful and permission is granted.
 */
static int provenance_msg_msg_alloc_security(struct msg_msg *msg)
{
	struct provenance *cprov = get_current_provenance();
	struct provenance *mprov;
	unsigned long irqflags;
	int rc;

	/* alloc new prov struct with generated id */
	mprov = alloc_provenance(ENT_MSG, GFP_KERNEL);

	if (!mprov)
		return -ENOMEM;
	prov_elt(mprov)->msg_msg_info.type = msg->m_type;
	msg->provenance = mprov;
	spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_TASK);
	rc = generates(RL_CREATE, cprov, mprov, NULL);
	spin_unlock_irqrestore(prov_lock(cprov), irqflags);
	return rc;
}

/*
 * Deallocate the security structure for this message.
 * @msg contains the message structure to be modified.
 */
static void provenance_msg_msg_free_security(struct msg_msg *msg)
{
	if (msg->provenance)
		free_provenance(msg->provenance);
	msg->provenance = NULL;
}


static inline int __mq_msgsnd(struct msg_msg *msg)
{
	struct provenance *cprov = get_current_provenance();
	struct provenance *mprov = msg->provenance;
	unsigned long irqflags;
	int rc;

	spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_TASK);
	spin_lock_nested(prov_lock(mprov), PROVENANCE_LOCK_MSG);
	rc = generates(RL_CREATE, cprov, mprov, NULL);
	spin_unlock(prov_lock(mprov));
	spin_unlock_irqrestore(prov_lock(cprov), irqflags);
	return rc;
}

/*
 * Check permission before a message, @msg, is enqueued on the message
 * queue, @msq.
 * @msq contains the message queue to send message to.
 * @msg contains the message to be enqueued.
 * @msqflg contains operational flags.
 * Return 0 if permission is granted.
 */
static int provenance_msg_queue_msgsnd(struct msg_queue *msq,
				       struct msg_msg *msg,
				       int msqflg)
{
	return __mq_msgsnd(msg);
}

#ifdef CONFIG_SECURITY_FLOW_FRIENDLY
static int provenance_mq_timedsend(struct inode *inode, struct msg_msg *msg,
				   struct timespec *ts)
{
	return __mq_msgsnd(msg);
}
#endif

static inline int __mq_msgrcv(struct provenance *cprov, struct msg_msg *msg)
{
	struct provenance *mprov = msg->provenance;
	unsigned long irqflags;
	int rc;

	spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_TASK);
	spin_lock_nested(prov_lock(mprov), PROVENANCE_LOCK_MSG);
	rc = uses(RL_READ, mprov, cprov, NULL);
	spin_unlock(prov_lock(mprov));
	spin_unlock_irqrestore(prov_lock(cprov), irqflags);
	return rc;
}

/*
 * Check permission before a message, @msg, is removed from the message
 * queue, @msq.  The @target task structure contains a pointer to the
 * process that will be receiving the message (not equal to the current
 * process when inline receives are being performed).
 * @msq contains the message queue to retrieve message from.
 * @msg contains the message destination.
 * @target contains the task structure for recipient process.
 * @type contains the type of message requested.
 * @mode contains the operational flags.
 * Return 0 if permission is granted.
 */
static int provenance_msg_queue_msgrcv(struct msg_queue *msq,
				       struct msg_msg *msg,
				       struct task_struct *target,
				       long type,
				       int mode)
{
	struct provenance *cprov = target->cred->provenance;

	return __mq_msgrcv(cprov, msg);
}

#ifdef CONFIG_SECURITY_FLOW_FRIENDLY
static int provenance_mq_timedreceive(struct inode *inode, struct msg_msg *msg,
				      struct timespec *ts)
{
	struct provenance *cprov = get_current_provenance();

	return __mq_msgrcv(cprov, msg);
}
#endif

/*
 * Allocate and attach a security structure to the shp->shm_perm.security
 * field.  The security field is initialized to NULL when the structure is
 * first created.
 * @shp contains the shared memory structure to be modified.
 * Return 0 if operation was successful and permission is granted.
 */
static int provenance_shm_alloc_security(struct shmid_kernel *shp)
{
	struct provenance *cprov = get_current_provenance();
	struct provenance *sprov = alloc_provenance(ENT_SHM, GFP_KERNEL);
	unsigned long irqflags;
	int rc;

	if (!sprov)
		return -ENOMEM;
	prov_elt(sprov)->shm_info.mode = shp->shm_perm.mode;
	shp->shm_perm.provenance = sprov;
	spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_TASK);
	rc = uses(RL_READ, sprov, cprov, NULL);
	if (rc < 0)
		goto out;
	rc = generates(RL_WRITE, cprov, sprov, NULL);
out:
	spin_unlock_irqrestore(prov_lock(cprov), irqflags);
	return 0;
}

/*
 * Deallocate the security struct for this memory segment.
 * @shp contains the shared memory structure to be modified.
 */
static void provenance_shm_free_security(struct shmid_kernel *shp)
{
	if (shp->shm_perm.provenance)
		free_provenance(shp->shm_perm.provenance);
	shp->shm_perm.provenance = NULL;
}

/*
 * Check permissions prior to allowing the shmat system call to attach the
 * shared memory segment @shp to the data segment of the calling process.
 * The attaching address is specified by @shmaddr.
 * @shp contains the shared memory structure to be modified.
 * @shmaddr contains the address to attach memory region to.
 * @shmflg contains the operational flags.
 * Return 0 if permission is granted.
 */
static int provenance_shm_shmat(struct shmid_kernel *shp, char __user *shmaddr, int shmflg)
{
	struct provenance *cprov = get_current_provenance();
	struct provenance *sprov = shp->shm_perm.provenance;
	unsigned long irqflags;
	int rc = 0;

	if (!sprov)
		return -ENOMEM;
	spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_TASK);
	spin_lock_nested(prov_lock(sprov), PROVENANCE_LOCK_SHM);
	if (shmflg & SHM_RDONLY)
		rc = uses(RL_READ, sprov, cprov, NULL);
	else {
		rc = uses(RL_READ, sprov, cprov, NULL);
		if (rc < 0)
			goto out;
		rc = generates(RL_WRITE, cprov, sprov, NULL);
	}
out:
	spin_unlock(prov_lock(sprov));
	spin_unlock_irqrestore(prov_lock(cprov), irqflags);
	return rc;
}

/*
 * Allocate and attach a security structure to the sk->sk_security field,
 * which is used to copy security attributes between local stream sockets.
 */
static int provenance_sk_alloc_security(struct sock *sk,
					int family,
					gfp_t priority)
{
	struct provenance *skprov = get_current_provenance();

	if (!skprov)
		return -ENOMEM;
	sk->sk_provenance = skprov;
	return 0;
}

/*
 * This hook allows a module to update or allocate a per-socket security
 * structure. Note that the security field was not added directly to the
 * socket structure, but rather, the socket security information is stored
 * in the associated inode.  Typically, the inode alloc_security hook will
 * allocate and and attach security information to
 * sock->inode->i_security.  This hook may be used to update the
 * sock->inode->i_security field with additional information that wasn't
 * available when the inode was allocated.
 * @sock contains the newly created socket structure.
 * @family contains the requested protocol family.
 * @type contains the requested communications type.
 * @protocol contains the requested protocol.
 * @kern set to 1 if a kernel socket.
 */
static int provenance_socket_post_create(struct socket *sock,
					 int family,
					 int type,
					 int protocol,
					 int kern)
{
	struct provenance *cprov  = get_current_provenance();
	struct provenance *iprov = socket_inode_provenance(sock);
	unsigned long irqflags;
	int rc;

	if (kern)
		return 0;
	spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_TASK);
	spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
	rc = generates(RL_CREATE, cprov, iprov, NULL);
	spin_unlock(prov_lock(iprov));
	spin_unlock_irqrestore(prov_lock(cprov), irqflags);
	return rc;
}

/*
 * Check permission before socket protocol layer bind operation is
 * performed and the socket @sock is bound to the address specified in the
 * @address parameter.
 * @sock contains the socket structure.
 * @address contains the address to bind to.
 * @addrlen contains the length of address.
 * Return 0 if permission is granted.
 */
static int provenance_socket_bind(struct socket *sock,
				  struct sockaddr *address,
				  int addrlen)
{
	struct provenance *cprov  = get_current_provenance();
	struct provenance *iprov = socket_inode_provenance(sock);
	struct sockaddr_in *ipv4_addr;
	uint8_t op;
	int rc;

	if (!iprov)
		return -ENOMEM;

	if (provenance_is_opaque(prov_elt(cprov)))
		return 0;

	/* should we start tracking this socket */
	if (address->sa_family == PF_INET) {
		if (addrlen < sizeof(struct sockaddr_in))
			return -EINVAL;
		ipv4_addr = (struct sockaddr_in*)address;
		op = prov_ipv4_ingressOP(ipv4_addr->sin_addr.s_addr, ipv4_addr->sin_port);
		if ((op & PROV_SET_TRACKED) != 0) {
			set_tracked(prov_elt(iprov));
			set_tracked(prov_elt(cprov));
		}
		if ((op & PROV_SET_PROPAGATE) != 0) {
			set_propagate(prov_elt(iprov));
			set_propagate(prov_elt(cprov));
		}
		if ((op & PROV_SET_RECORD) != 0)
			set_record_packet(prov_elt(iprov));
	}
	rc = provenance_record_address(address, addrlen, iprov);
	if (rc < 0)
		return rc;
	rc = generates(RL_BIND, cprov, iprov, NULL);
	return rc;
}

/*
 * Check permission before socket protocol layer connect operation
 * attempts to connect socket @sock to a remote address, @address.
 * @sock contains the socket structure.
 * @address contains the address of remote endpoint.
 * @addrlen contains the length of address.
 * Return 0 if permission is granted.
 */
static int provenance_socket_connect(struct socket *sock,
				     struct sockaddr *address,
				     int addrlen)
{
	struct provenance *cprov  = get_current_provenance();
	struct provenance *iprov = socket_inode_provenance(sock);
	struct sockaddr_in *ipv4_addr;
	unsigned long irqflags;
	uint8_t op;
	int rc = 0;

	if (!iprov)
		return -ENOMEM;

	spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_TASK);
	spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
	if (provenance_is_opaque(prov_elt(cprov)))
		goto out;

	/* should we start tracking this socket */
	if (address->sa_family == PF_INET) {
		if (addrlen < sizeof(struct sockaddr_in)) {
			rc = -EINVAL;
			goto out;
		}
		ipv4_addr = (struct sockaddr_in*)address;
		op = prov_ipv4_egressOP(ipv4_addr->sin_addr.s_addr, ipv4_addr->sin_port);
		if ((op & PROV_SET_TRACKED) != 0) {
			set_tracked(prov_elt(iprov));
			set_tracked(prov_elt(cprov));
		}
		if ((op & PROV_SET_PROPAGATE) != 0) {
			set_propagate(prov_elt(iprov));
			set_propagate(prov_elt(cprov));
		}
		if ((op & PROV_SET_RECORD) != 0)
			set_record_packet(prov_elt(iprov));
	}
	rc = provenance_record_address(address, addrlen, iprov);
	if (rc < 0)
		return rc;
	rc = generates(RL_CONNECT, cprov, iprov, NULL);
out:
	spin_unlock(prov_lock(iprov));
	spin_unlock_irqrestore(prov_lock(cprov), irqflags);
	return rc;
}

/*
 * Check permission before socket protocol layer listen operation.
 * @sock contains the socket structure.
 * @backlog contains the maximum length for the pending connection queue.
 * Return 0 if permission is granted.
 */
static int provenance_socket_listen(struct socket *sock, int backlog)
{
	struct provenance *cprov  = get_current_provenance();
	struct provenance *iprov = socket_inode_provenance(sock);
	unsigned long irqflags;
	int rc;

	if (!iprov)
		return -ENOMEM;
	spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_TASK);
	spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
	rc = generates(RL_LISTEN, cprov, iprov, NULL);
	spin_unlock(prov_lock(iprov));
	spin_unlock_irqrestore(prov_lock(cprov), irqflags);
	return rc;
}

/*
 * Check permission before accepting a new connection.  Note that the new
 * socket, @newsock, has been created and some information copied to it,
 * but the accept operation has not actually been performed.
 * @sock contains the listening socket structure.
 * @newsock contains the newly created server socket for connection.
 * Return 0 if permission is granted.
 */
static int provenance_socket_accept(struct socket *sock, struct socket *newsock)
{
	struct provenance *cprov  = get_current_provenance();
	struct provenance *iprov = socket_inode_provenance(sock);
	struct provenance *niprov = socket_inode_provenance(newsock);
	unsigned long irqflags;
	int rc;

	spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_TASK);
	spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
	rc = derives(RL_ACCEPT_SOCKET, iprov, niprov, NULL);
	if (rc < 0)
		goto out;
	rc = uses(RL_ACCEPT, niprov, cprov, NULL);
out:
	spin_unlock(prov_lock(iprov));
	spin_unlock_irqrestore(prov_lock(cprov), irqflags);
	return rc;
}

/*
 * Check permission before transmitting a message to another socket.
 * @sock contains the socket structure.
 * @msg contains the message to be transmitted.
 * @size contains the size of message.
 * Return 0 if permission is granted.
 */
#ifdef CONFIG_SECURITY_FLOW_FRIENDLY
static int provenance_socket_sendmsg_always(struct socket *sock,
					    struct msghdr *msg,
					    int size)
#else /* CONFIG_SECURITY_FLOW_FRIENDLY */
static int provenance_socket_sendmsg(struct socket *sock,
				     struct msghdr *msg,
				     int size)
#endif /* CONFIG_SECURITY_FLOW_FRIENDLY */
{
	struct provenance *cprov = get_current_provenance();
	struct provenance *iprov = socket_inode_provenance(sock);
	struct provenance *pprov = NULL;
	struct sock *peer = NULL;
	unsigned long irqflags;
	int rc;

	if (!iprov)
		return -ENOMEM;
	if (sock->sk->sk_family == PF_UNIX &&
	    sock->sk->sk_type != SOCK_DGRAM) {             // datagran handled by unix_may_send
		peer = unix_peer_get(sock->sk);
		if (peer) {
			pprov = sk_provenance(peer);
			if (pprov == cprov)
				pprov = NULL;
		}
	}
	spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_TASK);
	spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
	rc = generates(RL_SND, cprov, iprov, NULL);
	if (pprov)
		rc = uses(RL_RCV_UNIX, iprov, pprov, NULL);
	spin_unlock(prov_lock(iprov));
	spin_unlock_irqrestore(prov_lock(cprov), irqflags);
	if (peer)
		sock_put(peer);
	return rc;
}

/*
 * Check permission before receiving a message from a socket.
 * @sock contains the socket structure.
 * @msg contains the message structure.
 * @size contains the size of message structure.
 * @flags contains the operational flags.
 * Return 0 if permission is granted.
 */
#ifdef CONFIG_SECURITY_FLOW_FRIENDLY
static int provenance_socket_recvmsg_always(struct socket *sock,
					    struct msghdr *msg,
					    int size,
					    int flags)
#else /* CONFIG_SECURITY_FLOW_FRIENDLY */
static int provenance_socket_recvmsg(struct socket *sock,
				     struct msghdr *msg,
				     int size,
				     int flags)
#endif /* CONFIG_SECURITY_FLOW_FRIENDLY */
{
	struct provenance *cprov = get_current_provenance();
	struct provenance *iprov = socket_inode_provenance(sock);
	struct provenance *pprov = NULL;
	struct sock *peer = NULL;
	unsigned long irqflags;
	int rc;

	if (!iprov)
		return -ENOMEM;
	if (sock->sk->sk_family == PF_UNIX &&
	    sock->sk->sk_type != SOCK_DGRAM) {             // datagran handled by unix_may_send
		peer = unix_peer_get(sock->sk);
		if (peer) {
			pprov = sk_provenance(peer);
			if (pprov == cprov)
				pprov = NULL;
		}
	}
	spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_TASK);
	spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
	if (pprov)
		rc = generates(RL_SND_UNIX, pprov, iprov, NULL);
	rc = uses(RL_RCV, iprov, cprov, NULL);
	spin_unlock(prov_lock(iprov));
	spin_unlock_irqrestore(prov_lock(cprov), irqflags);
	if (peer)
		sock_put(peer);
	return rc;
}

/*
 * Check permissions on incoming network packets.  This hook is distinct
 * from Netfilter's IP input hooks since it is the first time that the
 * incoming sk_buff @skb has been associated with a particular socket, @sk.
 * Must not sleep inside this hook because some callers hold spinlocks.
 * @sk contains the sock (not socket) associated with the incoming sk_buff.
 * @skb contains the incoming network data.
 */
static int provenance_socket_sock_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
	struct provenance *cprov = sk_provenance(sk);
	struct provenance *iprov;
	union prov_elt pckprov;
	uint16_t family = sk->sk_family;
	unsigned long irqflags;
	int rc = 0;

	if (!cprov)
		return 0;
	if (family != PF_INET)
		return 0;
	iprov = sk_inode_provenance(sk);
	if (!iprov)
		return 0;
	if (provenance_is_tracked(prov_elt(iprov)) ||
	    provenance_is_tracked(prov_elt(cprov))) {
		provenance_parse_skb_ipv4(skb, &pckprov);
		spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_TASK);
		spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
		rc = record_pck_to_inode(&pckprov, iprov);
		if (rc < 0)
			goto out;
		if (provenance_is_tracked(prov_elt(cprov)))
			rc = uses(RL_RCV, iprov, cprov, NULL);
		if (rc < 0)
			goto out;
		if (provenance_records_packet(prov_elt(iprov)))
			rc = record_packet_content(&pckprov, skb);
out:
		spin_unlock(prov_lock(iprov));
		spin_unlock_irqrestore(prov_lock(cprov), irqflags);
	}
	return rc;
}

/*
 * Check permissions before establishing a Unix domain stream connection
 * between @sock and @other.
 * @sock contains the sock structure.
 * @other contains the peer sock structure.
 * @newsk contains the new sock structure.
 * Return 0 if permission is granted.
 */
static int provenance_unix_stream_connect(struct sock *sock,
					  struct sock *other,
					  struct sock *newsk)
{
	struct provenance *cprov = get_current_provenance();
	struct provenance *iprov = sk_inode_provenance(sock);
	unsigned long irqflags;

	spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_TASK);
	spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
	generates(RL_CONNECT, cprov, iprov, NULL);
	spin_unlock(prov_lock(iprov));
	spin_unlock_irqrestore(prov_lock(cprov), irqflags);
	return 0;
}

/*
 * Check permissions before connecting or sending datagrams from @sock to
 * @other.
 * @sock contains the socket structure.
 * @other contains the peer socket structure.
 * Return 0 if permission is granted.
 */
static int provenance_unix_may_send(struct socket *sock,
				    struct socket *other)
{
	struct provenance *sprov = socket_provenance(sock);
	struct provenance *oprov = socket_inode_provenance(other);
	unsigned long irqflags;
	int rc;

	spin_lock_irqsave_nested(prov_lock(sprov), irqflags, PROVENANCE_LOCK_SOCKET);
	spin_lock_nested(prov_lock(oprov), PROVENANCE_LOCK_SOCK);
	rc = generates(RL_SND_UNIX, sprov, oprov, NULL);
	spin_unlock(prov_lock(oprov));
	spin_unlock_irqrestore(prov_lock(sprov), irqflags);
	return rc;
}

/* outdated description */
/*
 * Save security information in the bprm->security field, typically based
 * on information about the bprm->file, for later use by the apply_creds
 * hook.  This hook may also optionally check permissions (e.g. for
 * transitions between security domains).
 * This hook may be called multiple times during a single execve, e.g. for
 * interpreters.  The hook can tell whether it has already been called by
 * checking to see if @bprm->security is non-NULL.if so, then the hook
 * may decide either to retain the security information saved earlier or
 * to replace it.
 * @bprm contains the linux_binprm structure.
 * Return 0 if the hook is successful and permission is granted.
 */
static int provenance_bprm_set_creds(struct linux_binprm *bprm)
{
	struct provenance *nprov = bprm->cred->provenance;
	struct provenance *iprov = file_provenance(bprm->file);
	unsigned long irqflags;
	int rc;

	if (!nprov)
		return -ENOMEM;

	if (provenance_is_opaque(prov_elt(iprov))) {
		set_opaque(prov_elt(nprov));
		return 0;
	}
	spin_lock_irqsave_nested(prov_lock(iprov), irqflags, PROVENANCE_LOCK_INODE);
	rc = uses(RL_EXEC, iprov, nprov, NULL);
	spin_unlock_irqrestore(prov_lock(iprov), irqflags);
	return rc;
}

/*
 *	This hook mediates the point when a search for a binary handler will
 *	begin.  It allows a check the @bprm->security value which is set in the
 *	preceding set_creds call.  The primary difference from set_creds is
 *	that the argv list and envp list are reliably available in @bprm.  This
 *	hook may be called multiple times during a single execve; and in each
 *	pass set_creds is called first.
 *	@bprm contains the linux_binprm structure.
 *	Return 0 if the hook is successful and permission is granted.
 */
static int provenance_bprm_check(struct linux_binprm *bprm)
{
	struct provenance *nprov = bprm->cred->provenance;
	struct provenance *iprov = file_provenance(bprm->file);

	if (!nprov)
		return -ENOMEM;

	if (provenance_is_opaque(prov_elt(iprov))) {
		set_opaque(prov_elt(nprov));
		return 0;
	}
	return prov_record_args(nprov, bprm);
}

/*
 * Prepare to install the new security attributes of a process being
 * transformed by an execve operation, based on the old credentials
 * pointed to by @current->cred and the information set in @bprm->cred by
 * the bprm_set_creds hook.  @bprm points to the linux_binprm structure.
 * This hook is a good place to perform state changes on the process such
 * as closing open file descriptors to which access will no longer be
 * granted when the attributes are changed.  This is called immediately
 * before commit_creds().
 */
static void provenance_bprm_committing_creds(struct linux_binprm *bprm)
{
	struct provenance *cprov  = get_current_provenance();
	struct provenance *nprov = bprm->cred->provenance;
	struct provenance *iprov = file_provenance(bprm->file);
	unsigned long irqflags;

	if (provenance_is_opaque(prov_elt(iprov))) {
		set_opaque(prov_elt(nprov));
		return;
	}
	record_node_name(cprov, bprm->interp);
	spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_TASK);
	spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
	informs(RL_EXEC_PROCESS, cprov, nprov, NULL);
	uses(RL_EXEC, iprov, nprov, NULL);
	spin_unlock(prov_lock(iprov));
	spin_unlock_irqrestore(prov_lock(cprov), irqflags);
}

/*
 * Allocate and attach a security structure to the sb->s_security field.
 * The s_security field is initialized to NULL when the structure is
 * allocated.
 * @sb contains the super_block structure to be modified.
 * Return 0 if operation was successful.
 */
static int provenance_sb_alloc_security(struct super_block *sb)
{
	struct provenance *sbprov  = alloc_provenance(ENT_SBLCK, GFP_KERNEL);

	if (!sbprov)
		return -ENOMEM;
	sb->s_provenance = sbprov;
	return 0;
}

/*
 * Deallocate and clear the sb->s_security field.
 * @sb contains the super_block structure to be modified.
 */
static void provenance_sb_free_security(struct super_block *sb)
{
	if (sb->s_provenance)
		free_provenance(sb->s_provenance);
	sb->s_provenance = NULL;
}

static int provenance_sb_kern_mount(struct super_block *sb,
				    int flags,
				    void *data)
{
	int i;
	uint8_t c = 0;
	struct provenance *sbprov = sb->s_provenance;

	for (i = 0; i < 16; i++) {
		prov_elt(sbprov)->sb_info.uuid[i] = sb->s_uuid.b[i];
		c |= sb->s_uuid.b[i];
	}
	if (c == 0) // no uuid defined, generate random one
		get_random_bytes(prov_elt(sbprov)->sb_info.uuid, 16 * sizeof(uint8_t));
	return 0;
}

static struct security_hook_list provenance_hooks[] __lsm_ro_after_init = {
	/* task related hooks */
	LSM_HOOK_INIT(cred_alloc_blank,	      provenance_cred_alloc_blank),
	LSM_HOOK_INIT(cred_free,	      provenance_cred_free),
	LSM_HOOK_INIT(cred_prepare,	      provenance_cred_prepare),
	LSM_HOOK_INIT(cred_transfer,	      provenance_cred_transfer),
	LSM_HOOK_INIT(task_fix_setuid,	      provenance_task_fix_setuid),

	/* inode related hooks */
	LSM_HOOK_INIT(inode_alloc_security,   provenance_inode_alloc_security),
	LSM_HOOK_INIT(inode_create,	      provenance_inode_create),
	LSM_HOOK_INIT(inode_free_security,    provenance_inode_free_security),
	LSM_HOOK_INIT(inode_permission,	      provenance_inode_permission),
	LSM_HOOK_INIT(inode_link,	      provenance_inode_link),
	LSM_HOOK_INIT(inode_rename,	      provenance_inode_rename),
	LSM_HOOK_INIT(inode_setattr,	      provenance_inode_setattr),
	LSM_HOOK_INIT(inode_getattr,	      provenance_inode_getattr),
	LSM_HOOK_INIT(inode_readlink,	      provenance_inode_readlink),
	LSM_HOOK_INIT(inode_setxattr,	      provenance_inode_setxattr),
	LSM_HOOK_INIT(inode_post_setxattr,    provenance_inode_post_setxattr),
	LSM_HOOK_INIT(inode_getxattr,	      provenance_inode_getxattr),
	LSM_HOOK_INIT(inode_listxattr,	      provenance_inode_listxattr),
	LSM_HOOK_INIT(inode_removexattr,      provenance_inode_removexattr),
	LSM_HOOK_INIT(inode_getsecurity,      provenance_inode_getsecurity),
	LSM_HOOK_INIT(inode_listsecurity,     provenance_inode_listsecurity),

	/* file related hooks */
	LSM_HOOK_INIT(file_permission,	      provenance_file_permission),
	LSM_HOOK_INIT(mmap_file,	      provenance_mmap_file),
	LSM_HOOK_INIT(file_ioctl,	      provenance_file_ioctl),
	LSM_HOOK_INIT(file_open,	      provenance_file_open),

	/* msg related hooks */
	LSM_HOOK_INIT(msg_msg_alloc_security, provenance_msg_msg_alloc_security),
	LSM_HOOK_INIT(msg_msg_free_security,  provenance_msg_msg_free_security),
	LSM_HOOK_INIT(msg_queue_msgsnd,	      provenance_msg_queue_msgsnd),
	LSM_HOOK_INIT(msg_queue_msgrcv,	      provenance_msg_queue_msgrcv),

	/* shared memory related hooks */
	LSM_HOOK_INIT(shm_alloc_security,     provenance_shm_alloc_security),
	LSM_HOOK_INIT(shm_free_security,      provenance_shm_free_security),
	LSM_HOOK_INIT(shm_shmat,	      provenance_shm_shmat),

	/* socket related hooks */
	LSM_HOOK_INIT(sk_alloc_security,      provenance_sk_alloc_security),
	LSM_HOOK_INIT(socket_post_create,     provenance_socket_post_create),
	LSM_HOOK_INIT(socket_bind,	      provenance_socket_bind),
	LSM_HOOK_INIT(socket_connect,	      provenance_socket_connect),
	LSM_HOOK_INIT(socket_listen,	      provenance_socket_listen),
	LSM_HOOK_INIT(socket_accept,	      provenance_socket_accept),
#ifdef CONFIG_SECURITY_FLOW_FRIENDLY
	LSM_HOOK_INIT(socket_sendmsg_always,  provenance_socket_sendmsg_always),
	LSM_HOOK_INIT(socket_recvmsg_always,  provenance_socket_recvmsg_always),
	LSM_HOOK_INIT(mq_timedreceive,	      provenance_mq_timedreceive),
	LSM_HOOK_INIT(mq_timedsend,	      provenance_mq_timedsend),
#else   /* CONFIG_SECURITY_FLOW_FRIENDLY */
	LSM_HOOK_INIT(socket_sendmsg,	      provenance_socket_sendmsg),
	LSM_HOOK_INIT(socket_recvmsg,	      provenance_socket_recvmsg),
#endif  /* CONFIG_SECURITY_FLOW_FRIENDLY */
	LSM_HOOK_INIT(socket_sock_rcv_skb,    provenance_socket_sock_rcv_skb),
	LSM_HOOK_INIT(unix_stream_connect,    provenance_unix_stream_connect),
	LSM_HOOK_INIT(unix_may_send,	      provenance_unix_may_send),

	/* exec related hooks */
	LSM_HOOK_INIT(bprm_check_security,    provenance_bprm_check),
	LSM_HOOK_INIT(bprm_set_creds,	      provenance_bprm_set_creds),
	LSM_HOOK_INIT(bprm_committing_creds,  provenance_bprm_committing_creds),

	/* file system related hooks */
	LSM_HOOK_INIT(sb_alloc_security,      provenance_sb_alloc_security),
	LSM_HOOK_INIT(sb_free_security,	      provenance_sb_free_security),
	LSM_HOOK_INIT(sb_kern_mount,	      provenance_sb_kern_mount)
};

struct kmem_cache *provenance_cache;
struct kmem_cache *long_provenance_cache;

struct prov_boot_buffer         *boot_buffer;
struct prov_long_boot_buffer    *long_boot_buffer;

LIST_HEAD(ingress_ipv4filters);
LIST_HEAD(egress_ipv4filters);
LIST_HEAD(secctx_filters);
LIST_HEAD(user_filters);
LIST_HEAD(group_filters);
LIST_HEAD(ns_filters);
LIST_HEAD(provenance_query_hooks);
LIST_HEAD(relay_list);

struct capture_policy prov_policy;

uint32_t prov_machine_id;
uint32_t prov_boot_id;

void __init provenance_add_hooks(void)
{
	prov_policy.prov_enabled = true;
#ifdef CONFIG_SECURITY_PROVENANCE_WHOLE_SYSTEM
	prov_policy.prov_all = true;
#else
	prov_policy.prov_all = false;
#endif
	prov_machine_id = 1;
	prov_boot_id = 0;
	provenance_cache = kmem_cache_create("provenance_struct",
					     sizeof(struct provenance),
					     0, SLAB_PANIC, NULL);
	long_provenance_cache = kmem_cache_create("long_provenance_struct",
						  sizeof(union long_prov_elt),
						  0, SLAB_PANIC, NULL);
	/* init relay buffers, to deal with provenance before FS is ready */
	boot_buffer = kzalloc(sizeof(struct prov_boot_buffer), GFP_KERNEL);
	if (unlikely(!boot_buffer))
		panic("Provenance: could not allocate boot_buffer.");
	long_boot_buffer = kzalloc(sizeof(struct prov_long_boot_buffer), GFP_KERNEL);
	if (unlikely(!long_boot_buffer))
		panic("Provenance: could not allocate long_boot_buffer.");
#ifdef CONFIG_SECURITY_PROVENANCE_PERSISTENCE
	prov_queue = alloc_workqueue("prov_queue", 0, 0);
	if (!prov_queue)
		pr_err("Provenance: could not initialise work queue.");
#endif
	relay_ready = false;
	cred_init_provenance();
	/* register the provenance security hooks */
	security_add_hooks(provenance_hooks, ARRAY_SIZE(provenance_hooks), "provenance");
	pr_info("Provenance: version %s\n", CAMFLOW_VERSION_STR);
	pr_info("Provenance: hooks ready.\n");
}
