// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2019 University of Cambridge, Harvard University, University of Bristol
 *
 * Author: Thomas Pasquier <thomas.pasquier@bristol.ac.uk>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
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
#include "provenance_record.h"
#include "provenance_net.h"
#include "provenance_inode.h"
#include "provenance_task.h"
#include "provenance_machine.h"
#include "memcpy_ss.h"

#ifdef CONFIG_SECURITY_PROVENANCE_PERSISTENCE
// If provenance is set to be persistant (saved between reboots).
struct save_work {
	struct work_struct work;
	struct dentry *dentry;
};

/*!
 * @brief Helper function for queue_save_provenance function.
 *
 * Calls save_provenance function to persist provenance.
 *
 */
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

static struct workqueue_struct *prov_queue __ro_after_init;

/*!
 * @brief Create workqueue to persist provenance.
 */
static inline void queue_save_provenance(struct provenance *provenance,
					 struct dentry *dentry)
{
	struct save_work *work;

	if (!prov_queue)
		return;
	if (!provenance_is_initialized(prov_elt(provenance))
	    || provenance_is_saved(prov_elt(provenance)))
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

/*!
 * @brief Record provenance when task_alloc is triggered.
 *
 * Record provenance relation RL_PROC_READ (by calling "uses_two" function) and RL_CLONE (by calling "informs" function).
 * We create a ACT_TASK node for the newly allocated task.
 * Since @cred is shared by all threads, we use @cred to save process's provenance,
 * and @task to save provenance of each thread.
 * @param task Task being allocated.
 * @param clone_flags The flags indicating what should be shared.
 * @return 0 if no error occurred. Other error codes unknown.
 *
 */
static int provenance_task_alloc(struct task_struct *task,
				 unsigned long clone_flags)
{
	struct provenance *ntprov = alloc_provenance(ACT_TASK, GFP_KERNEL);
	const struct cred *cred;
	struct task_struct *t = current;
	struct provenance *tprov;
	struct provenance *cprov;

	task->provenance = ntprov;
	if (t != NULL) {
		cred = t->real_cred;
		tprov = t->provenance;
		if (cred != NULL) {
			cprov = cred->provenance;
			if (tprov != NULL &&  cprov != NULL) {
				record_task_name(current, cprov);
				uses_two(RL_PROC_READ, cprov, tprov, NULL, clone_flags);
				informs(RL_CLONE, tprov, ntprov, NULL, clone_flags);
			}
		}
	}
	return 0;
}

/*!
 * @brief Record provenance when task_free hook is triggered.
 *
 * Record provenance relation RL_TERMINATE_TASK by calling function "record_terminate".
 * Free kernel memory allocated for provenance entry of the task in question.
 * Set the provenance pointer in task_struct to NULL.
 * @param task The task in question (i.e., to be free).
 *
 */
static void provenance_task_free(struct task_struct *task)
{
	struct provenance *tprov = task->provenance;

	if (tprov) {
		record_terminate(RL_TERMINATE_TASK, tprov);
		free_provenance(tprov);
	}
	task->provenance = NULL;
}

/*!
 * @brief Initialize the security for the initial task.
 *
 * This is the initial task when provenance capture is initialized.
 * We create a ENT_PROC provenance node, and set the UID and GID of the provenance node information from the current process's credential.
 * Current process's cred struct's provenance pointer now points to the provenance node.
 *
 */
static void task_init_provenance(void)
{
	struct cred *cred = (struct cred *)current->real_cred;
	struct provenance *cprov = alloc_provenance(ENT_PROC, GFP_KERNEL);
	struct provenance *tprov = alloc_provenance(ACT_TASK, GFP_KERNEL);

	if (!cprov || !tprov)
		panic("Provenance:  Failed to initialize initial task.\n");
	node_uid(prov_elt(cprov)) = __kuid_val(cred->euid);
	node_gid(prov_elt(cprov)) = __kgid_val(cred->egid);
	cred->provenance = cprov;

	prov_elt(tprov)->task_info.pid = task_pid_nr(current);
	prov_elt(tprov)->task_info.vpid = task_pid_vnr(current);
	current->provenance = tprov;
}

/*!
 * @brief Record provenance when cred_alloc_blank hook is triggered.
 *
 * This hook is triggered when allocating sufficient memory and attaching to @cred such that cred_transfer() will not get ENOMEM.
 * Therefore, no information flow occurred.
 * We simply create a ENT_PROC provenance node and associate the provenance entry to the newly allocated @cred.
 * Set the proper UID and GID of the node based on the information from @cred.
 * @param cred Points to the new credentials.
 * @param gfp Indicates the atomicity of any memory allocations.
 * @return 0 if no error occurred; -ENOMEM if no memory can be allocated for the new provenance entry. Other error codes unknown.\
 *
 */
static int provenance_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{
	struct provenance *prov = alloc_provenance(ENT_PROC, gfp);

	if (!prov)
		return -ENOMEM;

	node_uid(prov_elt(prov)) = __kuid_val(cred->euid);
	node_gid(prov_elt(prov)) = __kgid_val(cred->egid);
	cred->provenance = prov;
	return 0;
}

/*!
 * @brief Record provenance when cred_free hook is triggered.
 *
 * This hook is triggered when deallocating and clearing the cred->security field in a set of credentials.
 * Record provenance relation RL_TERMINATE_PROC by calling "record_terminate" function.
 * Free kernel memory allocated for provenance entry of the cred in question.
 * Set the provenance pointer in @cred to NULL.
 * @param cred Points to the credentials to be freed.
 *
 */
static void provenance_cred_free(struct cred *cred)
{
	struct provenance *cprov = cred->provenance;

	if (cprov) {
		record_terminate(RL_TERMINATE_PROC, cprov);
		free_provenance(cprov);
	}
	cred->provenance = NULL;
}

/*!
 * @brief Record provenance when cred_prepare hook is triggered.
 *
 * This hook is triggered when preparing a new set of credentials by copying the data from the old set.
 * Record provenance relation RL_CLONE_MEM by calling "generates" function.
 * We create a new ENT_PROC provenance entry for the new cred.
 * Information flows from old cred to the process that is preparing the new cred.
 * @param new Points to the new credentials.
 * @param old Points to the original credentials.
 * @param gfp Indicates the atomicity of any memory allocations.
 * @return 0 if no error occured. Other error codes unknown.
 *
 */
static int provenance_cred_prepare(struct cred *new,
				   const struct cred *old,
				   gfp_t gfp)
{
	struct provenance *old_prov = old->provenance;
	struct provenance *nprov = alloc_provenance(ENT_PROC, gfp);
	struct provenance *tprov;
	unsigned long irqflags;
	int rc = 0;

	if (!nprov)
		return -ENOMEM;
	node_uid(prov_elt(nprov)) = __kuid_val(new->euid);
	node_gid(prov_elt(nprov)) = __kgid_val(new->egid);
	spin_lock_irqsave_nested(prov_lock(old_prov), irqflags, PROVENANCE_LOCK_PROC);
	if (current != NULL) {
		// Here we use current->provenance instead of calling get_task_provenance because at this point pid and vpid are not ready yet.
		// System will crash if attempt to update those values.
		tprov = current->provenance;
		if (tprov != NULL)
			rc = generates(RL_CLONE_MEM, old_prov, tprov, nprov, NULL, 0);
	}
	spin_unlock_irqrestore(prov_lock(old_prov), irqflags);
	record_task_name(current, nprov);
	new->provenance = nprov;
	return rc;
}

/*!
 * @brief Record provenance when cred_transfer hook is triggered.
 *
 * This hook is triggered when transfering data from original creds to new creds.
 * We simply update the new creds provenance entry to that of the old creds.
 * Information flow between cred's is captured when provenance_cred_prepare function is called.
 * @param new Points to the new credentials.
 * @param old Points to the original credentials.
 *
 */
static void provenance_cred_transfer(struct cred *new, const struct cred *old)
{
	const struct provenance *old_prov = old->provenance;
	struct provenance *cprov = new->provenance;

	*cprov =  *old_prov;
}

/*!
 * @brief Record provenance when task_fix_setuid hook is triggered.
 *
 * This hook is triggered when updating the module's state after setting one or more of the user
 * identity attributes of the current process.
 * The @flags parameter indicates which of the set*uid system calls invoked this hook.
 * If @new is the set of credentials that will be installed,
 * modifications should be made to this rather than to @current->cred.
 * Information flows from @old to current process and then eventually flows to @new (since modification should be made to @new instead of @current->cred).
 * Record provenance relation RL_SETUID by calling "generates" function.
 * @param old The set of credentials that are being replaced.
 * @param flags One of the LSM_SETID_* values.
 * @return 0 if no error occurred. Other error codes unknown.
 *
 */
static int provenance_task_fix_setuid(struct cred *new,
				      const struct cred *old,
				      int flags)
{
	struct provenance *old_prov = old->provenance;
	struct provenance *nprov = new->provenance;
	struct provenance *tprov = get_task_provenance(true);
	unsigned long irqflags;
	int rc;

	spin_lock_irqsave_nested(prov_lock(old_prov), irqflags, PROVENANCE_LOCK_PROC);
	rc = generates(RL_SETUID, old_prov, tprov, nprov, NULL, flags);
	spin_unlock_irqrestore(prov_lock(old_prov), irqflags);
	return rc;
}

/*!
 * @brief Record provenance when task_setpgid hook is triggered.
 *
 * This hooks is triggered when checking permission before setting the process group identifier of the process @p to @pgid.
 * @cprov is the cred provenance of the @current process, and @tprov is the task provenance of the @current process.
 * During "get_cred_provenance" and "get_task_provenance" functions, their provenances are updated too.
 * We update process @p's cred provenance's pgid info as required by the trigger of the hook.
 * Record provenance relation RL_SETGID by calling "generates" function.
 * Information flows from cred of the @current process, which sets the @pgid, to the current process, and eventually to the process @p whose @pgid is updated.
 * @param p The task_struct for process being modified.
 * @param pgid The new pgid.
 * @return 0 if permission is granted. Other error codes unknown.
 *
 */
static int provenance_task_setpgid(struct task_struct *p, pid_t pgid)
{
	struct provenance *cprov = get_cred_provenance();
	struct provenance *tprov = get_task_provenance(true);
	const struct cred *cred = get_task_cred(p);
	struct provenance *nprov = cred->provenance;
	int rc;

	prov_elt(nprov)->proc_info.gid = pgid;
	rc = generates(RL_SETGID, cprov, tprov, nprov, NULL, 0);
	put_cred(cred); // Release cred.
	return rc;
}

static int provenance_task_getpgid(struct task_struct *p)
{
	struct provenance *cprov = get_cred_provenance();
	struct provenance *tprov = get_task_provenance(true);
	const struct cred *cred = get_task_cred(p);
	struct provenance *nprov = cred->provenance;
	int rc;

	rc = uses(RL_GETGID, nprov, tprov, cprov, NULL, 0);
	put_cred(cred); // Release cred.
	return rc;
}

/*!
 * @brief Record provenance when task_kill hook is triggered.
 *
 * This hook is triggered when checking permission before sending signal @sig to @p.
 * @info can be NULL, the constant 1, or a pointer to a siginfo structure.
 * If @info is 1 or SI_FROMKERNEL(info) is true, then the signal should be viewed as coming from the kernel and should typically be permitted.
 * SIGIO signals are handled separately by the send_sigiotask hook in file_security_ops.
 * No information flow happens in this case. Simply return 0.
 * @param p The task_struct for process.
 * @param info The signal information.
 * @param sig The signal value.
 * @param secid The sid of the process where the signal originated.
 * @return 0 if permission is granted.
 *
 */
static int provenance_task_kill(struct task_struct *p, struct kernel_siginfo *info,
				int sig, const struct cred *cred)
{
	return 0;
}

/*!
 * @brief Record provenance when inode_alloc_security hook is triggered.
 *
 * This hook is triggered when allocating and attaching a security structure to @inode->i_security.
 * The i_security field is initialized to NULL when the inode structure is allocated.
 * When i_security field is initialized, we also initialize i_provenance field of the inode.
 * Therefore, we create a new ENT_INODE_UNKNOWN provenance entry.
 * UUID information from @i_sb (superblock) is copied to the new inode's provenance entry.
 * We then call function "refresh_inode_provenance" to obtain more information about the inode.
 * No information flow occurs.
 * @param inode The inode structure.
 * @return 0 if operation was successful; -ENOMEM if no memory can be allocated for the new inode provenance entry. Other error codes unknown.
 *
 */
static int provenance_inode_alloc_security(struct inode *inode)
{
	struct provenance *iprov = alloc_provenance(ENT_INODE_UNKNOWN, GFP_KERNEL);
	struct provenance *sprov;

	if (unlikely(!iprov))
		return -ENOMEM;
	sprov = inode->i_sb->s_provenance;
	__memcpy_ss(prov_elt(iprov)->inode_info.sb_uuid, PROV_SBUUID_LEN, prov_elt(sprov)->sb_info.uuid, 16 * sizeof(uint8_t));
	inode->i_provenance = iprov;
	refresh_inode_provenance(inode, iprov);
	return 0;
}

/*!
 * @brief Record provenance when inode_free_security hook is triggered.
 *
 * This hook is triggered when deallocating the inode security structure and set @inode->i_security to NULL.
 * Record provenance relation RL_FREED by calling "record_terminate" function.
 * Free kernel memory allocated for provenance entry of the inode in question.
 * Set the provenance pointer in @inode to NULL.
 * @param inode The inode structure whose security is to be freed.
 *
 */
static void provenance_inode_free_security(struct inode *inode)
{
	struct provenance *iprov = inode->i_provenance;

	if (iprov) {
		record_terminate(RL_FREED, iprov);
		free_provenance(iprov);
	}
	inode->i_provenance = NULL;
}

/*!
 * @brief Record provenance when inode_create hook is triggered.
 *
 * This hook is trigger when checking permission to create a regular file.
 * Record provenance relation RL_INODE_CREATE by calling "generates" function.
 * Information flows from current process's cred's to the process, and eventually to the parent's inode.
 * @param dir Inode structure of the parent of the new file.
 * @param dentry The dentry structure for the file to be created.
 * @param mode The file mode of the file to be created.
 * @return 0 if permission is granted; -ENOMEM if parent's inode's provenance entry is NULL. Other error codes unknown.
 *
 */
static int provenance_inode_create(struct inode *dir,
				   struct dentry *dentry,
				   umode_t mode)
{
	struct provenance *cprov = get_cred_provenance();
	struct provenance *tprov = get_task_provenance(true);
	struct provenance *iprov = get_inode_provenance(dir, true);
	unsigned long irqflags;
	int rc;

	if (!iprov)
		return -ENOMEM;
	spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
	spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_DIR);
	rc = generates(RL_INODE_CREATE, cprov, tprov, iprov, NULL, mode);
	spin_unlock(prov_lock(iprov));
	spin_unlock_irqrestore(prov_lock(cprov), irqflags);
	return rc;
}

/*!
 * @brief Record provenance when inode_permission hook is triggered.
 *
 * This hook is triggered when checking permission before accessing an inode.
 * This hook is called by the existing Linux permission function,
 * so a security module can use it to provide additional checking for existing Linux permission checks.
 * Notice that this hook is called when a file is opened (as well as many other operations),
 * whereas the file_security_ops permission hook is called when the actual read/write operations are performed.
 * Depending on the permission specified in @mask,
 * Zero or more relation may be recorded during this permission check.
 * If permission is:
 * 1. MAY_EXEC: record provenance relation RL_PERM_EXEC by calling "uses" function, and
 * 2. MAY_READ: record provenance relation MAY_READ by calling "uses" function, and
 * 3. MAY_APPEND: record provenance relation RL_PERM_APPEND by calling "uses" function, and
 * 4. MAY_WRITE: record provenance relation RL_PERM_WRITE by calling "uses" function.
 * Note that "uses" function also generates provenance relation RL_PROC_WRITE.
 * Information flows from @inode's provenance to the current process that attempts to access the inode, and eventually to the cred of the task.
 * Provenance relation is not recorded if the inode to be access is private or if the inode's provenance entry does not exist.
 * @param inode The inode structure to check.
 * @param mask The permission mask.
 * @return 0 if permission is granted; -ENOMEM if @inode's provenance does not exist. Other error codes unknown.
 *
 * @todo We ignore inode that are PRIVATE (i.e., IS_PRIVATE is true). Private inodes are FS internals and we ignore for now.
 *
 */
static int provenance_inode_permission(struct inode *inode, int mask)
{
	struct provenance *cprov = NULL;
	struct provenance *tprov = NULL;
	struct provenance *iprov = NULL;
	unsigned long irqflags;
	int rc = 0;

	if (!mask)
		return 0;
	if (unlikely(IS_PRIVATE(inode)))
		return 0;
	cprov = get_cred_provenance();
	tprov = get_task_provenance(true);
	iprov = get_inode_provenance(inode, false);
	if (!iprov)
		return -ENOMEM;

	spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
	spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
	if (mask & MAY_EXEC) {
		rc = uses(RL_PERM_EXEC, iprov, tprov, cprov, NULL, mask);
		if (rc < 0)
			goto out;
	}
	if (mask & MAY_READ) {
		rc = uses(RL_PERM_READ, iprov, tprov, cprov, NULL, mask);
		if (rc < 0)
			goto out;
	}
	if (mask & MAY_APPEND) {
		rc = uses(RL_PERM_APPEND, iprov, tprov, cprov, NULL, mask);
		if (rc < 0)
			goto out;
	}
	if (mask & MAY_WRITE) {
		rc = uses(RL_PERM_WRITE, iprov, tprov, cprov, NULL, mask);
		if (rc < 0)
			goto out;
	}
out:
	spin_unlock(prov_lock(iprov));
	spin_unlock_irqrestore(prov_lock(cprov), irqflags);
	return rc;
}

/*!
 * @brief Record provenance when inode_link hook is triggered.
 *
 * This hook is triggered when checking permission before creating a new hard link to a file.
 * We obtain the provenance of current process and its cred, as well as provenance of inode or parent directory of new link.
 * We also get the provenance of existing link to the file.
 * Record two provenance relations RL_LINK by calling "generates" function.
 * Information flows:
 * 1. From cred of the current process to the process, and eventually to the inode of parent directory of new link, and,
 * 2. From cred of the current process to the process, and eventually to the dentry of the existing link to the file, and
 * 3. From the inode of parent directory of new link to the dentry of the existing link to the file.
 * @param old_dentry The dentry structure for an existing link to the file.
 * @parm dir The inode structure of the parent directory of the new link.
 * @param new_dentry The dentry structure for the new link.
 * @return 0 if permission is granted; -ENOMEM if either the dentry provenance of the existing link to the file or the inode provenance of the new parent directory of new link does not exist.
 *
 * @todo The information flow relations captured here is a bit weird. We need to double check the correctness.
 */

static int provenance_inode_link(struct dentry *old_dentry,
				 struct inode *dir,
				 struct dentry *new_dentry)
{
	struct provenance *cprov = get_cred_provenance();
	struct provenance *tprov = get_task_provenance(true);
	struct provenance *iprov = NULL;
	unsigned long irqflags;
	int rc;

	iprov = get_dentry_provenance(old_dentry, true);
	if (!iprov)
		return -ENOMEM;

	spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
	spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
	rc = generates(RL_LINK, cprov, tprov, iprov, NULL, 0);
	spin_unlock(prov_lock(iprov));
	spin_unlock_irqrestore(prov_lock(cprov), irqflags);
	record_inode_name_from_dentry(new_dentry, iprov, true);
	return rc;
}

/*
 *	Check the permission to remove a hard link to a file.
 *	@dir contains the inode structure of parent directory of the file.
 *	@dentry contains the dentry structure for file to be unlinked.
 *	Return 0 if permission is granted.
 */
static int provenance_inode_unlink(struct inode *dir, struct dentry *dentry)
{
	struct provenance *cprov = get_cred_provenance();
	struct provenance *tprov = get_task_provenance(true);
	struct provenance *iprov = NULL;
	unsigned long irqflags;
	int rc;

	iprov = get_dentry_provenance(dentry, true);
	if (!iprov)
		return -ENOMEM;

	spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
	spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
	rc = generates(RL_UNLINK, cprov, tprov, iprov, NULL, 0);
	spin_unlock(prov_lock(iprov));
	spin_unlock_irqrestore(prov_lock(cprov), irqflags);
	return rc;
}

/*
 * @inode_symlink:
 *	Check the permission to create a symbolic link to a file.
 *	@dir contains the inode structure of parent directory of the symbolic link.
 *	@dentry contains the dentry structure of the symbolic link.
 *	@old_name contains the pathname of file.
 *	Return 0 if permission is granted.
 */
static int provenance_inode_symlink(struct inode *dir,
				    struct dentry *dentry,
				    const char *name)
{
	struct provenance *cprov = get_cred_provenance();
	struct provenance *tprov = get_task_provenance(true);
	struct provenance *iprov = NULL;
	unsigned long irqflags;
	int rc;

	iprov = get_dentry_provenance(dentry, true);
	if (!iprov)
		return 0;  // do not touch!

	spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
	spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
	rc = generates(RL_SYMLINK, cprov, tprov, iprov, NULL, 0);
	spin_unlock(prov_lock(iprov));
	spin_unlock_irqrestore(prov_lock(cprov), irqflags);
	record_node_name(iprov, name, true);
	return rc;
}

/*!
 * @brief Record provenance when inode_rename hook is triggered.
 *
 * This hook is triggered when checking for permission to rename a file or directory.
 * Information flow is the same as in the "provenance_inode_link" function so we call this function.
 * @param old_dir The inode structure for parent of the old link.
 * @param old_dentry The dentry structure of the old link.
 * @param new_dir The inode structure for parent of the new link.
 * @param new_dentry The dentry structure of the new link.
 * @return Error code is the same as in "provenance_inode_link" function.
 *
 */
static int provenance_inode_rename(struct inode *old_dir,
				   struct dentry *old_dentry,
				   struct inode *new_dir,
				   struct dentry *new_dentry)
{
	struct provenance *cprov = get_cred_provenance();
	struct provenance *tprov = get_task_provenance(true);
	struct provenance *iprov = NULL;
	unsigned long irqflags;
	int rc;

	iprov = get_dentry_provenance(old_dentry, true);
	if (!iprov)
		return -ENOMEM;

	spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
	spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
	rc = generates(RL_RENAME, cprov, tprov, iprov, NULL, 0);
	clear_name_recorded(prov_elt(iprov));
	spin_unlock(prov_lock(iprov));
	spin_unlock_irqrestore(prov_lock(cprov), irqflags);
	record_inode_name_from_dentry(new_dentry, iprov, true);
	return rc;
}

/*!
 * @brief Record provenance when inode_setattr hook is triggered.
 *
 * This hooks is triggered when checking permission before setting file attributes.
 * Note that the kernel call to notify_change is performed from several locations,
 * whenever file attributes change (such as when a file is truncated, chown/chmod operations
 * transferring disk quotas, etc).
 * We create a new provenance node ENT_IATTR, and update its information based on @iattr.
 * Record provenance relation RL_SETATTR by calling "generates" function.
 * Record provenance relation RL_SETATTR_INODE by calling "derives" function.
 * Information flows from cred of the current process to the process, and eventually to the inode attribute to set the attributes.
 * Information also flows from inode attribute to the inode whose attributes are to be set.
 * After relation is recorded, iattr provenance entry is freed (i.e., memory deallocated).
 * We also persistant the inode's provenance.
 * @param dentry The dentry structure for the file.
 * @param attr The iattr structure containing the new file attributes.
 * @return 0 if permission is granted; -ENOMEM if inode provenance of the file is NULL; -ENOMEM if no memory can be allocated for a new ENT_IATTR provenance entry. Other error codes unknown.
 *
 */
static int provenance_inode_setattr(struct dentry *dentry, struct iattr *iattr)
{
	struct provenance *cprov = get_cred_provenance();
	struct provenance *tprov = get_task_provenance(true);
	struct provenance *iprov;
	struct provenance *iattrprov;
	unsigned long irqflags;
	int rc;

	iprov = get_dentry_provenance(dentry, true);
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

	spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
	spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
	rc = generates(RL_SETATTR, cprov, tprov, iattrprov, NULL, 0);
	if (rc < 0)
		goto out;
	rc = derives(RL_SETATTR_INODE, iattrprov, iprov, NULL, 0);
out:
	queue_save_provenance(iprov, dentry);
	spin_unlock(prov_lock(iprov));
	spin_unlock_irqrestore(prov_lock(cprov), irqflags);
	free_provenance(iattrprov);
	return rc;
}

/*!
 * @brief Record provenance when inode_getattr hook is triggered.
 *
 * This hook is triggered when checking permission before obtaining file attributes.
 * Record provenance relation RL_GETATTR by calling "uses" function.
 * Information flows from the inode of the file to the calling process, and eventually to the process's cred.
 * @param path The path structure for the file.
 * @return 0 if permission is granted; -ENOMEM if the provenance entry of the file is NULL. Other error codes unknown.
 *
 */
static int provenance_inode_getattr(const struct path *path)
{
	struct provenance *cprov = get_cred_provenance();
	struct provenance *tprov = get_task_provenance(true);
	struct provenance *iprov = get_dentry_provenance(path->dentry, true);
	unsigned long irqflags;
	int rc;

	if (!iprov)
		return -ENOMEM;

	spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
	spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
	rc = uses(RL_GETATTR, iprov, tprov, cprov, NULL, 0);
	spin_unlock(prov_lock(iprov));
	spin_unlock_irqrestore(prov_lock(cprov), irqflags);
	return rc;
}

/*!
 * @brief Record provenance when inode_readlink hook is triggered.
 *
 * This hook is triggered when checking the permission to read the symbolic link.
 * Record provenance relation RL_READ_LINK by calling "uses" function.
 * Information flows from the link file to the calling process, and eventually to its cred.
 * @param dentry The dentry structure for the file link.
 * @return 0 if permission is granted; -ENOMEM if the link file's provenance entry is NULL. Other error codes unknown.
 *
 */
static int provenance_inode_readlink(struct dentry *dentry)
{
	struct provenance *cprov = get_cred_provenance();
	struct provenance *tprov = get_task_provenance(true);
	struct provenance *iprov = get_dentry_provenance(dentry, true);
	unsigned long irqflags;
	int rc;

	if (!iprov)
		return -ENOMEM;

	spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
	spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
	rc = uses(RL_READ_LINK, iprov, tprov, cprov, NULL, 0);
	spin_unlock(prov_lock(iprov));
	spin_unlock_irqrestore(prov_lock(cprov), irqflags);
	return rc;
}

/*!
 * @brief Setting provenance extended attribute for an inode.

 * The provenance extended attributes are set for an inode only if the @name of xattr is matched to be XATTR_NAME_PROVENANCE.
 * @param dentry The dentry struct whose inode's provenance xattr is to be set.
 * @param name Must be XATTR_NAME_PROVENANCE to set the xattr.
 * @param value Setting of the provenance xattr.
 * @param size Must be the size of provenance entry.
 * @param flags The operational flags.
 * @return 0 if no error occurred; -ENOMEM if size does not match. Other error codes unknown.
 *
 */
static int provenance_inode_setxattr(struct dentry *dentry,
				     const char *name,
				     const void *value,
				     size_t size,
				     int flags)
{
	struct provenance *prov;
	union prov_elt *setting;

	if (strcmp(name, XATTR_NAME_PROVENANCE) == 0) { // Provenance xattr
		if (size != sizeof(union prov_elt))
			return -ENOMEM;
		prov = get_dentry_provenance(dentry, false);
		setting = (union prov_elt *)value;

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

/*!
 * @brief Record provenance when inode_post_setxattr hook is triggered.
 *
 * This hook is triggered when updating inode security field after successful setxattr operation.
 * The relations are recorded through "record_write_xattr" function defined in provenance_inode.h file.
 * RL_SETXATTR is one of the relations to be recorded.
 * The relations may not be recorded for the following reasons:
 * 1. The name of the extended attribute is provenance (do not capture provenance of CamFlow provenance ops), or
 * 2. inode provenance entry is NULL.
 * @param dentry The dentry structure for the file.
 * @param name The name of the extended attribute.
 * @param value The value of that attribute.
 * @param size The size of the value.
 * @param flags The operational flags.
 *
 */
static void provenance_inode_post_setxattr(struct dentry *dentry,
					   const char *name,
					   const void *value,
					   size_t size,
					   int flags)
{
	struct provenance *cprov = get_cred_provenance();
	struct provenance *tprov = get_task_provenance(true);
	struct provenance *iprov = get_dentry_provenance(dentry, true);
	unsigned long irqflags;

	if (strcmp(name, XATTR_NAME_PROVENANCE) == 0)
		return;

	if (!iprov)
		return;
	spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
	spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
	record_write_xattr(RL_SETXATTR, iprov, tprov, cprov, name, value, size, flags);
	queue_save_provenance(iprov, dentry);
	spin_unlock(prov_lock(iprov));
	spin_unlock_irqrestore(prov_lock(cprov), irqflags);
}

/*!
 * @brief Record provenance when inode_getxattr hook is triggered.
 *
 * This hook is triggered when checking permission before obtaining the extended attributes.
 * The relations are recorded through "record_read_xattr" function defined in provenance_inode.h file.
 * The relations may not be recorded for the following reasons:
 * 1. The name of the extended attribute is provenance (do not capture provenance of CamFlow provenance ops), or
 * 2. inode provenance entry is NULL.
 * @param dentry The dentry structure for the file.
 * @param name The name of the extended attribute.
 * @return 0 if no error occurred; -ENOMEM if inode provenance is NULL; Other error codes inherited from "record_read_xattr" function or unknown.
 *
 */
static int provenance_inode_getxattr(struct dentry *dentry, const char *name)
{
	struct provenance *cprov = get_cred_provenance();
	struct provenance *tprov = get_task_provenance(true);
	struct provenance *iprov = get_dentry_provenance(dentry, true);
	int rc = 0;
	unsigned long irqflags;

	if (strcmp(name, XATTR_NAME_PROVENANCE) == 0)
		return 0;

	if (!iprov)
		return -ENOMEM;
	spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
	spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
	rc = record_read_xattr(cprov, tprov, iprov, name);
	spin_unlock(prov_lock(iprov));
	spin_unlock_irqrestore(prov_lock(cprov), irqflags);
	return rc;
}

/*!
 * @brief Record provenance when inode_listxattr hook is triggered.
 *
 * This hook is triggered when checking permission before obtaining the list of extended attribute names for @dentry.
 * Record provenance relation RL_LSTXATTR by calling "uses" function.
 * Information flows from inode (whose xattrs are of interests) to calling task process, and eventually to its cred.
 * The relation may not be recorded if inode provenance entry is NULL.
 * @param dentry The dentry structure for the file.
 * @return 0 if no error occurred; -ENOMEM if inode provenance is NULL; Other error codes inherited from "uses" function or unknown.
 *
 */
static int provenance_inode_listxattr(struct dentry *dentry)
{
	struct provenance *cprov = get_cred_provenance();
	struct provenance *tprov = get_task_provenance(true);
	struct provenance *iprov = get_dentry_provenance(dentry, true);
	unsigned long irqflags;
	int rc = 0;

	if (!iprov)
		return -ENOMEM;
	spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
	spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
	rc = uses(RL_LSTXATTR, iprov, tprov, cprov, NULL, 0);
	spin_unlock(prov_lock(iprov));
	spin_unlock_irqrestore(prov_lock(cprov), irqflags);
	return rc;
}

/*!
 * @brief Record provenance when inode_removexattr hook is triggered.
 *
 * This hook is triggered when checking permission before removing the extended attribute identified by @name for @dentry.
 * The relations are recorded through "record_write_xattr" function defined in provenance_inode.h file.
 * RL_RMVXATTR is one of the relations to be recorded.
 * The relations may not be recorded for the following reasons:
 * 1. The name of the extended attribute is provenance (do not capture provenance of CamFlow provenance ops), or
 * 2. inode provenance entry is NULL.
 * @param dentry The dentry structure for the file.
 * @param name The name of the extended attribute.
 *
 */
static int provenance_inode_removexattr(struct dentry *dentry, const char *name)
{
	struct provenance *cprov = get_cred_provenance();
	struct provenance *tprov = get_task_provenance(true);
	struct provenance *iprov = get_dentry_provenance(dentry, true);
	unsigned long irqflags;
	int rc = 0;

	if (strcmp(name, XATTR_NAME_PROVENANCE) == 0)
		return -EPERM;

	if (!iprov)
		return -ENOMEM;

	spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
	spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
	rc = record_write_xattr(RL_RMVXATTR, iprov, tprov, cprov, name, NULL, 0, 0);
	queue_save_provenance(iprov, dentry);
	spin_unlock(prov_lock(iprov));
	spin_unlock_irqrestore(prov_lock(cprov), irqflags);
	return rc;
}

/*!
 * @brief Enabling checking provenance of an inode from user space.
 *
 * This hook allows us to retrieve a copy of the extended attribute representation of the security label
 * associated with @name for @inode via @buffer.
 * Note that @name is the remainder of the attribute name after the security prefix has been removed.
 * The provenance of the inode, if exists, is stored in @buffer.
 * @param inode The inode whose provenance is to be retrieved.
 * @param name The name of extended attribute, which must be provenance (or an error will be thrown).
 * @param buffer The buffer to hold the provenance of the inode.
 * @param alloc Specify if the call should return a value via the buffer or just the value length.
 * @return Size of the buffer on success, which in this case is the size of the provenance entry; -ENOMEM if inode provenance is NULL; -EOPNOTSUPP if name of the attribute is not provenance.
 *
 */
static int provenance_inode_getsecurity(struct inode *inode,
					const char *name,
					void **buffer,
					bool alloc)
{
	struct provenance *iprov = get_inode_provenance(inode, false);

	if (unlikely(!iprov))
		return -ENOMEM;
	if (strcmp(name, XATTR_PROVENANCE_SUFFIX))
		return -EOPNOTSUPP;
	if (!alloc)
		goto out;
	*buffer = kmalloc(sizeof(union prov_elt), GFP_KERNEL);
	__memcpy_ss(*buffer, sizeof(union prov_elt), prov_elt(iprov), sizeof(union prov_elt));
out:
	return sizeof(union prov_elt);
}

/*!
 * @brief Copy the name of the provenance extended attribute to buffer.
 *
 * This function copies the extended attribute of provenance associated with @inode into @buffer.
 * The maximum size of @buffer is specified by @buffer_size.
 * @buffer may be NULL to request the size of the buffer required.
 * If @buffer is not NULL and the length of the provenance attribute name is smaller than @buffer_size,
 * then the buffer will contain the name of the provenance attribute.
 * @param inode The inode whose provenance extended attribute is to be retrieved.
 * @param buffer The buffer that holds that attribute name.
 * @param buffer_size The maximum size of the buffer.
 * @returns Number of bytes used/required on success.
 *
 */
static int provenance_inode_listsecurity(struct inode *inode,
					 char *buffer,
					 size_t buffer_size)
{
	const int len = sizeof(XATTR_NAME_PROVENANCE);

	if (buffer && len <= buffer_size)
		__memcpy_ss(buffer, buffer_size, XATTR_NAME_PROVENANCE, len);
	return len;
}

/*!
 * @brief Record provenance when file_permission hook is triggered.
 *
 * This hook is triggered when checking file permissions before accessing an open file.
 * This hook is called by various operations that read or write files.
 * A security module can use this hook to perform additional checking on these operations,
 * e.g., to revalidate permissions on use to support privilege bracketing or policy changes.
 * Notice that this hook is used when the actual read/write operations are performed,
 * whereas the inode_security_ops hook is called when a file is opened (as well as many other operations).
 * Caveat:
 * Although this hook can be used to revalidate permissions for various system call operations that read or write files,
 * it does not address the revalidation of permissions for memory-mapped files.
 * Security modules must handle this separately if they need such revalidation.
 * Depending on the type of the @file (e.g., a regular file or a directory),
 * and the requested permission from @mask,
 * record various provenance relations, including:
 * RL_WRITE, RL_READ, RL_SEARCH, RL_SND, RL_RCV, RL_EXEC.
 * @param file The file structure being accessed.
 * @param mask The requested permissions.
 * @return 0 if permission is granted; -ENOMEM if inode provenance is NULL. Other error codes unknown.
 *
 */
static int provenance_file_permission(struct file *file, int mask)
{
	struct provenance *cprov = get_cred_provenance();
	struct provenance *tprov = get_task_provenance(true);
	struct provenance *iprov = get_file_provenance(file, true);
	struct inode *inode = file_inode(file);
	uint32_t perms;
	unsigned long irqflags;
	int rc = 0;

	if (!iprov)
		return -ENOMEM;
	perms = file_mask_to_perms(inode->i_mode, mask);
	spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
	spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
	if (is_inode_dir(inode)) {
		if ((perms & (DIR__WRITE)) != 0) {
			rc = generates(RL_WRITE, cprov, tprov, iprov, file, mask);
			if (rc < 0)
				goto out;
		}
		if ((perms & (DIR__READ)) != 0) {
			rc = uses(RL_READ, iprov, tprov, cprov, file, mask);
			if (rc < 0)
				goto out;
		}
		if ((perms & (DIR__SEARCH)) != 0) {
			rc = uses(RL_SEARCH, iprov, tprov, cprov, file, mask);
			if (rc < 0)
				goto out;
		}
	} else if (is_inode_socket(inode)) {
		if ((perms & (FILE__WRITE | FILE__APPEND)) != 0) {
			rc = generates(RL_SND, cprov, tprov, iprov, file, mask);
			if (rc < 0)
				goto out;
		}
		if ((perms & (FILE__READ)) != 0) {
			rc = uses(RL_RCV, iprov, tprov, cprov, file, mask);
			if (rc < 0)
				goto out;
		}
	} else {
		if ((perms & (FILE__WRITE | FILE__APPEND)) != 0) {
			rc = generates(RL_WRITE, cprov, tprov, iprov, file, mask);
			if (rc < 0)
				goto out;
		}
		if ((perms & (FILE__READ)) != 0) {
			rc = uses(RL_READ, iprov, tprov, cprov, file, mask);
			if (rc < 0)
				goto out;
		}
		if ((perms & (FILE__EXECUTE)) != 0) {
			if (provenance_is_opaque(prov_elt(iprov)))
				set_opaque(prov_elt(cprov));
			else
				rc = derives(RL_EXEC, iprov, cprov, file, mask);
		}
	}
out:
	queue_save_provenance(iprov, file_dentry(file));
	spin_unlock(prov_lock(iprov));
	spin_unlock_irqrestore(prov_lock(cprov), irqflags);
	return rc;
}

#ifdef CONFIG_SECURITY_FLOW_FRIENDLY
/*!
 * @brief Record provenance when file_splice_pipe_to_pipe hook is triggered (splice system call).
 *
 * Record provenance relation RL_SPLICE by calling "derives" function.
 * Information flows from one pipe @in to another pipe @out.
 * Fail if either file inode provenance does not exist.
 * @param in Information source file.
 * @param out Information drain file.
 * @return 0 if no error occurred; -ENOMEM if either end of the file provenance entry is NULL; Other error code inherited from derives function or unknown.
 *
 */
static int provenance_file_splice_pipe_to_pipe(struct file *in, struct file *out)
{
	struct provenance *cprov = get_cred_provenance();
	struct provenance *tprov = get_task_provenance(true);
	struct provenance *inprov = get_file_provenance(in, true);
	struct provenance *outprov = get_file_provenance(out, true);
	unsigned long irqflags;
	int rc = 0;

	if (!inprov || !outprov)
		return -ENOMEM;

	spin_lock_irqsave_nested(prov_lock(inprov), irqflags, PROVENANCE_LOCK_INODE);
	spin_lock_nested(prov_lock(outprov), PROVENANCE_LOCK_INODE);
	rc = uses(RL_SPLICE_IN, inprov, tprov, cprov, NULL, 0);
	if (rc < 0)
		goto out;
	rc = generates(RL_SPLICE_OUT, cprov, tprov, outprov, NULL, 0);
out:
	spin_unlock(prov_lock(outprov));
	spin_unlock_irqrestore(prov_lock(inprov), irqflags);
	return rc;
}
#endif

static int provenance_kernel_read_file(struct file *file
				       , enum kernel_read_file_id id)
{
	struct provenance *tprov = get_task_provenance(true);
	struct provenance *iprov = get_file_provenance(file, true);
	unsigned long irqflags;
	int rc = 0;

	if (!iprov)   // not sure it could happen, ignore it for now
		return 0;

	spin_lock_irqsave_nested(prov_lock(iprov), irqflags, PROVENANCE_LOCK_INODE);
	switch (id) {
	case READING_UNKNOWN:
		rc = record_influences_kernel(RL_LOAD_UNKNOWN, iprov, tprov, file);
		break;
	case READING_FIRMWARE:
		rc = record_influences_kernel(RL_LOAD_FIRMWARE, iprov, tprov, file);
		break;
	case READING_FIRMWARE_PREALLOC_BUFFER:
		rc = record_influences_kernel(RL_LOAD_FIRMWARE_PREALLOC_BUFFER, iprov, tprov, file);
		break;
	case READING_MODULE:
		rc = record_influences_kernel(RL_LOAD_MODULE, iprov, tprov, file);
		break;
	case READING_KEXEC_IMAGE:
		rc = record_influences_kernel(RL_LOAD_KEXEC_IMAGE, iprov, tprov, file);
		break;
	case READING_KEXEC_INITRAMFS:
		rc = record_influences_kernel(RL_LOAD_KEXEC_INITRAMFS, iprov, tprov, file);
		break;
	case READING_POLICY:
		rc = record_influences_kernel(RL_LOAD_POLICY, iprov, tprov, file);
		break;
	case READING_X509_CERTIFICATE:
		rc = record_influences_kernel(RL_LOAD_CERTIFICATE, iprov, tprov, file);
		break;
	default: // should not happen
		rc = record_influences_kernel(RL_LOAD_UNDEFINED, iprov, tprov, file);
		break;
	}
	spin_unlock_irqrestore(prov_lock(iprov), irqflags);
	return rc;
}

/*!
 * @brief Record provenance when file_open hook is triggered.
 *
 * This hook is triggered when saving open-time permission checking state for later use upon file_permission,
 * and rechecking access if anything has changed since inode_permission.
 * Record provenance relation RL_OPEN by calling "uses" function.
 * Information flows from inode of the file to be opened to the calling process, and eventually to its cred.
 * @param file The file to be opened.
 * @param cred Unused parameter.
 * @return 0 if no error occurred; -ENOMEM if the file inode provenance entry is NULL; Other error code inherited from uses function or unknown.
 *
 */
static int provenance_file_open(struct file *file)
{
	struct provenance *cprov = get_cred_provenance();
	struct provenance *tprov = get_task_provenance(true);
	struct provenance *iprov = get_file_provenance(file, true);
	unsigned long irqflags;
	int rc = 0;

	if (!iprov)
		return -ENOMEM;
	spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
	spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
	rc = uses(RL_OPEN, iprov, tprov, cprov, file, 0);
	spin_unlock(prov_lock(iprov));
	spin_unlock_irqrestore(prov_lock(cprov), irqflags);
	return rc;
}

/*!
 * @brief Record provenance when file_receive hook is triggered.
 *
 * This hook allows security modules to control the ability of a process to receive an open file descriptor via socket IPC.
 * Record provenance relation RL_FILE_RCV by calling "uses" function.
 * Information flows from inode of the file being received to the calling process, and eventually to its cred.
 * @param file The file structure being received.
 * @return 0 if permission is granted, no error occurred; -ENOMEM if the file inode provenance entry is NULL; Other error code inherited from uses function or unknown.
 *
 */
static int provenance_file_receive(struct file *file)
{
	struct provenance *cprov = get_cred_provenance();
	struct provenance *tprov = get_task_provenance(true);
	struct provenance *iprov = get_file_provenance(file, true);
	unsigned long irqflags;
	int rc = 0;

	if (!iprov)
		return -ENOMEM;
	spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
	spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
	rc = uses(RL_FILE_RCV, iprov, tprov, cprov, file, 0);
	spin_unlock(prov_lock(iprov));
	spin_unlock_irqrestore(prov_lock(cprov), irqflags);
	return rc;
}

/*
 *	Check permission before performing file locking operations.
 *	Note: this hook mediates both flock and fcntl style locks.
 *	@file contains the file structure.
 *	@cmd contains the posix-translated lock operation to perform
 *	(e.g. F_RDLCK, F_WRLCK).
 *	Return 0 if permission is granted.
 */
static int provenance_file_lock(struct file *file, unsigned int cmd)
{
	struct provenance *cprov = get_cred_provenance();
	struct provenance *tprov = get_task_provenance(true);
	struct provenance *iprov = get_file_provenance(file, false);
	unsigned long irqflags;
	int rc = 0;

	if (!iprov)
		return -ENOMEM;
	spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
	spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
	rc = generates(RL_FILE_LOCK, cprov, tprov, iprov, file, cmd);
	spin_unlock(prov_lock(iprov));
	spin_unlock_irqrestore(prov_lock(cprov), irqflags);
	return rc;
}

/*
 *	process @tsk.  Note that this hook is sometimes called from interrupt.
 *	Note that the fown_struct, @fown, is never outside the context of a
 *	struct file, so the file structure (and associated security information)
 *	can always be obtained:
 *		container_of(fown, struct file, f_owner)
 *	@tsk contains the structure of task receiving signal.
 *	@fown contains the file owner information.
 *	@sig is the signal that will be sent.  When 0, kernel sends SIGIO.
 *	Return 0 if permission is granted.
 */
static int provenance_file_send_sigiotask(struct task_struct *task,
					  struct fown_struct *fown, int signum)
{
	struct file *file = container_of(fown, struct file, f_owner);
	struct provenance *iprov = get_file_provenance(file, false);
	struct provenance *tprov = task->provenance;
	struct provenance *cprov = task_cred_xxx(task, provenance);
	unsigned long irqflags;
	int rc = 0;

	if (!iprov)
		return -ENOMEM;
	if (!signum)
		signum = SIGIO;
	spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
	spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
	rc = uses(RL_FILE_SIGIO, iprov, tprov, cprov, file, signum);
	spin_unlock(prov_lock(iprov));
	spin_unlock_irqrestore(prov_lock(cprov), irqflags);
	return rc;
}

/*!
 * @brief Record provenance when mmap_file hook is triggered.
 *
 * This hook is triggered when checking permissions for a mmap operation.
 * The @file may be NULL, e.g., if mapping anonymous memory.
 * Provenance relation will not be recorded if:
 * 1. The file is NULL, or
 * 2. Failure occurred.
 * If the mmap is shared (flag: MAP_SHARED or MAP_SHARED_VALIDATE),
 * depending on the action allowed by the kernel,
 * record provenance relation RL_MMAP_WRITE and/or RL_MMAP_READ and/or RL_MMAP_EXEC by calling "derives" function.
 * Information flows between the mmap file and calling process and its cred.
 * The direction of the information flow depends on the action allowed.
 * If the mmap is private (flag: MAP_PRIVATE),
 * we create an additional provenance node to represent the private mapped inode by calling function "branch_mmap",
 * record provenance relation RL_MMAP by calling "derives" function because information flows from the original mapped file to the private file.
 * Then depending on the action allowed by the kernel,
 * record provenance relation RL_MMAP_WRITE and/or RL_MMAP_READ and/or RL_MMAP_EXEC by calling "derives" function.
 * Information flows between the new private mmap node and calling process and its cred.
 * The direction of the information flow depends on the action allowed.
 * Note that this new node is short-lived.
 * @param file The file structure for file to map (may be NULL).
 * @param reqprot The protection requested by the application.
 * @param prot The protection that will be applied by the kernel.
 * @param flags The operational flags.
 * @return 0 if permission is granted and no error occurred; -ENOMEM if the original file inode provenance entry is NULL; Other error codes inherited from derives function or unknown.
 *
 */
static int provenance_mmap_file(struct file *file,
				unsigned long reqprot,
				unsigned long prot,
				unsigned long flags)
{
	struct provenance *cprov = get_cred_provenance();
	struct provenance *tprov = get_task_provenance(true);
	struct provenance *iprov = NULL;
	unsigned long irqflags;
	int rc = 0;

	if (unlikely(!file))
		return rc;
	iprov = get_file_provenance(file, true);
	if (!iprov)
		return -ENOMEM;
	spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
	spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
	if (provenance_is_opaque(prov_elt(cprov)))
		goto out;
	if ((flags & MAP_TYPE) == MAP_SHARED
	    || (flags & MAP_TYPE) == MAP_SHARED_VALIDATE) {
		if ((prot & (PROT_WRITE)) != 0)
			rc = uses(RL_MMAP_WRITE, iprov, tprov, cprov, file, flags);
		if (rc < 0)
			goto out;
		if ((prot & (PROT_READ)) != 0)
			rc = uses(RL_MMAP_READ, iprov, tprov, cprov, file, flags);
		if (rc < 0)
			goto out;
		if ((prot & (PROT_EXEC)) != 0)
			rc = uses(RL_MMAP_EXEC, iprov, tprov, cprov, file, flags);
	} else {
		if (rc < 0)
			goto out;
		if ((prot & (PROT_WRITE)) != 0)
			rc = uses(RL_MMAP_WRITE_PRIVATE, iprov, tprov, cprov, file, flags);
		if (rc < 0)
			goto out;
		if ((prot & (PROT_READ)) != 0)
			rc = uses(RL_MMAP_READ_PRIVATE, iprov, tprov, cprov, file, flags);
		if (rc < 0)
			goto out;
		if ((prot & (PROT_EXEC)) != 0)
			rc = uses(RL_MMAP_EXEC_PRIVATE, iprov, tprov, cprov, file, flags);
	}
out:
	spin_unlock(prov_lock(iprov));
	spin_unlock_irqrestore(prov_lock(cprov), irqflags);
	return rc;
}

#ifdef CONFIG_SECURITY_FLOW_FRIENDLY
/*!
 * @brief Record provenance when mmap_munmap hook is triggered.
 *
 * This hook is triggered when a file is unmmap'ed.
 * We obtain the provenance entry of the mmap'ed file, and if it shows that the mmap'ed file is shared based on the flags,
 * record provenance relation RL_MUNMAP by calling "derives" function.
 * Information flows from cred of the process that unmmaps the file to the mmap'ed file.
 * Note that if the file to be unmmap'ed is private, the provenance of the mmap'ed file is short-lived and thus no longer exists.
 * @param mm Unused parameter.
 * @param vma Virtual memory of the calling process.
 * @param start Unused parameter.
 * @param end Unused parameter.
 *
 */
static void provenance_mmap_munmap(struct mm_struct *mm,
				   struct vm_area_struct *vma,
				   unsigned long start,
				   unsigned long end)
{
	struct provenance *cprov = get_cred_provenance();
	struct provenance *tprov = get_task_provenance(true);
	struct provenance *iprov = NULL;
	struct file *mmapf;
	unsigned long irqflags;
	vm_flags_t flags = vma->vm_flags;

	if (vm_mayshare(flags)) {       // It is a shared mmap.
		mmapf = vma->vm_file;
		if (mmapf) {
			iprov = get_file_provenance(mmapf, false);
			spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
			spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
			generates(RL_MUNMAP, cprov, tprov, iprov, mmapf, flags);
			spin_unlock(prov_lock(iprov));
			spin_unlock_irqrestore(prov_lock(cprov), irqflags);
		}
	}
}
#endif

/*!
 * @brief Record provenance when file_ioctl hook is triggered.
 *
 * This hook is triggered when checking permission for an ioctl operation on @file.
 * Note that @arg sometimes represents a user space pointer;
 * in other cases, it may be a simple integer value.
 * When @arg represents a user space pointer, it should never be used by the security module.
 * Record provenance relation RL_WRITE_IOCTL by calling "generates" function and RL_READ_IOCTL by calling "uses" function.
 * Information flows between the file and the calling process and its cred.
 * At the end, we save @iprov provenance.
 * @param file The file structure.
 * @param cmd The operation to perform.
 * @param arg The operational arguments.
 * @return 0 if permission is granted or no error occurred; -ENOMEM if the file inode provenance entry is NULL; Other error code inherited from generates/uses function or unknown.
 *
 */
static int provenance_file_ioctl(struct file *file,
				 unsigned int cmd,
				 unsigned long arg)
{
	struct provenance *cprov = get_cred_provenance();
	struct provenance *tprov = get_task_provenance(true);
	struct provenance *iprov = get_file_provenance(file, true);
	unsigned long irqflags;
	int rc = 0;

	if (!iprov)
		return -ENOMEM;
	spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
	spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
	rc = generates(RL_WRITE_IOCTL, cprov, tprov, iprov, NULL, 0);
	if (rc < 0)
		goto out;
	rc = uses(RL_READ_IOCTL, iprov, tprov, cprov, NULL, 0);
out:
	queue_save_provenance(iprov, file_dentry(file));
	spin_unlock(prov_lock(iprov));
	spin_unlock_irqrestore(prov_lock(cprov), irqflags);
	return rc;
}

/* msg */

/*!
 * @brief Record provenance when msg_msg_alloc_security hook is triggered.
 *
 * This hooks allocates and attaches a security structure to the msg->security field.
 * The security field is initialized to NULL when the structure is first created.
 * This function initializes and attaches a new provenance entry to the msg->provenance field.
 * We create a new provenance node ENT_MSG and update the information in the provenance entry from @msg.
 * Record provenance relation RL_MSG_CREATE by calling "generates" function.
 * Information flows from cred of the calling process to the task, and eventually to the newly created msg node.
 * @param msg The message structure to be modified.
 * @return 0 if operation was successful and permission is granted; -ENOMEM if no memory can be allocated for the new provenance entry; Other error codes inherited from generates function or unknown.
 *
 */
static int provenance_msg_msg_alloc_security(struct msg_msg *msg)
{
	struct provenance *cprov = get_cred_provenance();
	struct provenance *tprov = get_task_provenance(true);
	struct provenance *mprov;
	unsigned long irqflags;
	int rc = 0;

	mprov = alloc_provenance(ENT_MSG, GFP_KERNEL);

	if (!mprov)
		return -ENOMEM;
	prov_elt(mprov)->msg_msg_info.type = msg->m_type;
	msg->provenance = mprov;
	spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
	rc = generates(RL_MSG_CREATE, cprov, tprov, mprov, NULL, 0);
	spin_unlock_irqrestore(prov_lock(cprov), irqflags);
	return rc;
}

/*!
 * @brief Record provenance when msg_msg_free_security hook is triggered.
 *
 * This hook is triggered when deallocating the security structure for this message.
 * Free msg provenance entry when security structure for this message is deallocated.
 * If the msg has a valid provenance entry pointer (i.e., non-NULL), free the memory and set the pointer to NULL.
 * @param msg The message structure whose security structure to be freed.
 *
 */
static void provenance_msg_msg_free_security(struct msg_msg *msg)
{
	struct provenance *mprov = msg->provenance;

	if (mprov) {
		record_terminate(RL_FREED, mprov);
		free_provenance(mprov);
	}
	msg->provenance = NULL;
}

/*!
 * @brief Helper function for two security hooks: msg_queue_msgsnd and mq_timedsend.
 *
 * Record provenance relation RL_SND_MSG_Q by calling "generates" function.
 * Information flows from calling process's cred to the process, and eventually to msg.
 * @param msg The message structure.
 * @return 0 if no error occurred; Other error codes inherited from generates function or unknown.
 *
 */
static inline int __mq_msgsnd(struct msg_msg *msg)
{
	struct provenance *cprov = get_cred_provenance();
	struct provenance *tprov = get_task_provenance(true);
	struct provenance *mprov = msg->provenance;
	unsigned long irqflags;
	int rc = 0;

	spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
	spin_lock_nested(prov_lock(mprov), PROVENANCE_LOCK_MSG);
	rc = generates(RL_SND_MSG_Q, cprov, tprov, mprov, NULL, 0);
	spin_unlock(prov_lock(mprov));
	spin_unlock_irqrestore(prov_lock(cprov), irqflags);
	return rc;
}

/*!
 * @brief Record provenance when msg_queue_msgsnd hook is triggered.
 *
 * This hook is trigger when checking permission before a message, @msg, is enqueued on the message queue, @msq.
 * This function simply calls the helper function __mq_msgsnd.
 * @param msq The message queue to send message to.
 * @param msg The message to be enqueued.
 * @param msqflg The operational flags.
 * @return 0 if permission is granted. Other error codes inherited from __mq_msgsnd function or unknown.
 *
 */
static int provenance_msg_queue_msgsnd(struct kern_ipc_perm *msq,
				       struct msg_msg *msg,
				       int msqflg)
{
	return __mq_msgsnd(msg);
}

#ifdef CONFIG_SECURITY_FLOW_FRIENDLY

/*!
 * @brief Record provenance when mq_timedsend hook is triggered.
 *
 * This function simply calls the helper function __mq_msgsnd.
 * @param inode Unused parameter.
 * @param msg The message to be enqueued.
 * @param ts Unused parameter.
 * @return 0 if permission is granted. Other error codes inherited from __mq_msgsnd function or unknown.
 *
 */
static int provenance_mq_timedsend(struct inode *inode, struct msg_msg *msg,
				   struct timespec64 *ts)
{
	return __mq_msgsnd(msg);
}
#endif

/*!
 * @brief Helper function for two security hooks: msg_queue_msgrcv and mq_timedreceive.
 *
 * Record provenance relation RL_RCV_MSG_Q by calling "uses" function.
 * Information flows from msg to the calling process, and eventually to its cred.
 * @param cprov The calling process's cred provenance entry pointer.
 * @param msg The message structure.
 * @return 0 if no error occurred; Other error codes inherited from uses function or unknown.
 *
 */
static inline int __mq_msgrcv(struct provenance *cprov, struct msg_msg *msg)
{
	struct provenance *mprov = msg->provenance;
	struct provenance *tprov = get_task_provenance(true);
	unsigned long irqflags;
	int rc = 0;

	spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
	spin_lock_nested(prov_lock(mprov), PROVENANCE_LOCK_MSG);
	rc = uses(RL_RCV_MSG_Q, mprov, tprov, cprov, NULL, 0);
	spin_unlock(prov_lock(mprov));
	spin_unlock_irqrestore(prov_lock(cprov), irqflags);
	return rc;
}

/*!
 * @brief Record provenance when msg_queue_msgrcv hook is triggered.
 *
 * This hook is triggered when checking permission before a message, @msg, is removed from the message queue, @msq.
 * The @target task structure contains a pointer to the process that will be receiving the message
 * (not equal to the current process when inline receives are being performed).
 * Since it is the receiving task that receives the msg,
 * we first obtain the receiving task's cred provenance entry pointer,
 * and then simply calls the helper function __mq_msgrcv to record the information flow.
 * @param msq The message queue to retrieve message from.
 * @param msg The message destination.
 * @param target The task structure for recipient process.
 * @param type The type of message requested.
 * @param mode The operational flags.
 * @return 0 if permission is granted. Other error codes inherited from __mq_msgrcv function or unknown.
 *
 */
static int provenance_msg_queue_msgrcv(struct kern_ipc_perm *msq,
				       struct msg_msg *msg,
				       struct task_struct *target,
				       long type,
				       int mode)
{
	struct provenance *cprov = target->cred->provenance;

	return __mq_msgrcv(cprov, msg);
}

#ifdef CONFIG_SECURITY_FLOW_FRIENDLY

/*!
 * @brief Record provenance when mq_timedreceive hook is triggered.
 *
 * Current process will be receiving the message.
 * We simply calls the helper function __mq_msgrcv to record the information flow.
 * @param inode Unused parameter.
 * @param msg The message destination.
 * @param ts Unused parameter.
 * @return 0 if permission is granted. Other error codes inherited from __mq_msgrcv function or unknown.
 *
 */
static int provenance_mq_timedreceive(struct inode *inode, struct msg_msg *msg,
				      struct timespec64 *ts)
{
	struct provenance *cprov = get_cred_provenance();

	return __mq_msgrcv(cprov, msg);
}
#endif

/*!
 * @brief Record provenance when shm_alloc_security hook is triggered.
 *
 * This hunk is triggered when allocating and attaching a security structure to the shp->shm_perm.security field.
 * The security field is initialized to NULL when the structure is first created.
 * This function allocates and attaches a provenance entry to the shp->shm_perm.provenance field.
 * That is, it creates a new provenance node ENT_SHM.
 * It also fills in some provenance information based on the information contained in @shp.
 * Record provenance relation RL_SH_CREATE_READ by calling "uses" function.
 * For read, information flows from shared memory to the calling process, and eventually to its cred.
 * Record provenance relation RL_SH_CREATE_WRITE by calling "uses" function.
 * For write, information flows from the calling process's cree to the process, and eventually to shared memory.
 * @param shp The shared memory structure to be modified.
 * @return 0 if operation was successful and permission is granted, no error occurred. -ENOMEM if no memory can be allocated to create a new ENT_SHM provenance entry. Other error code inherited from uses and generates function or unknown.
 *
 */
static int provenance_shm_alloc_security(struct kern_ipc_perm *shp)
{
	struct provenance *cprov = get_cred_provenance();
	struct provenance *tprov = get_task_provenance(true);
	struct provenance *sprov = alloc_provenance(ENT_SHM, GFP_KERNEL);
	unsigned long irqflags;
	int rc = 0;

	if (!sprov)
		return -ENOMEM;
	prov_elt(sprov)->shm_info.mode = shp->mode;
	shp->provenance = sprov;
	spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
	rc = generates(RL_SH_CREATE_READ, cprov, tprov, sprov, NULL, 0);
	if (rc < 0)
		goto out;
	rc = generates(RL_SH_CREATE_WRITE, cprov, tprov, sprov, NULL, 0);
out:
	spin_unlock_irqrestore(prov_lock(cprov), irqflags);
	return 0;
}

/*!
 * @brief Record provenance when shm_free_security hook is triggered.
 *
 * This hook is triggered when deallocating the security struct for this memory segment.
 * We simply free the memory of the allocated provenance entry if it exists, and set the pointer to NULL.
 * @param shp The shared memory structure to be modified.
 *
 */
static void provenance_shm_free_security(struct kern_ipc_perm *shp)
{
	struct provenance *sprov = shp->provenance;

	if (sprov) {
		record_terminate(RL_FREED, sprov);
		free_provenance(sprov);
	}
	shp->provenance = NULL;
}

/*!
 * @brief Record provenance when shm_shmat hook is triggered.
 *
 * This hook is triggered when checking permissions prior to allowing the shmat system call to attach the
 * shared memory segment @shp to the data segment of the calling process.
 * The attaching address is specified by @shmaddr.
 * If @shmflg is SHM_RDONLY (readable only), then:
 * Record provenance relation RL_SH_ATTACH_READ by calling "uses" function.
 * Information flows from shared memory to the calling process, and then eventually to its cred.
 * Otherwise, shared memory is both readable and writable, then:
 * Record provenance relation RL_SH_ATTACH_READ by calling "uses" function and RL_SH_ATTACH_WRITE by calling "uses" function.
 * Information can flow both ways.
 * @param shp The shared memory structure to be modified.
 * @param shmaddr The address to attach memory region to.
 * @param shmflg The operational flags.
 * @return 0 if permission is granted and no error occurred; -ENOMEM if shared memory provenance entry does not exist. Other error codes inherited from uses and generates function or unknown.
 *
 */
static int provenance_shm_shmat(struct kern_ipc_perm *shp, char __user *shmaddr, int shmflg)
{
	struct provenance *cprov = get_cred_provenance();
	struct provenance *tprov = get_task_provenance(true);
	struct provenance *sprov = shp->provenance;
	unsigned long irqflags;
	int rc = 0;

	if (!sprov)
		return -ENOMEM;
	spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
	spin_lock_nested(prov_lock(sprov), PROVENANCE_LOCK_SHM);
	if (shmflg & SHM_RDONLY)
		rc = uses(RL_SH_ATTACH_READ, sprov, tprov, cprov, NULL, shmflg);
	else {
		rc = uses(RL_SH_ATTACH_READ, sprov, tprov, cprov, NULL, shmflg);
		if (rc < 0)
			goto out;
		rc = generates(RL_SH_ATTACH_WRITE, cprov, tprov, sprov, NULL, shmflg);
	}
out:
	spin_unlock(prov_lock(sprov));
	spin_unlock_irqrestore(prov_lock(cprov), irqflags);
	return rc;
}

#ifdef CONFIG_SECURITY_FLOW_FRIENDLY
/*!
 * @brief Record provenance when shm_shmdt hook is triggered.
 *
 * This hook is triggered when detaching the shared memory segment from the address space of the calling process.
 * The to-be-detached segment must be currently attached with shmaddr equal to the value returned by the attaching shmat() call.
 * Record provenance relation RL_SHMDT by calling "generates" function.
 * Information flows from the calling process's cred to the process, and eventually to the shared memory.
 * @param shp The shared memory structure to be modified.
 *
 */
static void provenance_shm_shmdt(struct kern_ipc_perm *shp)
{
	struct provenance *cprov = get_cred_provenance();
	struct provenance *tprov = get_task_provenance(true);
	struct provenance *sprov = shp->provenance;
	unsigned long irqflags;

	if (!sprov)
		return;
	spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
	spin_lock_nested(prov_lock(sprov), PROVENANCE_LOCK_SHM);
	generates(RL_SHMDT, cprov, tprov, sprov, NULL, 0);
	spin_unlock(prov_lock(sprov));
	spin_unlock_irqrestore(prov_lock(cprov), irqflags);
}
#endif

/*!
 * @brief Record provenance when sk_alloc_security hook is triggered.
 *
 * This hook is triggered when allocating and attaching a security structure to the sk->sk_security field,
 * which is used to copy security attributes between local stream sockets.
 * This function therefore allocates and attaches @sk_provenance structure to @sk.
 * The provenance of the local stream socket is the same as the cred provenance of the calling process.
 * @param sk The sock structure to be modified.
 * @param family The protocol family. Unused parameter.
 * @param priority Memory allocation operation flag.
 * @return 0 if success and no error occurred; -ENOMEM if calling process's cred structure does not exist. Other error codes unknown.
 *
 */
static int provenance_sk_alloc_security(struct sock *sk,
					int family,
					gfp_t priority)
{
	struct provenance *skprov = current_provenance();

	if (!skprov)
		return -ENOMEM;
	sk->sk_provenance = skprov;
	return 0;
}

/*!
 * @brief Record provenance when socket_post_create hook is triggered.
 *
 * This hook allows a module to update or allocate a per-socket security structure.
 * Note that the security field was not added directly to the socket structure,
 * but rather, the socket security information is stored in the associated inode.
 * Typically, the inode alloc_security hook will allocate and and attach security information to
 * sock->inode->i_security.
 * This hook may be used to update the sock->inode->i_security field
 * with additional information that wasn't available when the inode was allocated.
 * Record provenance relation RL_SOCKET_CREATE by calling "generates" function.
 * Information flows from the calling process's cred to the process, and eventually to the socket that is being created.
 * If @kern is 1 (kernal socket), no provenance relation is recorded.
 * This is becasuse kernel socket is a form of communication between kernel and userspace.
 * We do not capture kernel's provenance for now.
 * @param sock The newly created socket structure.
 * @param family The requested protocol family.
 * @param type The requested communications type.
 * @param protocol The requested protocol.
 * @param kern Set to 1 if it is a kernel socket.
 * @return 0 if no error occurred; -ENOMEM if inode provenance entry does not exist. Other error codes inherited from generates function or unknown.
 *
 * @todo Maybe support kernel socket in a future release.
 */
static int provenance_socket_post_create(struct socket *sock,
					 int family,
					 int type,
					 int protocol,
					 int kern)
{
	struct provenance *cprov = get_cred_provenance();
	struct provenance *tprov = get_task_provenance(true);
	struct provenance *iprov = get_socket_inode_provenance(sock);
	unsigned long irqflags;
	int rc = 0;

	if (kern)
		return 0;
	if (!iprov)
		return -ENOMEM;

	if (provenance_is_tracked(prov_elt(cprov))
	    || provenance_is_tracked(prov_elt(tprov)))
		set_tracked(prov_elt(iprov));

	spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
	spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
	rc = generates(RL_SOCKET_CREATE, cprov, tprov, iprov, NULL, 0);
	spin_unlock(prov_lock(iprov));
	spin_unlock_irqrestore(prov_lock(cprov), irqflags);
	return rc;
}

static int provenance_socket_socketpair(struct socket *socka, struct socket *sockb)
{
	struct provenance *cprov = get_cred_provenance();
	struct provenance *tprov = get_task_provenance(true);
	struct provenance *iprova = get_socket_inode_provenance(socka);
	struct provenance *iprovb = get_socket_inode_provenance(sockb);
	unsigned long irqflags;
	int rc = 0;

	if (!iprova)
		return -ENOMEM;
	if (!iprovb)
		return -ENOMEM;

	spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
	spin_lock_nested(prov_lock(iprova), PROVENANCE_LOCK_INODE);
	rc = generates(RL_SOCKET_PAIR_CREATE, cprov, tprov, iprova, NULL, 0);
	spin_unlock(prov_lock(iprova));
	if (rc < 0)
		goto out;
	spin_lock_nested(prov_lock(iprovb), PROVENANCE_LOCK_INODE);
	rc = generates(RL_SOCKET_PAIR_CREATE, cprov, tprov, iprovb, NULL, 0);
	spin_unlock(prov_lock(iprovb));
out:
	spin_unlock_irqrestore(prov_lock(cprov), irqflags);
	return rc;
}

/*!
 * @brief Record provenance when socket_bind hook is triggered.
 *
 * This hook is triggered when checking permission before socket protocol layer bind operation is performed,
 * and the socket @sock is bound to the address specified in the @address parameter.
 * The function records the provenance relations if the calling process is not set to be opaque (i.e., should be recorded).
 * The relation between the socket and its address is recorded first,
 * then record provenance relation RL_BIND by calling "generates" function.
 * Information flows from the cred of the calling process to the process itself, and eventually to the socket.
 * If the address family is PF_INET (we only support IPv4 for now), we check if we should record the packet from the socket,
 * and track and propagate recording from the socket and the calling process.
 * Note that usually server binds the socket to its local address.
 * @param sock The socket structure.
 * @param address The address to bind to.
 * @param addrlen The length of address.
 * @return 0 if permission is granted and no error occurred; -EINVAL if socket address is longer than @addrlen; -ENOMEM if socket inode provenance entry does not exist. Other error codes inherited or unknown.
 *
 */
static int provenance_socket_bind(struct socket *sock,
				  struct sockaddr *address,
				  int addrlen)
{
	struct provenance *cprov = get_cred_provenance();
	struct provenance *tprov = get_task_provenance(true);
	struct provenance *iprov = get_socket_inode_provenance(sock);
	int rc = 0;

	if (!iprov)
		return -ENOMEM;
	// We perform a check here so that we won't accidentally
	// start tracking/propagating @iprov and @cprov
	if (provenance_is_opaque(prov_elt(cprov)))
		return 0;
	rc = check_track_socket(address, addrlen, cprov, iprov);
	if (rc < 0)
		return rc;
	rc = record_address(address, addrlen, iprov);
	if (rc < 0)
		return rc;
	rc = generates(RL_BIND, cprov, tprov, iprov, NULL, 0);
	return rc;
}

/*!
 * @brief Record provenance when socket_connect hook is triggered.
 *
 * This hook is triggered when checking permission before socket protocol layer connect operation
 * attempts to connect socket @sock to a remote address, @address.
 * This function is similar to the above provenance_socket_bind function, except that we
 * record provenance relation RL_CONNECT by calling "generates" function.
 * @param sock The socket structure.
 * @param address The address of remote endpoint.
 * @param addrlen The length of address.
 * @return 0 if permission is granted and no error occurred; -EINVAL if socket address is longer than @addrlen; -ENOMEM if socket inode provenance entry does not exist. Other error codes inherited or unknown.
 *
 */
static int provenance_socket_connect(struct socket *sock,
				     struct sockaddr *address,
				     int addrlen)
{
	struct provenance *cprov = get_cred_provenance();
	struct provenance *tprov = get_task_provenance(true);
	struct provenance *iprov = get_socket_inode_provenance(sock);
	unsigned long irqflags;
	int rc = 0;

	if (!iprov)
		return -ENOMEM;

	spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
	spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
	if (provenance_is_opaque(prov_elt(cprov)))
		goto out;
	rc = check_track_socket(address, addrlen, cprov, iprov);
	if (rc < 0)
		goto out;
	rc = record_address(address, addrlen, iprov);
	if (rc < 0)
		goto out;
	rc = generates(RL_CONNECT, cprov, tprov, iprov, NULL, 0);
out:
	spin_unlock(prov_lock(iprov));
	spin_unlock_irqrestore(prov_lock(cprov), irqflags);
	return rc;
}

/*!
 * @brief Record provenance when socket_listen hook is triggered.
 *
 * This hook is triggered when checking permission before socket protocol layer listen operation.
 * Record provenance relation RL_LISTEN by calling "generates" function.
 * @param sock The socket structure.
 * @param backlog The maximum length for the pending connection queue.
 * @return 0 if no error occurred; -ENOMEM if socket inode provenance entry does not exist. Other error codes inherited from generates function or unknown.
 *
 */
static int provenance_socket_listen(struct socket *sock, int backlog)
{
	struct provenance *cprov = get_cred_provenance();
	struct provenance *tprov = get_task_provenance(true);
	struct provenance *iprov = get_socket_inode_provenance(sock);
	unsigned long irqflags;
	int rc = 0;

	if (!iprov)
		return -ENOMEM;
	spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
	spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
	rc = generates(RL_LISTEN, cprov, tprov, iprov, NULL, 0);
	spin_unlock(prov_lock(iprov));
	spin_unlock_irqrestore(prov_lock(cprov), irqflags);
	return rc;
}

/*!
 * @brief Record provenance when socket_accept hook is triggered.
 *
 * This hook is triggered when checking permission before accepting a new connection.
 * Note that the new socket, @newsock, has been created and some information copied to it,
 * but the accept operation has not actually been performed.
 * Since a new socket has been created after aceepting a new connection,
 * record provenance relation RL_ACCEPT_SOCKET by calling "derives" function.
 * Information flows from the old socket to the new socket.
 * Then record provenance relation RL_ACCEPT by calling "uses" function,
 * since the calling process accepts the connection.
 * Information flows from the new socket to the calling process, and eventually to its cred.
 * @param sock The listening socket structure.
 * @param newsock The newly created server socket for connection.
 * @return 0 if permission is granted and no error occurred; Other error codes inherited from derives and uses function or unknown.
 *
 */
static int provenance_socket_accept(struct socket *sock, struct socket *newsock)
{
	struct provenance *cprov = get_cred_provenance();
	struct provenance *tprov = get_task_provenance(true);
	struct provenance *iprov = get_socket_inode_provenance(sock);
	struct provenance *niprov = get_socket_inode_provenance(newsock);
	unsigned long irqflags;
	int rc = 0;

	spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
	spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
	rc = derives(RL_ACCEPT_SOCKET, iprov, niprov, NULL, 0);
	if (rc < 0)
		goto out;
	rc = uses(RL_ACCEPT, niprov, tprov, cprov, NULL, 0);
out:
	spin_unlock(prov_lock(iprov));
	spin_unlock_irqrestore(prov_lock(cprov), irqflags);
	return rc;
}

/*!
 * @brief Record provenance when socket_sendmsg_always/socket_sendmsg hook is triggered.
 *
 * This hook is triggered when checking permission before transmitting a message to another socket.
 * Record provenance relation RL_SND_MSG by calling "generates" function.
 * Information flows from the calling process's cred to the calling process, and eventually to the sending socket.
 * If sk_family is PF_UNIX (or any local communication) and sk_type is not SOCK_DGRAM,
 * we obtain the @peer receiving socket and its provenance,
 * and if the provenance is not NULL,
 * record provenance relation RL_RCV_UNIX by calling "derives" function.
 * Information flows from the sending socket to the receiving peer socket.
 * @param sock The socket structure.
 * @param msg The message to be transmitted.
 * @param size The size of message.
 * @return 0 if permission is granted and no error occurred; -ENOMEM if the sending socket's provenance entry does not exist; Other error codes inherited from generates and derives function or unknown.
 *
 */
#ifdef CONFIG_SECURITY_FLOW_FRIENDLY
static int provenance_socket_sendmsg_always(struct socket *sock,
					    struct msghdr *msg,
					    int size)
#else
static int provenance_socket_sendmsg(struct socket *sock,
				     struct msghdr *msg,
				     int size)
#endif /* CONFIG_SECURITY_FLOW_FRIENDLY */
{
	struct provenance *cprov = get_cred_provenance();
	struct provenance *tprov = get_task_provenance(true);
	struct provenance *iprova = get_socket_inode_provenance(sock);
	struct provenance *iprovb = NULL;
	struct sock *peer = NULL;
	unsigned long irqflags;
	int rc = 0;

	if (!iprova)
		return -ENOMEM;
	if (sock->sk->sk_family == PF_UNIX &&
	    sock->sk->sk_type != SOCK_DGRAM) {  // Datagram handled by unix_may_send hook.
		peer = unix_peer_get(sock->sk);
		if (peer) {
			iprovb = get_sk_inode_provenance(peer);
			if (iprovb == cprov)
				iprovb = NULL;
		}
	}
	spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
	spin_lock_nested(prov_lock(iprova), PROVENANCE_LOCK_SOCKET);
	rc = generates(RL_SND_MSG, cprov, tprov, iprova, NULL, 0);
	if (rc < 0)
		goto out;
	if (iprovb)
		rc = derives(RL_RCV_UNIX, iprova, iprovb, NULL, 0);
out:
	spin_unlock(prov_lock(iprova));
	spin_unlock_irqrestore(prov_lock(cprov), irqflags);
	if (peer)
		sock_put(peer);
	return rc;
}

/*!
 * @brief Record provenance when socket_recvmsg_always/socket_recvmsg hook is triggered.
 *
 * This hook is triggered when checking permission before receiving a message from a socket.
 * This function is similar to the above provenance_socket_sendmsg_always function except the direction is reversed.
 * Specifically, if we know the sending socket, we have
 * record provenance relation RL_SND_UNIX by calling "derives" function.
 * Information flows from the sending socket (@peer) to the receiving socket (@sock).
 * Then record provenance relation RL_RCV_MSG by calling "uses" function.
 * Information flows from the receiving socket to the calling process, and eventually to its cred.
 * @param sock The receiving socket structure.
 * @param msg The message structure.
 * @param size The size of message structure.
 * @param flags The operational flags.
 * @return 0 if permission is granted, and no error occurred; -ENOMEM if the receiving socket's provenance entry does not exist; Other error codes inherited from uses and derives function or unknown.
 *
 */
#ifdef CONFIG_SECURITY_FLOW_FRIENDLY
static int provenance_socket_recvmsg_always(struct socket *sock,
					    struct msghdr *msg,
					    int size,
					    int flags)
#else
static int provenance_socket_recvmsg(struct socket *sock,
				     struct msghdr *msg,
				     int size,
				     int flags)
#endif /* CONFIG_SECURITY_FLOW_FRIENDLY */
{
	struct provenance *cprov = get_cred_provenance();
	struct provenance *tprov = get_task_provenance(true);
	struct provenance *iprov = get_socket_inode_provenance(sock);
	struct provenance *pprov = NULL;
	struct sock *peer = NULL;
	unsigned long irqflags;
	int rc = 0;

	if (!iprov)
		return -ENOMEM;
	if (sock->sk->sk_family == PF_UNIX &&
	    sock->sk->sk_type != SOCK_DGRAM) {             // datagran handled by unix_may_send
		peer = unix_peer_get(sock->sk);
		if (peer) {
			pprov = get_sk_provenance(peer);
			if (pprov == cprov)
				pprov = NULL;
		}
	}
	spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
	spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
	if (pprov) {
		rc = derives(RL_SND_UNIX, pprov, iprov, NULL, flags);
		if (rc < 0)
			goto out;
	}
	rc = uses(RL_RCV_MSG, iprov, tprov, cprov, NULL, flags);
out:
	spin_unlock(prov_lock(iprov));
	spin_unlock_irqrestore(prov_lock(cprov), irqflags);
	if (peer)
		sock_put(peer);
	return rc;
}

/*!
 * @brief Record provenance when socket_sock_rcv_skb hook is triggered.
 *
 * This hooks is triggered when checking permissions on incoming network packets.
 * This hook is distinct from Netfilter's IP input hooks since it is the first time that
 * the incoming sk_buff @skb has been associated with a particular socket, @sk.
 * Must not sleep inside this hook because some callers hold spinlocks.
 * If the socket inode is tracked,
 * create a packet provenance node and fill the provenance information of the node from @skb,
 * and record provenance relation RL_RCV_PACKET by calling "derives" function.
 * Information flows from the packet to the socket.
 * We only handle IPv4 in this function for now (i.e. PF_INET family only).
 * @param sk The sock (not socket) associated with the incoming sk_buff.
 * @param skb The incoming network data.
 * @return 0 if no error occurred; -ENOMEM if sk provenance does not exist. Other error codes inherited from derives function or unknown.
 *
 */
static int provenance_socket_sock_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
	struct provenance *iprov;
	struct provenance *pckprov;
	uint16_t family = sk->sk_family;
	unsigned long irqflags;
	int rc = 0;

	if (family != PF_INET)
		return 0;
	iprov = get_sk_inode_provenance(sk);
	if (!iprov)
		return -ENOMEM;
	if (provenance_is_tracked(prov_elt(iprov))) {
		pckprov = provenance_alloc_with_ipv4_skb(ENT_PACKET, skb);
		if (!pckprov)
			return -ENOMEM;

		if (provenance_records_packet(prov_elt(iprov)))
			record_packet_content(skb, pckprov);

		spin_lock_irqsave(prov_lock(iprov), irqflags);
		rc = derives(RL_RCV_PACKET, pckprov, iprov, NULL, 0);
		spin_unlock_irqrestore(prov_lock(iprov), irqflags);
		free_provenance(pckprov);
	}
	return rc;
}

/*!
 * @brief Record provenance when unix_stream_connect hook is triggered.
 *
 * This hook is triggered when checking permissions before establishing a Unix domain stream connection b]etween @sock and @other.
 * Unix domain connection is local communication.
 * Since this is simply to connect (no information should flow between the two local sockets yet),
 * we do not use receiving socket information @other or new socket @newsk.
 * Record provenance relation RL_CONNECT by calling "generates" function.
 * Information flows from the calling process's cred to the task , and eventually to the sending socket.
 * @param sock The (sending) sock structure.
 * @param other The peer (i.e., receiving) sock structure. Unused parameter.
 * @param newsk The new sock structure. Unused parameter.
 * @return 0 if permission is granted; Other error code inherited from generates function or unknown.
 *
 */
static int provenance_unix_stream_connect(struct sock *sock,
					  struct sock *other,
					  struct sock *newsk)
{
	struct provenance *cprov = get_cred_provenance();
	struct provenance *tprov = get_task_provenance(true);
	struct provenance *iprov = get_sk_inode_provenance(sock);
	unsigned long irqflags;
	int rc = 0;

	spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_PROC);
	spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
	rc = generates(RL_CONNECT_UNIX_STREAM, cprov, tprov, iprov, NULL, 0);
	spin_unlock(prov_lock(iprov));
	spin_unlock_irqrestore(prov_lock(cprov), irqflags);
	return rc;
}

/*!
 * @brief Record provenance when unix_may_send hook is triggered.
 *
 * This hook is triggered when checking permissions before connecting or sending datagrams from @sock to @other.
 * Record provenance relation RL_SND_UNIX by calling "derives" function.
 * Information flows from the sending socket (@sock) to the receiving socket (@other).
 * @param sock The socket structure.
 * @param other The peer socket structure.
 * @return 0 if permission is granted and no error occurred; Other error codes inherited from derives function or unknown.
 *
 */
static int provenance_unix_may_send(struct socket *sock,
				    struct socket *other)
{
	struct provenance *iprov = get_socket_provenance(sock);
	struct provenance *oprov = get_socket_inode_provenance(other);
	unsigned long irqflags;
	int rc = 0;

	spin_lock_irqsave_nested(prov_lock(iprov), irqflags, PROVENANCE_LOCK_SOCKET);
	spin_lock_nested(prov_lock(oprov), PROVENANCE_LOCK_SOCK);
	rc = derives(RL_SND_UNIX, iprov, oprov, NULL, 0);
	spin_unlock(prov_lock(oprov));
	spin_unlock_irqrestore(prov_lock(iprov), irqflags);
	return rc;
}

/*!
 * @brief Record provenance when bprm_set_creds hook is triggered.
 *
 * This hook is triggered when saving security information in the bprm->security field,
 * typically based on information about the bprm->file, for later use by the apply_creds hook.
 * This hook may also optionally check permissions (e.g. for transitions between security domains).
 * This hook may be called multiple times during a single execve, e.g. for interpreters.
 * The hook can tell whether it has already been called by checking to see if @bprm->security is non-NULL.
 * If so, then the hook may decide either to retain the security information saved earlier or to replace it.
 * Since cred is based on information about the @bprm->file,
 * information flows from the inode of bprm->file to bprm->cred.
 * Therefore, record provenance relation RL_EXEC by calling "derives" function.
 * Relation is not recorded if the inode of bprm->file is set to be opaque.
 * @param bprm The linux_binprm structure.
 * @return 0 if the hook is successful and permission is granted; -ENOMEM if bprm->cred's provenance does not exist. Other error codes inherited from derives function or unknown.
 *
 */
static int provenance_bprm_set_creds(struct linux_binprm *bprm)
{
	struct provenance *nprov = bprm->cred->provenance;
	struct provenance *iprov = get_file_provenance(bprm->file, true);
	unsigned long irqflags;
	int rc = 0;

	if (!nprov)
		return -ENOMEM;

	if (provenance_is_opaque(prov_elt(iprov))) {
		set_opaque(prov_elt(nprov));
		return 0;
	}
	spin_lock_irqsave(prov_lock(iprov), irqflags);
	rc = derives(RL_EXEC, iprov, nprov, NULL, 0);
	spin_unlock_irqrestore(prov_lock(iprov), irqflags);
	return rc;
}

/*!
 * @brief Record provenance when bprm_check hook is triggered.
 *
 * This hook mediates the point when a search for a binary handler will begin.
 * It allows a check the @bprm->security value which is set in the preceding set_creds call.
 * The primary difference from set_creds is that the argv list and envp list are reliably available in @bprm.
 * This hook may be called multiple times during a single execve;
 * and in each pass set_creds is called first.
 * If the inode of bprm->file is opaque, we set the bprm->cred to be opaque (i.e., do not track).
 * The relations between the bprm arguments and bprm->cred are recorded by calling record_args function.
 * @param bprm The linux_binprm structure.
 * @return 0 if no error occurred; -ENOMEM if bprm->cred provenance does not exist. Other error codes inherited from record_args function or unknown.
 *
 */
static int provenance_bprm_check_security(struct linux_binprm *bprm)
{
	struct provenance *nprov = bprm->cred->provenance;
	struct provenance *tprov = get_task_provenance(false);
	struct provenance *iprov = get_file_provenance(bprm->file, false);

	if (!nprov)
		return -ENOMEM;

	if (provenance_is_opaque(prov_elt(iprov))) {
		set_opaque(prov_elt(nprov));
		set_opaque(prov_elt(tprov));
		return 0;
	}
	if (provenance_is_tracked(prov_elt(iprov)))
		set_tracked(prov_elt(nprov));
	return record_args(nprov, bprm);
}

/*!
 * @brief Record provenance when bprm_committing_creds hook is triggered.
 *
 * This hook is triggered when preparing to install the new security attributes of a process being transformed by an execve operation,
 * based on the old credentials pointed to by @current->cred,
 * and the information set in @bprm->cred by the bprm_set_creds hook.
 * This hook is a good place to perform state changes on the process such as
 * closing open file descriptors to which access will no longer
 * be granted when the attributes are changed.
 * This is called immediately before commit_creds().
 * Since the process is being transformed to the new process,
 * record provenance relation RL_EXEC_TASK by calling "derives" function.
 * Information flows from the old process's cred to the new process's cred.
 * Cred can also be set by bprm_set_creds, so
 * record provenance relation RL_EXEC by calling "derives" function.
 * Information flows from the bprm->file's cred to the new process's cred.
 * The old process gets the name of the new process by calling record_node_name function.
 * Note that if bprm->file's provenance is set to be opaque,
 * the new process bprm->cred's provenance will therefore be opaque and we do not track any of the relations.
 * @param bprm points to the linux_binprm structure.
 *
 */
static void provenance_bprm_committing_creds(struct linux_binprm *bprm)
{
	struct provenance *tprov = get_task_provenance(true);
	struct provenance *cprov = get_cred_provenance();
	struct provenance *nprov = bprm->cred->provenance;
	unsigned long irqflags;

	record_node_name(cprov, bprm->interp, false);
	spin_lock_irqsave(prov_lock(cprov), irqflags);
	generates(RL_EXEC_TASK, cprov, tprov, nprov, NULL, 0);
	spin_unlock_irqrestore(prov_lock(cprov), irqflags);
}

/*!
 * @brief Record provenance when sb_alloc_security hook is triggered.
 *
 * This hook is triggered when allocating and attaching a security structure to the sb->s_security field.
 * The s_security field is initialized to NULL when the structure is allocated.
 * This function allocates and initializes a provenance structure to sb->s_provenance field.
 * It also creates a new provenance node ENT_SBLCK.
 * SB represents the existence of a device/pipe.
 * @param sb The super_block structure to be modified.
 * @return 0 if operation was successful; -ENOMEM if no memory can be allocated for a new provenance entry. Other error codes unknown.
 *
 */
static int provenance_sb_alloc_security(struct super_block *sb)
{
	struct provenance *sbprov = alloc_provenance(ENT_SBLCK, GFP_KERNEL);

	if (!sbprov)
		return -ENOMEM;
	sb->s_provenance = sbprov;
	return 0;
}

/*!
 * @brief Record provenance when sb_free_security hook is triggered.
 *
 * This hooks is triggered when deallocating and clearing the sb->s_security field.
 * This function frees the memory of the allocated provenance field and set the pointer to NULL.
 * @param sb The super_block structure to be modified.
 *
 */
static void provenance_sb_free_security(struct super_block *sb)
{
	if (sb->s_provenance)
		free_provenance(sb->s_provenance);
	sb->s_provenance = NULL;
}

/*!
 * @brief Record provenance when sb_kern_mount hook is triggered.
 *
 * This hook is triggered when mounting a kernel device, including pipe.
 * This function will update the Universal Unique ID of the provenance entry of the device @sb->s_provenance once it is mounted.
 * We obtain this information from @sb if it exists, or we give it a random value.
 * @param sb The super block structure.
 * @param flags The operations flags.
 * @param data
 * @return always return 0.
 *
 */
static int provenance_sb_kern_mount(struct super_block *sb)
{
	int i;
	uint8_t c = 0;
	struct provenance *sbprov = sb->s_provenance;

	for (i = 0; i < 16; i++) {
		prov_elt(sbprov)->sb_info.uuid[i] = sb->s_uuid.b[i];
		c |= sb->s_uuid.b[i];
	}
	if (c == 0)     // If no uuid defined, generate a random one.
		get_random_bytes(prov_elt(sbprov)->sb_info.uuid, 16 * sizeof(uint8_t));
	return 0;
}

struct lsm_blob_sizes provenance_blob_sizes __lsm_ro_after_init = {
	.lbs_cred = sizeof(struct provenance),
	.lbs_file = sizeof(struct provenance),
	.lbs_inode = sizeof(struct provenance),
	.lbs_ipc = sizeof(struct provenance),
	.lbs_msg_msg = sizeof(struct provenance),
	.lbs_task = sizeof(struct provenance),
};

/*!
 * @brief Add provenance hooks to security_hook_list.
 */
static struct security_hook_list provenance_hooks[] __lsm_ro_after_init = {
	/* cred related hooks */
	LSM_HOOK_INIT(cred_free,                provenance_cred_free),
	LSM_HOOK_INIT(cred_alloc_blank,         provenance_cred_alloc_blank),
	LSM_HOOK_INIT(cred_prepare,             provenance_cred_prepare),
	LSM_HOOK_INIT(cred_transfer,            provenance_cred_transfer),

	/* task related hooks */
	LSM_HOOK_INIT(task_alloc,               provenance_task_alloc),
	LSM_HOOK_INIT(task_free,                provenance_task_free),
	LSM_HOOK_INIT(task_fix_setuid,          provenance_task_fix_setuid),
	LSM_HOOK_INIT(task_setpgid,             provenance_task_setpgid),
	LSM_HOOK_INIT(task_getpgid,             provenance_task_getpgid),
	LSM_HOOK_INIT(task_kill,                provenance_task_kill),

	/* inode related hooks */
	LSM_HOOK_INIT(inode_alloc_security,     provenance_inode_alloc_security),
	LSM_HOOK_INIT(inode_create,             provenance_inode_create),
	LSM_HOOK_INIT(inode_free_security,      provenance_inode_free_security),
	LSM_HOOK_INIT(inode_permission,         provenance_inode_permission),
	LSM_HOOK_INIT(inode_link,               provenance_inode_link),
	LSM_HOOK_INIT(inode_unlink,             provenance_inode_unlink),
	LSM_HOOK_INIT(inode_symlink,            provenance_inode_symlink),
	LSM_HOOK_INIT(inode_rename,             provenance_inode_rename),
	LSM_HOOK_INIT(inode_setattr,            provenance_inode_setattr),
	LSM_HOOK_INIT(inode_getattr,            provenance_inode_getattr),
	LSM_HOOK_INIT(inode_readlink,           provenance_inode_readlink),
	LSM_HOOK_INIT(inode_setxattr,           provenance_inode_setxattr),
	LSM_HOOK_INIT(inode_post_setxattr,      provenance_inode_post_setxattr),
	LSM_HOOK_INIT(inode_getxattr,           provenance_inode_getxattr),
	LSM_HOOK_INIT(inode_listxattr,          provenance_inode_listxattr),
	LSM_HOOK_INIT(inode_removexattr,        provenance_inode_removexattr),
	LSM_HOOK_INIT(inode_getsecurity,        provenance_inode_getsecurity),
	LSM_HOOK_INIT(inode_listsecurity,       provenance_inode_listsecurity),

	/* file related hooks */
	LSM_HOOK_INIT(file_permission,          provenance_file_permission),
	LSM_HOOK_INIT(mmap_file,                provenance_mmap_file),
#ifdef CONFIG_SECURITY_FLOW_FRIENDLY
	LSM_HOOK_INIT(mmap_munmap,              provenance_mmap_munmap),
#endif
	LSM_HOOK_INIT(file_ioctl,               provenance_file_ioctl),
	LSM_HOOK_INIT(file_open,                provenance_file_open),
	LSM_HOOK_INIT(file_receive,             provenance_file_receive),
	LSM_HOOK_INIT(file_lock,                provenance_file_lock),
	LSM_HOOK_INIT(file_send_sigiotask,      provenance_file_send_sigiotask),
#ifdef CONFIG_SECURITY_FLOW_FRIENDLY
	LSM_HOOK_INIT(file_splice_pipe_to_pipe, provenance_file_splice_pipe_to_pipe),
#endif
	LSM_HOOK_INIT(kernel_read_file,         provenance_kernel_read_file),

	/* msg related hooks */
	LSM_HOOK_INIT(msg_msg_alloc_security,   provenance_msg_msg_alloc_security),
	LSM_HOOK_INIT(msg_msg_free_security,    provenance_msg_msg_free_security),
	LSM_HOOK_INIT(msg_queue_msgsnd,         provenance_msg_queue_msgsnd),
	LSM_HOOK_INIT(msg_queue_msgrcv,         provenance_msg_queue_msgrcv),

	/* shared memory related hooks */
	LSM_HOOK_INIT(shm_alloc_security,       provenance_shm_alloc_security),
	LSM_HOOK_INIT(shm_free_security,        provenance_shm_free_security),
	LSM_HOOK_INIT(shm_shmat,                provenance_shm_shmat),
#ifdef CONFIG_SECURITY_FLOW_FRIENDLY
	LSM_HOOK_INIT(shm_shmdt,                provenance_shm_shmdt),
#endif

	/* socket related hooks */
	LSM_HOOK_INIT(sk_alloc_security,        provenance_sk_alloc_security),
	LSM_HOOK_INIT(socket_post_create,       provenance_socket_post_create),
	LSM_HOOK_INIT(socket_socketpair,        provenance_socket_socketpair),
	LSM_HOOK_INIT(socket_bind,              provenance_socket_bind),
	LSM_HOOK_INIT(socket_connect,           provenance_socket_connect),
	LSM_HOOK_INIT(socket_listen,            provenance_socket_listen),
	LSM_HOOK_INIT(socket_accept,            provenance_socket_accept),
#ifdef CONFIG_SECURITY_FLOW_FRIENDLY
	LSM_HOOK_INIT(socket_sendmsg_always,    provenance_socket_sendmsg_always),
	LSM_HOOK_INIT(socket_recvmsg_always,    provenance_socket_recvmsg_always),
	LSM_HOOK_INIT(mq_timedreceive,          provenance_mq_timedreceive),
	LSM_HOOK_INIT(mq_timedsend,             provenance_mq_timedsend),
#else   /* CONFIG_SECURITY_FLOW_FRIENDLY */
	LSM_HOOK_INIT(socket_sendmsg,           provenance_socket_sendmsg),
	LSM_HOOK_INIT(socket_recvmsg,           provenance_socket_recvmsg),
#endif  /* CONFIG_SECURITY_FLOW_FRIENDLY */
	LSM_HOOK_INIT(socket_sock_rcv_skb,      provenance_socket_sock_rcv_skb),
	LSM_HOOK_INIT(unix_stream_connect,      provenance_unix_stream_connect),
	LSM_HOOK_INIT(unix_may_send,            provenance_unix_may_send),

	/* exec related hooks */
	LSM_HOOK_INIT(bprm_check_security,      provenance_bprm_check_security),
	LSM_HOOK_INIT(bprm_set_creds,           provenance_bprm_set_creds),
	LSM_HOOK_INIT(bprm_committing_creds,    provenance_bprm_committing_creds),

	/* file system related hooks */
	LSM_HOOK_INIT(sb_alloc_security,        provenance_sb_alloc_security),
	LSM_HOOK_INIT(sb_free_security,         provenance_sb_free_security),
	LSM_HOOK_INIT(sb_kern_mount,            provenance_sb_kern_mount)
};

struct kmem_cache *provenance_cache __ro_after_init;
struct kmem_cache *long_provenance_cache __ro_after_init;

union prov_elt *buffer_head;
union long_prov_elt *long_buffer_head;

LIST_HEAD(ingress_ipv4filters);
LIST_HEAD(egress_ipv4filters);
LIST_HEAD(secctx_filters);
LIST_HEAD(user_filters);
LIST_HEAD(group_filters);
LIST_HEAD(ns_filters);
LIST_HEAD(provenance_query_hooks);

struct capture_policy prov_policy;

uint32_t prov_machine_id;
uint32_t prov_boot_id;
uint32_t epoch;

/*!
 * @brief Operations to start provenance capture.
 *
 * Those operations are:
 * 1. Set up default capture policies.
 * 2. Machine ID is default to 1.
 * 3. Boot ID is default to 0.
 * 4. Set up kernel memory cache for regular provenance entries (NULL on failure).
 * 5. Set up kernel memory cache for long provenance entries (NULL on failure).
 * 6. Set up boot buffer for regualr provenance entries (NULL on failure).
 * 7. Set up boot buffer for long provenance entries (NULL on failure).
 * (Note that we set up boot buffer because relayfs is not ready at this point.)
 * 8. Initialize a workqueue (NULL on failure).
 * 9. Initialize security for provenance task ("task_init_provenance" function).
 * 10. Register provenance security hooks.
 * Work_queue helps persiste provenance of inodes (if needed) during the operations that cannot sleep,
 * since persists provenance requires writing to disk (which means sleep is needed).
 *
 */
static int __init provenance_init(void)
{
	prov_policy.prov_enabled = true;
#ifdef CONFIG_SECURITY_PROVENANCE_WHOLE_SYSTEM
	prov_policy.prov_all = true;
#else
	prov_policy.prov_all = false;
#endif
	prov_policy.prov_written = false;
	prov_policy.should_duplicate = false;
	prov_policy.should_compress_node = true;
	prov_policy.should_compress_edge = true;
	prov_machine_id = 0;
	prov_boot_id = 0;
	epoch = 1;
	provenance_cache = kmem_cache_create("provenance_struct",
					     sizeof(struct provenance),
					     0, SLAB_PANIC, NULL);
	if (unlikely(!provenance_cache))
		panic("Provenance: could not allocate provenance_cache.");
	long_provenance_cache = kmem_cache_create("long_provenance_struct",
						  sizeof(union long_prov_elt),
						  0, SLAB_PANIC, NULL);
	if (unlikely(!long_provenance_cache))
		panic("Provenance: could not allocate long_provenance_cache.");
	buffer_head = NULL;
	long_buffer_head = NULL;

#ifdef CONFIG_SECURITY_PROVENANCE_PERSISTENCE
	prov_queue = alloc_workqueue("prov_queue", 0, 0);
	if (!prov_queue)
		pr_err("Provenance: could not initialize work queue.");
#endif
	relay_ready = false;
	task_init_provenance();
	init_prov_machine();
	print_prov_machine();
	pr_info("Provenance: starting in epoch %d.", epoch);
	security_add_hooks(provenance_hooks, ARRAY_SIZE(provenance_hooks), "provenance");       // Register provenance security hooks.
	pr_info("Provenance: hooks ready.\n");
}

DEFINE_LSM(provenance) = {
	.name = "provenance",
	.blobs = &provenance_blob_sizes,
	.init = provenance_init,
};
