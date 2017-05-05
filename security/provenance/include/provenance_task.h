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
#ifndef CONFIG_SECURITY_PROVENANCE_TASK
#define CONFIG_SECURITY_PROVENANCE_TASK

#include <linux/cred.h>
#include <linux/binfmts.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/sched/mm.h>
#include <linux/utsname.h>
#include <linux/ipc_namespace.h>
#include <linux/mnt_namespace.h>
#include <net/net_namespace.h>
#include <linux/pid_namespace.h>
#include "../../../fs/mount.h" // nasty

#include "provenance_secctx.h"
#include "provenance_cgroup.h"
#include "provenance_inode.h"

#define current_pid() (current->pid)
static inline uint32_t current_cgroupns(void)
{
	uint32_t id = 0;
	struct cgroup_namespace *cns;

	task_lock(current);
	if (current->nsproxy) {
		cns = current->nsproxy->cgroup_ns;
		if (cns) {
			get_cgroup_ns(cns);
			id = cns->ns.inum;
			put_cgroup_ns(cns);
		}
	}
	task_unlock(current);
	return id;
}

static inline uint32_t current_utsns(void)
{
	uint32_t id = 0;
	struct uts_namespace *ns;

	task_lock(current);
	if (current->nsproxy) {
		ns = current->nsproxy->uts_ns;
		if (ns) {
			get_uts_ns(ns);
			id = ns->ns.inum;
			put_uts_ns(ns);
		}
	}
	task_unlock(current);
	return id;
}

static inline uint32_t current_ipcns(void)
{
	uint32_t id = 0;
	struct ipc_namespace *ns;

	task_lock(current);
	if (current->nsproxy) {
		ns = current->nsproxy->ipc_ns;
		if (ns) {
			get_ipc_ns(ns);
			id = ns->ns.inum;
			put_ipc_ns(ns);
		}
	}
	task_unlock(current);
	return id;
}

static inline uint32_t current_mntns(void)
{
	uint32_t id = 0;
	struct mnt_namespace *ns;

	task_lock(current);
	if (current->nsproxy) {
		ns = current->nsproxy->mnt_ns;
		if (ns) {
			get_mnt_ns(ns);
			id = ns->ns.inum;
			put_mnt_ns(ns);
		}
	}
	task_unlock(current);
	return id;
}

static inline uint32_t current_netns(void)
{
	uint32_t id = 0;
	struct net *ns;

	task_lock(current);
	if (current->nsproxy) {
		ns = current->nsproxy->net_ns;
		if (ns) {
			get_net(ns);
			id = ns->ns.inum;
			put_net(ns);
		}
	}
	task_unlock(current);
	return id;
}

static inline uint32_t current_pidns(void)
{
	uint32_t id = 0;
	struct pid_namespace *ns;

	task_lock(current);
	ns = task_active_pid_ns(current);
	if (ns) {
		id = ns->ns.inum;
		put_pid_ns(ns);
	}
	task_unlock(current);
	return id;
}

#define vm_write(flags)   ((flags & VM_WRITE) == VM_WRITE)
#define vm_read(flags)    ((flags & VM_READ) == VM_READ)
#define vm_exec(flags)    ((flags & VM_EXEC) == VM_EXEC)
#define vm_mayshare(flags) ((flags & (VM_SHARED | VM_MAYSHARE)) != 0)
#define vm_write_mayshare(flags) (vm_write(flags) && vm_mayshare(flags))
#define vm_read_exec_mayshare(flags) ((vm_write(flags) || vm_exec(flags)) && vm_mayshare(flags))


static inline void current_update_shst(struct provenance *cprov)
{
	struct mm_struct *mm = get_task_mm(current);
	struct vm_area_struct *vma;
	struct file *mmapf;
	vm_flags_t flags;
	struct provenance *mmprov;

	if (!mm)
		return;
	cprov->has_mmap = 0;
	vma = mm->mmap;
	while (vma) { // we go through mmaped files
		mmapf = vma->vm_file;
		if (mmapf) {
			flags = vma->vm_flags;
			mmprov = file_inode(mmapf)->i_provenance;
			if (mmprov) {
				cprov->has_mmap = 1;
				spin_lock_nested(prov_lock(mmprov), PROVENANCE_LOCK_INODE);
				if (vm_read_exec_mayshare(flags))
					record_relation(RL_SH_READ, mmprov, cprov, NULL);
				if (vm_write_mayshare(flags))
					record_relation(RL_SH_WRITE, cprov, mmprov, NULL);
				spin_unlock(prov_lock(mmprov));
			}
		}
		vma = vma->vm_next;
	}
	mmput_async(mm);
}

static inline int record_task_name(struct task_struct *task, struct provenance *prov)
{
	const struct cred *cred;
	struct provenance *fprov;
	struct mm_struct *mm;
	struct file *exe_file;
	char *buffer;
	char *ptr;
	int rc = 0;

	if (provenance_is_name_recorded(prov_elt(prov)) ||
	    !provenance_is_recorded(prov_elt(prov)))
		return 0;
	cred = get_task_cred(task);
	if (!cred)
		return rc;
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
		rc = record_node_name(prov, ptr);
		kfree(buffer);
	}
out:
	put_cred(cred);
	return rc;
}

static inline void refresh_current_provenance(void)
{
	struct provenance *prov = current_provenance();
	unsigned long irqflags;

	// will not be recorded
	if (provenance_is_opaque(prov_elt(prov)))
		return;
	record_task_name(current, prov);
	spin_lock_irqsave_nested(prov_lock(prov), irqflags, PROVENANCE_LOCK_TASK);
	if (unlikely(prov_elt(prov)->task_info.pid == 0))
		prov_elt(prov)->task_info.pid = task_pid_nr(current);
	if (unlikely(prov_elt(prov)->task_info.vpid == 0))
		prov_elt(prov)->task_info.vpid = task_pid_vnr(current);
	prov_elt(prov)->task_info.utsns = current_utsns();
	prov_elt(prov)->task_info.ipcns = current_ipcns();
	prov_elt(prov)->task_info.mntns = current_mntns();
	prov_elt(prov)->task_info.pidns = current_pidns();
	prov_elt(prov)->task_info.netns = current_netns();
	prov_elt(prov)->task_info.cgroupns = current_cgroupns();
	security_task_getsecid(current, &(prov_elt(prov)->task_info.secid));
	if (prov->updt_mmap && prov->has_mmap) {
		current_update_shst(prov);
		prov->updt_mmap = 0;
	}
	spin_unlock_irqrestore(prov_lock(prov), irqflags);
}

static inline struct provenance *prov_from_vpid(pid_t pid)
{
	struct provenance *tprov;
	struct task_struct *dest = find_task_by_vpid(pid);

	if (!dest)
		return NULL;

	tprov = __task_cred(dest)->provenance;
	if (!tprov)
		return NULL;
	return tprov;
}

static inline int terminate_task(struct provenance *tprov)
{
	union prov_elt old_prov;
	int rc;
	if (!provenance_is_tracked(prov_elt(tprov)) && !prov_all)
		return 0;
	if (filter_node(prov_entry(tprov)))
		return 0;
	memcpy(&old_prov, prov_elt(tprov), sizeof(union prov_elt));
	node_identifier(prov_elt(tprov)).version++;
	clear_recorded(prov_elt(tprov));
	write_node(&old_prov);
	write_node(prov_elt(tprov));
	rc = write_relation(RL_TERMINATE_PROCESS, &old_prov, prov_elt(tprov), NULL);
	tprov->has_outgoing = false;
	return rc;
}
#endif
