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
#ifndef CONFIG_SECURITY_PROVENANCE_TASK
#define CONFIG_SECURITY_PROVENANCE_TASK

#include <linux/cred.h>
#include <linux/binfmts.h>
#include <linux/sched.h>

#include "provenance_long.h"
#include "provenance_secctx.h"
#include "provenance_cgroup.h"
#include "provenance_inode.h"

#define current_pid() (current->pid)
static inline uint32_t current_cid(void)
{
	uint32_t cid = 0;
	struct cgroup_namespace *cns;

	task_lock(current);
	if (current->nsproxy != NULL) {
		cns = current->nsproxy->cgroup_ns;
		if (cns != NULL) {
			get_cgroup_ns(cns);
			cid = cns->ns.inum;
			put_cgroup_ns(cns);
		}
	}
	task_unlock(current);
	return cid;
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
					record_relation(RL_SH_READ, prov_msg(mmprov), prov_msg(cprov), FLOW_ALLOWED, NULL);
				if (vm_write_mayshare(flags))
					record_relation(RL_SH_WRITE, prov_msg(cprov), prov_msg(mmprov), FLOW_ALLOWED, NULL);
				spin_unlock(prov_lock(mmprov));
			}
		}
		vma = vma->vm_next;
	}
	mmput_async(mm);
}


static inline void refresh_current_provenance(void)
{
	struct provenance *prov = current_provenance();
	uint32_t cid;
	// will not be recorded
	if( provenance_is_opaque(prov_msg(prov)) )
		return;
	cid = current_cid();
	record_task_name(current, prov);
	spin_lock_nested(prov_lock(prov), PROVENANCE_LOCK_TASK);
	if (unlikely(prov_msg(prov)->task_info.pid == 0))
		prov_msg(prov)->task_info.pid = task_pid_nr(current);
	if (unlikely(prov_msg(prov)->task_info.vpid == 0))
		prov_msg(prov)->task_info.vpid = task_pid_vnr(current);
	prov_msg(prov)->task_info.cid = cid;
	security_task_getsecid(current, &(prov_msg(prov)->task_info.secid));
	if (prov->updt_mmap && prov->has_mmap) {
		current_update_shst(prov);
		prov->updt_mmap = 0;
	}
	spin_unlock(prov_lock(prov));
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
#endif
