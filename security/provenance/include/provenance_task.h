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
#include <linux/sched/signal.h>
#include <linux/utsname.h>
#include <linux/ipc_namespace.h>
#include <linux/mnt_namespace.h>
#include <linux/mm.h> // used for get_page
#include <net/net_namespace.h>
#include <linux/pid_namespace.h>
#include "../../../fs/mount.h" // nasty

#include "provenance_inode.h"
#include "provenance_policy.h"

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
	if (!provenance_is_tracked(prov_elt(tprov)) && !prov_policy.prov_all)
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

/* see fs/exec.c */
static void acct_arg_size(struct linux_binprm *bprm, unsigned long pages)
{
	struct mm_struct *mm = current->mm;
	long diff = (long)(pages - bprm->vma_pages);

	if (!mm || !diff)
		return;

	bprm->vma_pages = pages;
	add_mm_counter(mm, MM_ANONPAGES, diff);
}

/* see fs/exec.c */
static struct page *get_arg_page(struct linux_binprm *bprm,
																				unsigned long pos,
																				int write)
{
	struct page *page;
	int ret;
	unsigned int gup_flags = FOLL_FORCE;

#ifdef CONFIG_STACK_GROWSUP
	if (write) {
		ret = expand_downwards(bprm->vma, pos);
		if (ret < 0)
			return NULL;
	}
#endif

	if (write)
		gup_flags |= FOLL_WRITE;

	/*
	 * We are doing an exec().  'current' is the process
	 * doing the exec and bprm->mm is the new process's mm.
	 */
	ret = get_user_pages_remote(current, bprm->mm, pos, 1, gup_flags,
			&page, NULL, NULL);
	if (ret <= 0)
		return NULL;

	if (write) {
		unsigned long size = bprm->vma->vm_end - bprm->vma->vm_start;
		unsigned long ptr_size;
		struct rlimit *rlim;

		/*
		 * Since the stack will hold pointers to the strings, we
		 * must account for them as well.
		 *
		 * The size calculation is the entire vma while each arg page is
		 * built, so each time we get here it's calculating how far it
		 * is currently (rather than each call being just the newly
		 * added size from the arg page).  As a result, we need to
		 * always add the entire size of the pointers, so that on the
		 * last call to get_arg_page() we'll actually have the entire
		 * correct size.
		 */
		ptr_size = (bprm->argc + bprm->envc) * sizeof(void *);
		if (ptr_size > ULONG_MAX - size)
			goto fail;
		size += ptr_size;

		acct_arg_size(bprm, size / PAGE_SIZE);

		/*
		 * We've historically supported up to 32 pages (ARG_MAX)
		 * of argument strings even with small stacks
		 */
		if (size <= ARG_MAX)
			return page;

		/*
		 * Limit to 1/4-th the stack size for the argv+env strings.
		 * This ensures that:
		 *  - the remaining binfmt code will not run out of stack space,
		 *  - the program will have a reasonable amount of stack left
		 *    to work from.
		 */
		rlim = current->signal->rlim;
		if (size > READ_ONCE(rlim[RLIMIT_STACK].rlim_cur) / 4)
			goto fail;
	}

	return page;

fail:
	put_page(page);
	return NULL;
}

/* see fs/exec.c */
static int copy_argv_bprm(struct linux_binprm *bprm, char *buff,
		unsigned long len)
{
	int rv = 0;
	unsigned long ofs, bytes;
	struct page *page = NULL, *new_page;
	const char *kaddr;
	unsigned long src;

	src = bprm->p;
	ofs = src % PAGE_SIZE;
	while (len) {
		new_page = get_arg_page(bprm, src, 0);
		if (!new_page) {
			rv = -E2BIG;
			goto out;
		}
		if (page) {
			kunmap(page);
			put_page(page);
		}
		page = new_page;
		kaddr = kmap(page);
		flush_cache_page(bprm->vma, ofs, page_to_pfn(page));
		bytes = min_t(unsigned int, len, PAGE_SIZE - ofs);
		memcpy(buff, kaddr + ofs, bytes);
		src += bytes;
		buff += bytes;
		len -= bytes;
		ofs = 0;
	}
	rv = src - bprm->p;
out:
	if (page) {
		kunmap(page);
		put_page(page);
	}
	return rv;
}

static int prov_record_args(struct provenance *prov,
																		struct linux_binprm *bprm)
{
	char* argv;
	char* ptr;
	unsigned long len;
	unsigned long offset;
	int rc=0;
	int argc;
	int envc;

	// we are not tracked, no need to register parameters
	if (!provenance_is_tracked(prov_elt(prov)) && !prov_policy.prov_all)
		return 0;
	len = bprm->exec - bprm->p;
	pr_info("Provenance: size %lu", len);
	argv = kzalloc(len, GFP_KERNEL);
	if (!argv)
		return -ENOMEM;
	rc = copy_argv_bprm(bprm, argv, len);
	if (rc < 0)
		return -ENOMEM;
	pr_info("Provenance: rc %d", rc);
	argc = bprm->argc;
	envc = bprm->envc;
	ptr = argv;
	while(argc-- > 0){
		pr_info("Provenance: argv %s", ptr);
		ptr += strnlen(ptr, len)+1;
		len -= strnlen(ptr, len)+1;
	}
	while(envc-- > 0){
		pr_info("Provenance: envv %s", ptr);
		ptr += strnlen(ptr, len)+1;
		len -= strnlen(ptr, len)+1;
	}
	kfree(argv);
	return 0;
}
#endif
