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
#include "provenance_inode.h"

#define current_pid() (current->pid)
static inline uint32_t current_cid( void ){
	uint32_t cid = 0;
	struct cgroup_namespace* cns;
	task_lock(current);
	if(current->nsproxy!=NULL){
		cns = current->nsproxy->cgroup_ns;
		if(cns!=NULL){
			get_cgroup_ns(cns);
			cid = cns->ns.inum;
			put_cgroup_ns(cns);
		}
	}
	task_unlock(current);
	return cid;
}

#define vm_write(flags)   ((flags & VM_WRITE)==VM_WRITE)
#define vm_read(flags)    ((flags & VM_READ)==VM_READ)
#define vm_exec(flags)    ((flags & VM_EXEC)==VM_EXEC)
#define vm_mayshare(flags) ((flags & (VM_SHARED|VM_MAYSHARE) )!=0)
#define vm_write_mayshare(flags) (vm_write(flags) && vm_mayshare(flags))
#define vm_read_exec_mayshare(flags) ((vm_write(flags) || vm_exec(flags)) && vm_mayshare(flags))


static inline void current_update_shst( struct provenance *cprov ){
	struct mm_struct *mm = get_task_mm(current);
  struct vm_area_struct *vma;
  struct file* mmapf;
  vm_flags_t flags;
  struct provenance * mmprov;

	if(!mm){
    return;
  }
	//while(!down_read_trylock(&mm->mmap_sem)); // we do not want to sleep
	vma = mm->mmap;
	while(vma){ // we go through mmaped files
    mmapf = vma->vm_file;
    if(mmapf){
      flags = vma->vm_flags;
      mmprov = file_inode(mmapf)->i_provenance;
			if(mmprov){
				if(vm_read_exec_mayshare(flags)){
          record_relation(RL_SH_READ, prov_msg(mmprov), prov_msg(cprov), FLOW_ALLOWED, NULL);
				}
      	if(vm_write_mayshare(flags)){
          record_relation(RL_SH_WRITE, prov_msg(cprov), prov_msg(mmprov), FLOW_ALLOWED, NULL);
        }
      }
    }
    vma = vma->vm_next;
  }
	//up_read(&mm->mmap_sem);
	mmput_async(mm);
}


static inline void refresh_current_provenance( void ){
	struct provenance *prov = current_provenance();
	uint32_t cid = current_cid();
	uint8_t op;
	uint8_t update;

	spin_lock_nested(prov_lock(prov), PROVENANCE_LOCK_TASK);
	if(unlikely(prov_msg(prov)->task_info.pid == 0)){
		prov_msg(prov)->task_info.pid = task_pid_nr(current);
	}
	if(unlikely(prov_msg(prov)->task_info.vpid == 0)){
		prov_msg(prov)->task_info.vpid = task_pid_vnr(current);
	}
	if(unlikely(prov_msg(prov)->task_info.cid != cid)){
		prov_msg(prov)->task_info.cid = cid;
	}
	security_task_getsecid(current, &(prov_msg(prov)->task_info.secid));
	op = prov_secctx_whichOP(&secctx_filters, prov_msg(prov)->task_info.secid);
	if(unlikely(op!=0)){
		if( (op & PROV_SEC_TRACKED)!=0 ){
			set_tracked(prov_msg(prov));
		}
		if( (op & PROV_SEC_PROPAGATE)!=0 ){
			set_propagate(prov_msg(prov));
		}
	}
	if(prov->updt_mmap && prov->has_mmap){
		update = 1;
		prov->updt_mmap = 0;
	}
	spin_unlock(prov_lock(prov));
	if(update){
		current_update_shst(prov);
	}
	record_task_name(current, prov);
}

static inline struct provenance* prov_from_vpid(pid_t pid){
	struct provenance* tprov;

	struct task_struct *dest = find_task_by_vpid(pid);
	if(!dest){
    return NULL;
	}

	tprov = __task_cred(dest)->provenance;
	if(!tprov){
		return NULL;
	}
	return tprov;
}

static inline struct provenance *get_current_provenance( void )
{
	refresh_current_provenance();
	return current_provenance();
}

/*
static inline void current_config_from_file(struct task_struct *task){
	const struct cred *cred = get_task_cred(task);
	struct mm_struct *mm;
 	struct file *exe_file;
	struct inode *inode;
	prov_msg_t* tprov;
	prov_msg_t* iprov;

	if(!cred)
		return;

	tprov = cred->provenance;

	mm = get_task_mm(task);
	if (!mm)
 		goto finished;
	exe_file = get_mm_exe_file(mm);
	mmput(mm);

	if(exe_file){
		inode = file_inode(exe_file);
		iprov = inode_provenance(inode);
		if(provenance_is_tracked(iprov)){
			set_tracked(tprov);
		}
		if(provenance_is_opaque(iprov)){
			set_opaque(tprov);
		}
		if(provenance_does_propagate(iprov)){
			set_propagate(tprov);
		}
	}

finished:
	put_cred(cred);
}
*/
#endif
