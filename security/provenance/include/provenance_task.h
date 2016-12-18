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

static inline prov_msg_t* ready_current_provenance( void ){
	prov_msg_t* tprov = current_provenance();
	uint32_t cid = current_cid();
	lock_node(tprov, PROVENANCE_MUTEX_TASK);
	if(unlikely(tprov->task_info.pid == 0)){
		tprov->task_info.pid = task_pid_nr(current);
	}
	if(unlikely(tprov->task_info.vpid == 0)){
		tprov->task_info.vpid = task_pid_vnr(current);
	}
	if(unlikely(tprov->task_info.cid != cid)){
		tprov->task_info.cid = cid;
	}
	if( provenance_is_recorded(tprov) && !provenance_is_name_recorded(tprov) ){ // the node has been recorded we need its name
		record_task_name(current, tprov);
	}
	return tprov;
}

static inline prov_msg_t* prov_from_vpid(pid_t pid){
	prov_msg_t* tprov;

	struct task_struct *dest = find_task_by_vpid(pid);
	if(!dest){
    return NULL;
	}

	tprov = __task_cred(dest)->provenance;
	if(!tprov){
		return NULL;
	}
	lock_node(tprov, PROVENANCE_MUTEX_TASK);
	return tprov;
}

static inline prov_msg_t* bprm_provenance( struct linux_binprm *bprm ){
	prov_msg_t* prov = bprm->cred->provenance;
	lock_node(prov, PROVENANCE_MUTEX_BPRM);
	return prov;
}

static inline void task_config_from_file(struct task_struct *task){
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
		put_prov(iprov);
	}

finished:
	put_cred(cred);
}
#endif
