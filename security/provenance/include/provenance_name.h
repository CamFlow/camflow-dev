/*
*
* Author: Thomas Pasquier <tfjmp@seas.harvard.edu>
*
* Copyright (C) 2016 Harvard University
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License version 2, as
* published by the Free Software Foundation.
*
*/
#ifndef _LINUX_PROVENANCE_NAME_H
#define _LINUX_PROVENANCE_NAME_H

#include <linux/file.h>
#include <uapi/linux/provenance.h>

static inline void record_node_name(prov_msg_t* node, char* name){
	long_prov_msg_t *fname_prov = alloc_long_provenance(MSG_FILE_NAME, GFP_KERNEL);
	strlcpy(fname_prov->file_name_info.name, name, PATH_MAX);
	fname_prov->file_name_info.length=strlen(fname_prov->file_name_info.name);
	long_prov_write(fname_prov);
	long_record_relation(RL_NAMED, fname_prov, node, FLOW_ALLOWED);
	free_long_provenance(fname_prov);
	set_name_recorded(node);
}

static inline void record_inode_name(struct inode *inode){
	prov_msg_t* iprov = inode_get_provenance(inode);
	struct dentry* dentry;
	char *buffer;
	char *ptr;

	if(!provenance_is_tracked(iprov)){
		return;
	}

	if(filter_node(iprov)){
		return;
	}

	dentry = d_find_alias(inode);

	if(!dentry) // we did not find a dentry, not sure if it should ever happen
		return;

	if( !provenance_is_name_recorded(iprov) ){
		buffer = (char*)kzalloc(PATH_MAX, GFP_KERNEL);
		ptr = dentry_path_raw(dentry, buffer, PATH_MAX);
		record_node_name(iprov, ptr);
		kfree(buffer);
	}
	dput(dentry);
}

static inline void record_task_name(struct task_struct *task){
	const struct cred *cred = get_task_cred(task);
	prov_msg_t* tprov;
	struct mm_struct *mm;
 	struct file *exe_file;
	char *ptr = NULL;
	char *buffer;

	if(!cred){
		return;
	}

	tprov = cred->provenance;

	if(!provenance_is_tracked(tprov)){
		goto finished;
	}

	if(filter_node(tprov)){
		goto finished;
	}

	// name already recorded
	if(provenance_is_name_recorded(tprov)){
		goto finished;
	}

	mm = get_task_mm(task);
	if (!mm){
 		goto finished;
	}
	exe_file = get_mm_exe_file(mm);
	mmput(mm);

	if(exe_file){
		buffer = (char*)kzalloc(PATH_MAX, GFP_KERNEL);
		ptr = file_path(exe_file, buffer, PATH_MAX);
		fput(exe_file);
		record_node_name(tprov, ptr);
		kfree(buffer);
	}

finished:
	put_cred(cred);
}

#endif
