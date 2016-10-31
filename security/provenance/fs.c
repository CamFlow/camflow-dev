/*
*
* Author: Thomas Pasquier <thomas.pasquier@cl.cam.ac.uk>
*
* Copyright (C) 2015 University of Cambridge
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License version 2, as
* published by the Free Software Foundation; either version 2 of the License, or
*	(at your option) any later version.
*
*/

#include <linux/security.h>
#include <linux/camflow.h>

#include "provenance.h"
#include "provenance_inode.h"
#include "provenance_task.h"
#include "camflow_utils.h"

#define TMPBUFLEN	12

#define declare_file_operations(ops_name, write_op, read_op) static const struct file_operations ops_name = { \
		.write		= write_op,\
	  .read     = read_op,\
		.llseek		= generic_file_llseek,\
	}

static ssize_t no_read(struct file *filp, char __user *buf,
				size_t count, loff_t *ppos)
{
	return -EPERM; // write only
}

/*static ssize_t no_write(struct file *file, const char __user *buf,
				 size_t count, loff_t *ppos)
{
	return -EPERM; // read only
}*/ // not used anymore

static inline void __init_opaque(void){
	provenance_mark_as_opaque(PROV_ENABLE_FILE);
	provenance_mark_as_opaque(PROV_ALL_FILE);
	provenance_mark_as_opaque(PROV_NODE_FILE);
	provenance_mark_as_opaque(PROV_RELATION_FILE);
	provenance_mark_as_opaque(PROV_SELF_FILE);
	provenance_mark_as_opaque(PROV_MACHINE_ID_FILE);
	provenance_mark_as_opaque(PROV_NODE_FILTER_FILE);
	provenance_mark_as_opaque(PROV_RELATION_FILTER_FILE);
	provenance_mark_as_opaque(PROV_PROPAGATE_NODE_FILTER_FILE);
	provenance_mark_as_opaque(PROV_PROPAGATE_RELATION_FILTER_FILE);
	provenance_mark_as_opaque(PROV_FLUSH_FILE);
	provenance_mark_as_opaque(PROV_FILE_FILE);
	provenance_mark_as_opaque(PROV_PROCESS_FILE);
}

static inline ssize_t __write_flag(struct file *file, const char __user *buf,
				 size_t count, loff_t *ppos, bool *flag)

{
  char* page = NULL;
  ssize_t length;
  bool new_value;
  int tmp;

  /* no partial write */
  if(*ppos > 0)
    return -EINVAL;

  if(__kuid_val(current_euid())!=0)
    return -EPERM;

  page = (char *)get_zeroed_page(GFP_KERNEL);
  if (!page)
    return -ENOMEM;

  length=-EFAULT;
	if (copy_from_user(page, buf, count))
		goto out;

  length = -EINVAL;
  if (sscanf(page, "%d", &tmp) != 1)
		goto out;

  new_value=tmp;
  (*flag)=new_value;
  length=count;
out:
  free_page((unsigned long)page);
  return length;
}

static ssize_t __read_flag(struct file *filp, char __user *buf,
				size_t count, loff_t *ppos, bool flag)
{
	char tmpbuf[TMPBUFLEN];
	ssize_t length;
  int tmp = flag;

	length = scnprintf(tmpbuf, TMPBUFLEN, "%d", tmp);
	return simple_read_from_buffer(buf, count, ppos, tmpbuf, length);
}

#define declare_write_flag_fcn(fcn_name, flag) static ssize_t fcn_name (struct file *file, const char __user *buf, size_t count, loff_t *ppos){\
		return __write_flag(file, buf, count, ppos, &flag);\
	}
#define declare_read_flag_fcn(fcn_name, flag) static ssize_t fcn_name (struct file *filp, char __user *buf, size_t count, loff_t *ppos){\
		return __read_flag(filp, buf, count, ppos, flag);\
	}

bool prov_enabled=true;
declare_write_flag_fcn(prov_write_enable, prov_enabled);
declare_read_flag_fcn(prov_read_enable, prov_enabled);
declare_file_operations(prov_enable_ops, prov_write_enable, prov_read_enable);

#ifdef CONFIG_SECURITY_PROVENANCE_WHOLE_SYSTEM
bool prov_all=true;
#else
bool prov_all=false;
#endif
declare_write_flag_fcn(prov_write_all, prov_all);
declare_read_flag_fcn(prov_read_all, prov_all);
declare_file_operations(prov_all_ops, prov_write_all, prov_read_all);

static ssize_t prov_write_machine_id(struct file *file, const char __user *buf,
				 size_t count, loff_t *ppos)
{
	uint32_t* tmp = (uint32_t*)buf;

	// ideally should be decoupled from set machine id
	__init_opaque();

	if(__kuid_val(current_euid())!=0) // only allowed for root
    return -EPERM;

	if(count < sizeof(uint32_t))
	{
		return -ENOMEM;
	}

	if(copy_from_user(&prov_machine_id, tmp, sizeof(uint32_t)))
	{
		return -EAGAIN;
	}

	return count; // read only
}

static ssize_t prov_read_machine_id(struct file *filp, char __user *buf,
				size_t count, loff_t *ppos)
{
	if(count < sizeof(uint32_t))
	{
		return -ENOMEM;
	}

	if(copy_to_user(buf, &prov_machine_id, sizeof(uint32_t)))
	{
		return -EAGAIN;
	}
	return count;
}

declare_file_operations(prov_machine_id_ops, prov_write_machine_id, prov_read_machine_id);

static ssize_t prov_write_node(struct file *file, const char __user *buf,
				 size_t count, loff_t *ppos)

{
	prov_msg_t* cprov = task_provenance();
	long_prov_msg_t* node;

	if(count < sizeof(struct disc_node_struct)){
		count = -ENOMEM;
		goto out;
	}

	node = (long_prov_msg_t*)kzalloc(sizeof(long_prov_msg_t), GFP_KERNEL); // revert back to cache if causes performance issue
	if(copy_from_user(node, buf, sizeof(struct disc_node_struct))){
		count = -ENOMEM;
		goto out;
	}
	if(prov_type(node)==ENT_DISC || prov_type(node)==ACT_DISC || prov_type(node)==AGT_DISC){
		__record_node(cprov);
		copy_node_info(&node->disc_node_info.parent, &cprov->node_info.identifier);
		node_identifier(node).id=prov_next_node_id();
	  node_identifier(node).boot_id=prov_boot_id;
	  node_identifier(node).machine_id=prov_machine_id;
		long_prov_write(node);
	}else{ // the node is not of disclosed type
		count = -EINVAL;
		goto out;
	}

	if(copy_to_user((void*)buf, &node, sizeof(struct disc_node_struct))){
		count = -ENOMEM;
		goto out;
	}

out:
	put_prov(cprov);
	kfree(node);
	return count;
}

declare_file_operations(prov_node_ops, prov_write_node, no_read);

static ssize_t prov_write_relation(struct file *file, const char __user *buf,
				 size_t count, loff_t *ppos)
{
	prov_msg_t relation;

	if(count < sizeof(struct relation_struct))
	{
		return -ENOMEM;
	}
	if(copy_from_user(&relation, buf, sizeof(struct relation_struct))){
		return -ENOMEM;
	}
	prov_write(&relation);
	return count;
}

declare_file_operations(prov_relation_ops, prov_write_relation, no_read);

static ssize_t prov_write_self(struct file *file, const char __user *buf,
				 size_t count, loff_t *ppos)
{
	struct prov_self_config msg;
  prov_msg_t* prov = task_provenance();
	prov_msg_t* setting;
	uint8_t op;
	int rtn=sizeof(struct prov_self_config);

  if(count < sizeof(struct prov_self_config)){
    rtn = -EINVAL;
		goto out;
  }
	if( copy_from_user(&msg, buf, sizeof(struct prov_self_config)) ){
		rtn = -ENOMEM;
		goto out;
	}

	setting = &(msg.prov);
	op = msg.op;

	if( (op & PROV_SET_TRACKED)!=0 ){
		if( provenance_is_tracked(setting) ){
			set_tracked(prov);
		}else{
			clear_tracked(prov);
		}
	}

	if( (op & PROV_SET_OPAQUE)!=0 ){
		if( provenance_is_opaque(setting) ){
			set_opaque(prov);
		}else{
			clear_opaque(prov);
		}
	}

	if( (op & PROV_SET_PROPAGATE)!=0 ){
		if( provenance_propagate(setting) ){
			set_propagate(prov);
		}else{
			clear_propagate(prov);
		}
	}

	if( (op & PROV_SET_TAINT)!=0 ){
		prov_bloom_merge( prov_taint(prov), prov_taint(setting) );
	}

out:
	put_prov(prov);
  return rtn;
}

static ssize_t prov_read_self(struct file *filp, char __user *buf,
				size_t count, loff_t *ppos)
{
	prov_msg_t* tmp = (prov_msg_t*)buf;
	prov_msg_t* cprov = task_provenance();

	if(count < sizeof(struct task_prov_struct))
	{
		count = -ENOMEM;
		goto out;
	}
	if(copy_to_user(tmp, cprov, sizeof(prov_msg_t))){
		count = -EAGAIN;
		goto out;
	}

out:
	put_prov(cprov);
	return count; // write only
}

declare_file_operations(prov_self_ops, prov_write_self, prov_read_self);

static inline ssize_t __write_filter(struct file *file, const char __user *buf,
				 size_t count, uint64_t* filter){
	struct prov_filter* setting;

	if(__kuid_val(current_euid())!=0){
	 return -EPERM;
	}

	if(count < sizeof(struct prov_filter)){
	 return -ENOMEM;
	}

	setting = (struct prov_filter*)buf;

	if(setting->add!=0){
		(*filter)|=setting->filter&setting->mask;
	}else{
		(*filter)&=~(setting->filter&setting->mask);
	}
	return count;
}

static inline ssize_t __read_filter(struct file *filp, char __user *buf,
				size_t count, uint64_t filter){
	if(count < sizeof(uint64_t)){
	  return -ENOMEM;
	}

	if(copy_to_user(buf, &filter, sizeof(uint64_t)))
	{
		return -EAGAIN;
	}
	return count;
}

#define declare_write_filter_fcn(fcn_name, filter) static ssize_t fcn_name ( struct file *file, const char __user *buf,size_t count, loff_t *ppos ){\
		return __write_filter(file, buf, count, &filter);\
	}
#define declare_reader_filter_fcn(fcn_name, filter) static ssize_t fcn_name (struct file *filp, char __user *buf, size_t count, loff_t *ppos) { \
		return __read_filter(filp, buf, count, filter);\
	}

uint64_t prov_node_filter;
declare_write_filter_fcn(prov_write_node_filter, prov_node_filter);
declare_reader_filter_fcn(prov_read_node_filter, prov_node_filter);
declare_file_operations(prov_node_filter_ops, prov_write_node_filter, prov_read_node_filter);

uint64_t prov_relation_filter = 0;
declare_write_filter_fcn(prov_write_relation_filter, prov_relation_filter);
declare_reader_filter_fcn(prov_read_relation_filter, prov_relation_filter);
declare_file_operations(prov_relation_filter_ops, prov_write_relation_filter, prov_read_relation_filter);

uint64_t prov_propagate_node_filter = 0;
declare_write_filter_fcn(prov_write_propagate_node_filter, prov_propagate_node_filter);
declare_reader_filter_fcn(prov_read_propagate_node_filter, prov_propagate_node_filter);
declare_file_operations(prov_propagate_node_filter_ops, prov_write_propagate_node_filter, prov_read_propagate_node_filter);

uint64_t prov_propagate_relation_filter = 0;
declare_write_filter_fcn(prov_write_propagate_relation_filter, prov_propagate_relation_filter);
declare_reader_filter_fcn(prov_read_propagate_relation_filter, prov_propagate_relation_filter);
declare_file_operations(prov_propagate_relation_filter_ops, prov_write_propagate_relation_filter, prov_read_propagate_relation_filter);

static ssize_t prov_write_flush(struct file *file, const char __user *buf,
				 size_t count, loff_t *ppos)

{
	if(__kuid_val(current_euid())!=0) // only allowed for root
    return -EPERM;

  prov_flush();
	return 0;
}

declare_file_operations(prov_flush_ops, prov_write_flush, no_read);

static ssize_t prov_write_file(struct file *file, const char __user *buf,
				 size_t count, loff_t *ppos)
{
	struct prov_file_config *msg;
  struct inode* in;
  prov_msg_t* prov;
	prov_msg_t* setting;
	uint8_t op;

  if(__kuid_val(current_euid())!=0)
    return -EPERM;

  if(count < sizeof(struct prov_file_config)){
    return -EINVAL;
  }

  msg = (struct prov_file_config*)buf;

  in = file_name_to_inode(msg->name);
  if(!in){
    printk(KERN_ERR "Provenance: could not find %s file.", msg->name);
    return -EINVAL;
  }
	op = msg->op;
	setting = &msg->prov;
  prov = inode_provenance(in);

	if( (op & PROV_SET_TRACKED)!=0 ){
		if( provenance_is_tracked(setting) ){
			set_tracked(prov);
		}else{
			clear_tracked(prov);
		}
	}

	if( (op & PROV_SET_OPAQUE)!=0 ){
		if( provenance_is_opaque(setting) ){
			set_opaque(prov);
		}else{
			clear_opaque(prov);
		}
	}

	if( (op & PROV_SET_PROPAGATE)!=0 ){
		if( provenance_propagate(setting) ){
			set_propagate(prov);
		}else{
			clear_propagate(prov);
		}
	}

	if( (op & PROV_SET_TAINT)!=0 ){
		prov_bloom_merge( prov_taint(prov), prov_taint(setting) );
	}
	put_prov(prov);
  return sizeof(struct prov_file_config);
}

static ssize_t prov_read_file(struct file *filp, char __user *buf,
				size_t count, loff_t *ppos)
{
  struct prov_file_config *msg;
  struct inode* in;
  prov_msg_t* prov;
	int rtn=sizeof(struct prov_file_config);

  if(count < sizeof(struct prov_file_config)){
    return -EINVAL;
  }

  msg = (struct prov_file_config*)buf;
  in = file_name_to_inode(msg->name);
  if(!in){
    printk(KERN_ERR "Provenance: could not find %s file.", msg->name);
    return -EINVAL;
  }

  prov = inode_provenance(in);
  if(copy_to_user(&msg->prov, prov, sizeof(prov_msg_t))){
    rtn = -ENOMEM;
		goto out; // a bit superfluous, but would avoid error if code changes
  }
out:
	put_prov(prov);
  return rtn;
}

declare_file_operations(prov_file_ops, prov_write_file, prov_read_file);

static ssize_t prov_write_process(struct file *file, const char __user *buf,
				 size_t count, loff_t *ppos)
{
	struct prov_process_config *msg;
	prov_msg_t* prov;
	prov_msg_t* setting;
	uint8_t op;

	if(__kuid_val(current_euid())!=0)
    return -EPERM;

  if(count < sizeof(struct prov_process_config)){
    return -EINVAL;
  }

  msg = (struct prov_process_config*)buf;

	setting = &(msg->prov);
	op = msg->op;

	prov = prov_from_vpid(msg->vpid);
	if(prov==NULL){
		return -EINVAL;
	}

	if( (op & PROV_SET_TRACKED)!=0 ){
		if( provenance_is_tracked(setting) ){
			set_tracked(prov);
		}else{
			clear_tracked(prov);
		}
	}

	if( (op & PROV_SET_OPAQUE)!=0 ){
		if( provenance_is_opaque(setting) ){
			set_opaque(prov);
		}else{
			clear_opaque(prov);
		}
	}

	if( (op & PROV_SET_PROPAGATE)!=0 ){
		if( provenance_propagate(setting) ){
			set_propagate(prov);
		}else{
			clear_propagate(prov);
		}
	}

	if( (op & PROV_SET_TAINT)!=0 ){
		prov_bloom_merge( prov_taint(prov), prov_taint(setting) );
	}
	put_prov(prov);
  return sizeof(struct prov_process_config);
}

static ssize_t prov_read_process(struct file *filp, char __user *buf,
				size_t count, loff_t *ppos)
{
	struct prov_process_config *msg;
  prov_msg_t* prov;
	int rtn=sizeof(struct prov_process_config);

  if(count < sizeof(struct prov_process_config)){
    return -EINVAL;
  }

  msg = (struct prov_process_config*)buf;

	prov = prov_from_vpid(msg->vpid);
	if(prov==NULL){
		return -EINVAL;
	}

	if(copy_to_user(&msg->prov, prov, sizeof(prov_msg_t))){
    rtn = -ENOMEM;
		goto out; // a bit superfluous, but would avoid error if code changes
  }
out:
	put_prov(prov);
  return rtn;
}

declare_file_operations(prov_process_ops, prov_write_process, prov_read_process);

static int __init init_prov_fs(void)
{
   struct dentry *prov_dir;

   prov_dir = securityfs_create_dir("provenance", NULL);

   securityfs_create_file("enable", 0644, prov_dir, NULL, &prov_enable_ops);
	 securityfs_create_file("all", 0644, prov_dir, NULL, &prov_all_ops);
	 securityfs_create_file("node", 0666, prov_dir, NULL, &prov_node_ops);
	 securityfs_create_file("relation", 0666, prov_dir, NULL, &prov_relation_ops);
	 securityfs_create_file("self", 0666, prov_dir, NULL, &prov_self_ops);
	 securityfs_create_file("machine_id", 0444, prov_dir, NULL, &prov_machine_id_ops);
	 securityfs_create_file("node_filter", 0644, prov_dir, NULL, &prov_node_filter_ops);
	 securityfs_create_file("relation_filter", 0644, prov_dir, NULL, &prov_relation_filter_ops);
	 securityfs_create_file("propagate_node_filter", 0644, prov_dir, NULL, &prov_propagate_node_filter_ops);
	 securityfs_create_file("propagate_relation_filter", 0644, prov_dir, NULL, &prov_propagate_relation_filter_ops);
	 securityfs_create_file("flush", 0600, prov_dir, NULL, &prov_flush_ops);
	 securityfs_create_file("file", 0644, prov_dir, NULL, &prov_file_ops);
	 securityfs_create_file("process", 0644, prov_dir, NULL, &prov_process_ops);

	 printk(KERN_INFO "Provenance fs ready.\n");

   return 0;
}

core_initcall(init_prov_fs);
