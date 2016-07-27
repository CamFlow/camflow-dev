/*
*
* /linux/security/provenance/fs.c
*
* Author: Thomas Pasquier <tfjmp2@cam.ac.uk>
*
* Copyright (C) 2015 University of Cambridge
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License version 2, as
* published by the Free Software Foundation.
*
*/

#include <linux/security.h>
#include <linux/camflow.h>
#include <linux/provenance.h>

#define TMPBUFLEN	12
#define DEFAULT_PROPAGATE_DEPTH 1

bool prov_enabled=false;

void provenance_mark_as_opaque(const char* name){
  struct inode* in;
  prov_msg_t* prov;

  in = file_name_to_inode(name);
  if(!in){
    printk(KERN_ERR "Provenance: could not find %s file.", name);
  }else{
    prov = inode_get_provenance(in);
    node_kern(prov).opaque=NODE_OPAQUE;
  }
}

static inline void __provenance_init_fs(void){
  // TODO fix this not working
	provenance_mark_as_opaque(PROV_ENABLE_FILE);
	provenance_mark_as_opaque(PROV_ALL_FILE);
	provenance_mark_as_opaque(PROV_OPAQUE_FILE);
	provenance_mark_as_opaque(PROV_TRACKED_FILE);
	provenance_mark_as_opaque(PROV_NODE_FILE);
	provenance_mark_as_opaque(PROV_EDGE_FILE);
	provenance_mark_as_opaque(PROV_SELF_FILE);
	provenance_mark_as_opaque(PROV_MACHINE_ID_FILE);
}

static ssize_t prov_write_enable(struct file *file, const char __user *buf,
				 size_t count, loff_t *ppos)

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
  if(new_value!=prov_enabled){
    if(new_value)
      printk(KERN_INFO "Provenance: enabling provenance capture");
    else
      printk(KERN_INFO "Provenance: disabling provenance capture");
    prov_enabled=new_value;
  }
  length=count;
out:
  free_page((unsigned long)page);
  return length;
}

static ssize_t prov_read_enable(struct file *filp, char __user *buf,
				size_t count, loff_t *ppos)
{
	char tmpbuf[TMPBUFLEN];
	ssize_t length;
  int tmp = prov_enabled;

	length = scnprintf(tmpbuf, TMPBUFLEN, "%d", tmp);
	return simple_read_from_buffer(buf, count, ppos, tmpbuf, length);
}

static const struct file_operations prov_enable_ops = {
	.write		= prov_write_enable,
  .read     = prov_read_enable,
	.llseek		= generic_file_llseek,
};

bool prov_all=false;

static ssize_t prov_write_all(struct file *file, const char __user *buf,
				 size_t count, loff_t *ppos)

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
  if(new_value!=prov_all){
    if(new_value)
      printk(KERN_INFO "Provenance: enabling all capture");
    else
      printk(KERN_INFO "Provenance: disabling all capture");
    prov_all=new_value;
  }
  length=count;
out:
  free_page((unsigned long)page);
  return length;
}

static ssize_t prov_read_all(struct file *filp, char __user *buf,
				size_t count, loff_t *ppos)
{
	char tmpbuf[TMPBUFLEN];
	ssize_t length;
  int tmp = prov_all;

	length = scnprintf(tmpbuf, TMPBUFLEN, "%d", tmp);
	return simple_read_from_buffer(buf, count, ppos, tmpbuf, length);
}

static const struct file_operations prov_all_ops = {
	.write		= prov_write_all,
  .read     = prov_read_all,
	.llseek		= generic_file_llseek,
};

static ssize_t prov_write_opaque(struct file *file, const char __user *buf,
				 size_t count, loff_t *ppos)

{
	prov_msg_t* cprov = current_provenance();
  char* page = NULL;
  ssize_t length;
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

	cprov->task_info.node_kern.opaque=tmp;
  length=count;
out:
  free_page((unsigned long)page);
  return length;
}

static ssize_t prov_read_opaque(struct file *filp, char __user *buf,
				size_t count, loff_t *ppos)
{
	prov_msg_t* cprov = current_provenance();
	char tmpbuf[TMPBUFLEN];
	ssize_t length;
  int tmp = cprov->task_info.node_kern.opaque;

	length = scnprintf(tmpbuf, TMPBUFLEN, "%d", tmp);
	return simple_read_from_buffer(buf, count, ppos, tmpbuf, length);
}

static const struct file_operations prov_opaque_ops = {
	.write		= prov_write_opaque,
  .read     = prov_read_opaque,
	.llseek		= generic_file_llseek,
};

static ssize_t prov_write_node(struct file *file, const char __user *buf,
				 size_t count, loff_t *ppos)

{
	prov_msg_t* cprov = current_provenance();
	long_prov_msg_t* node;

	if(count < sizeof(struct disc_node_struct))
		return -ENOMEM;

	node = (long_prov_msg_t*)kzalloc(sizeof(long_prov_msg_t), GFP_KERNEL);
	if(copy_from_user(node, buf, sizeof(struct disc_node_struct))){
		count = -ENOMEM;
		goto exit;
	}
	if(prov_type(node)==MSG_DISC_ENTITY || prov_type(node)==MSG_DISC_ACTIVITY || prov_type(node)==MSG_DISC_AGENT){
	  copy_node_info(&node->disc_node_info.parent, &cprov->node_info.identifier);
		long_prov_write(node);
	}else{ // the node is not of disclosed type
		count = -EINVAL;
		goto exit;
	}

	if(copy_to_user((void*)buf, node, sizeof(struct disc_node_struct))){
		count = -ENOMEM;
		goto exit;
	}

exit:
	kfree(node);
	return count;
}

static ssize_t prov_read_node(struct file *filp, char __user *buf,
				size_t count, loff_t *ppos)
{
	return -EPERM; // write only
}

static const struct file_operations prov_node_ops = {
	.write		= prov_write_node,
  .read     = prov_read_node,
	.llseek		= generic_file_llseek,
};

static ssize_t prov_write_edge(struct file *file, const char __user *buf,
				 size_t count, loff_t *ppos)
{
	prov_msg_t edge;

	if(count < sizeof(struct edge_struct))
	{
		return -ENOMEM;
	}
	if(copy_from_user(&edge, buf, sizeof(struct edge_struct))){
		return -ENOMEM;
	}
	prov_type((&edge)) = MSG_EDGE;
	prov_write(&edge);
	return count;
}

static ssize_t prov_read_edge(struct file *filp, char __user *buf,
				size_t count, loff_t *ppos)
{
	return -EPERM; // write only
}

static const struct file_operations prov_edge_ops = {
	.write		= prov_write_edge,
  .read     = prov_read_edge,
	.llseek		= generic_file_llseek,
};

static ssize_t prov_write_self(struct file *file, const char __user *buf,
				 size_t count, loff_t *ppos)
{
	return -EPERM; // read only
}

static ssize_t prov_read_self(struct file *filp, char __user *buf,
				size_t count, loff_t *ppos)
{
	prov_msg_t* tmp = (prov_msg_t*)buf;
	prov_msg_t* cprov = current_provenance();

	if(count < sizeof(struct task_prov_struct))
	{
		return -ENOMEM;
	}
	if(copy_to_user(tmp, cprov, sizeof(prov_msg_t))){
		return -EAGAIN;
	}
	record_node(cprov); // record self
	return count; // write only
}

static const struct file_operations prov_self_ops = {
	.write		= prov_write_self,
  .read     = prov_read_self,
	.llseek		= generic_file_llseek,
};

static ssize_t prov_write_machine_id(struct file *file, const char __user *buf,
				 size_t count, loff_t *ppos)
{
	uint32_t* tmp = (uint32_t*)buf;

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
	printk(KERN_INFO "Provenance: machine_id set to %u.", prov_machine_id);

	return count; // read only
}

static ssize_t prov_read_machine_id(struct file *filp, char __user *buf,
				size_t count, loff_t *ppos)
{
	uint32_t* tmp = (uint32_t*)buf;

	__provenance_init_fs();

	if(count < sizeof(uint32_t))
	{
		return -ENOMEM;
	}

	if(copy_to_user(tmp, &prov_machine_id, sizeof(uint32_t)))
	{
		return -EAGAIN;
	}
	return count; // write only
}

static const struct file_operations prov_machine_id_ops = {
	.write		= prov_write_machine_id,
  .read     = prov_read_machine_id,
	.llseek		= generic_file_llseek,
};

static ssize_t prov_write_tracked(struct file *file, const char __user *buf,
				 size_t count, loff_t *ppos)

{
	prov_msg_t* cprov = current_provenance();
  char* page = NULL;
  ssize_t length;
  int tmp;

  /* no partial write */
  if(*ppos > 0)
    return -EINVAL;

  page = (char *)get_zeroed_page(GFP_KERNEL);
  if (!page)
    return -ENOMEM;

  length=-EFAULT;
	if (copy_from_user(page, buf, count))
		goto out;

  length = -EINVAL;
  if (sscanf(page, "%d", &tmp) != 1)
		goto out;

	node_kern(cprov).tracked=tmp;
	node_kern(cprov).propagate=DEFAULT_PROPAGATE_DEPTH;
  length=count;
out:
  free_page((unsigned long)page);
  return length;
}

static ssize_t prov_read_tracked(struct file *filp, char __user *buf,
				size_t count, loff_t *ppos)
{
	prov_msg_t* cprov = current_provenance();
	char tmpbuf[TMPBUFLEN];
	ssize_t length;
  int tmp = cprov->task_info.node_kern.tracked;

	length = scnprintf(tmpbuf, TMPBUFLEN, "%d", tmp);
	return simple_read_from_buffer(buf, count, ppos, tmpbuf, length);
}

static const struct file_operations prov_tracked_ops = {
	.write		= prov_write_tracked,
  .read     = prov_read_tracked,
	.llseek		= generic_file_llseek,
};

bool prov_track_dir=false;

static ssize_t prov_write_track_dir(struct file *file, const char __user *buf,
				 size_t count, loff_t *ppos)

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
  if(new_value!=prov_track_dir){
    prov_track_dir=new_value;
  }
  length=count;
out:
  free_page((unsigned long)page);
  return length;
}

static ssize_t prov_read_track_dir(struct file *filp, char __user *buf,
				size_t count, loff_t *ppos)
{
	char tmpbuf[TMPBUFLEN];
	ssize_t length;
  int tmp = prov_track_dir;

	length = scnprintf(tmpbuf, TMPBUFLEN, "%d", tmp);
	return simple_read_from_buffer(buf, count, ppos, tmpbuf, length);
}

static const struct file_operations prov_track_dir_ops = {
	.write		= prov_write_track_dir,
  .read     = prov_read_track_dir,
	.llseek		= generic_file_llseek,
};

static int __init init_prov_fs(void)
{
   struct dentry *prov_dir;

   prov_dir = securityfs_create_dir("provenance", NULL);

   securityfs_create_file("enable", 0644, prov_dir, NULL, &prov_enable_ops);
	 securityfs_create_file("all", 0644, prov_dir, NULL, &prov_all_ops);
	 securityfs_create_file("opaque", 0644, prov_dir, NULL, &prov_opaque_ops);
	 securityfs_create_file("tracked", 0666, prov_dir, NULL, &prov_tracked_ops);
	 securityfs_create_file("node", 0666, prov_dir, NULL, &prov_node_ops);
	 securityfs_create_file("edge", 0666, prov_dir, NULL, &prov_edge_ops);
	 securityfs_create_file("self", 0444, prov_dir, NULL, &prov_self_ops);
	 securityfs_create_file("machine_id", 0444, prov_dir, NULL, &prov_machine_id_ops);
	 securityfs_create_file("dir", 0644, prov_dir, NULL, &prov_track_dir_ops);
   return 0;
}

late_initcall_sync(init_prov_fs);
