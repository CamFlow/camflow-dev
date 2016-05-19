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
#include <linux/provenance.h>

#define TMPBUFLEN	12

bool prov_enabled=false;

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
      prov_print("Enabling provenance capture");
    else
      prov_print("Disabling provenance capture");
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
      prov_print("Enabling all capture");
    else
      prov_print("Disabling all capture");
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
	prov_msg_t* node = (prov_msg_t*)buf;

	if(count < sizeof(struct disc_node_struct))
	{
		return -ENOMEM;
	}

	set_node_id(node, ASSIGN_NODE_ID);
	node->disc_node_info.msg_info.type = MSG_DISC_NODE;
	prov_write(node);
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
	edge.msg_info.msg_info.type=MSG_EDGE;
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

static int __init init_prov_fs(void)
{
   struct dentry *prov_dir;

   prov_dir = securityfs_create_dir("provenance", NULL);

   securityfs_create_file("enable", 0644, prov_dir, NULL, &prov_enable_ops);
	 securityfs_create_file("all", 0644, prov_dir, NULL, &prov_all_ops);
	 securityfs_create_file("opaque", 0644, prov_dir, NULL, &prov_opaque_ops);
	 securityfs_create_file("node", 0666, prov_dir, NULL, &prov_node_ops);
	 securityfs_create_file("edge", 0666, prov_dir, NULL, &prov_edge_ops);
	 securityfs_create_file("self", 0444, prov_dir, NULL, &prov_self_ops);
	 securityfs_create_file("machine_id", 0444, prov_dir, NULL, &prov_machine_id_ops);
   return 0;
}

__initcall(init_prov_fs);
