/*
*
* /linux/security/ifc/fs.c
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
#include <linux/fs.h>
#include <linux/ifc.h>
#include <linux/delay.h>
#include <linux/camflow.h>
#include <linux/provenance.h>

static void mark_as_trusted(const char* name){
  struct inode* in;
  struct ifc_struct* ifc;
#ifdef CONFIG_SECURITY_PROVENANCE
  prov_msg_t* provenance;
#endif

  in = file_name_to_inode(name);
  if(!in){
    printk(KERN_ERR "IFC: could not find %s file.", name);
  }else{
    ifc = inode_get_ifc(in);
    ifc->context.trusted=IFC_TRUSTED;
#ifdef CONFIG_SECURITY_PROVENANCE
    // opaque NODES are not recorded in audit data
    provenance = inode_get_provenance(in);
    provenance->node_info.opaque=NODE_OPAQUE;
#endif
  }
}

static bool ifc_fs_is_initialised=false;

static inline void initialize(void){
  if(ifc_fs_is_initialised)
    return;
  printk(KERN_INFO "IFC: marking API files as trusted...");
  mark_as_trusted(IFC_SELF_FILE);
  mark_as_trusted(IFC_TAG_FILE);
  mark_as_trusted(IFC_PROCESS_FILE);
  mark_as_trusted(IFC_BRIDGE_FILE);
  mark_as_trusted(IFC_FILE_FILE);
  ifc_fs_is_initialised=true;
}

static inline struct ifc_context* context_from_pid(pid_t pid){
  struct task_struct *dest = find_task_by_vpid(pid);
  if(!dest)
    return NULL;
  return __task_cred(dest)->ifc;
}

static ssize_t ifc_write_self(struct file *file, const char __user *buf,
				 size_t count, loff_t *ppos)

{
  struct ifc_context *cifc = current_ifc();
  prov_msg_t* cprovenance;
  struct ifc_tag_msg *msg;
  int rv=-EINVAL;

  initialize();

  if(count < sizeof(struct ifc_tag_msg)){
    return -ENOMEM;
  }

  msg = (struct ifc_tag_msg*)buf;

  if(!ifc_tag_valid(msg->tag)){
    return -EINVAL;
  }

  if(msg->op==IFC_ADD_TAG){
    switch(msg->tag_type){
      case IFC_SECRECY:
        rv=ifc_add_tag(cifc, IFC_SECRECY, msg->tag);
        break;
      case IFC_INTEGRITY:
        rv=ifc_add_tag(cifc, IFC_INTEGRITY, msg->tag);
        break;
      case IFC_SECRECY_P:
        rv=ifc_add_privilege(cifc, IFC_SECRECY_P, msg->tag);
        break;
      case IFC_INTEGRITY_P:
        rv=ifc_add_privilege(cifc, IFC_INTEGRITY_P, msg->tag);
        break;
      case IFC_SECRECY_N:
        rv=ifc_add_privilege(cifc, IFC_SECRECY_N, msg->tag);
        break;
      case IFC_INTEGRITY_N:
        rv=ifc_add_privilege(cifc, IFC_INTEGRITY_N, msg->tag);
        break;
    }
  }else{
    switch(msg->tag_type){
      case IFC_SECRECY:
        rv=ifc_remove_tag(cifc, IFC_SECRECY, msg->tag);
        break;
      case IFC_INTEGRITY:
        rv=ifc_remove_tag(cifc, IFC_INTEGRITY, msg->tag);
        break;
      case IFC_SECRECY_P:
        rv=ifc_remove_privilege(cifc, IFC_SECRECY_P, msg->tag);
        break;
      case IFC_INTEGRITY_P:
        rv=ifc_remove_privilege(cifc, IFC_INTEGRITY_P, msg->tag);
        break;
      case IFC_SECRECY_N:
        rv=ifc_remove_privilege(cifc, IFC_SECRECY_N, msg->tag);
        break;
      case IFC_INTEGRITY_N:
        rv=ifc_remove_privilege(cifc, IFC_INTEGRITY_N, msg->tag);
        break;
    }
  }
  if(!rv){
#ifdef CONFIG_SECURITY_PROVENANCE
  // mark as tracked depending of the label state
  cprovenance = current_provenance();
  if(ifc_is_labelled(cifc)){
    cprovenance->node_info.tracked=NODE_TRACKED;
  }else{
    cprovenance->node_info.tracked=NODE_NOT_TRACKED;
  }
#endif
    return sizeof(struct ifc_tag_msg);
  }
  return rv; // return error
}

static ssize_t ifc_read_self(struct file *filp, char __user *buf,
				size_t count, loff_t *ppos)
{
  struct ifc_context *cifc = current_ifc();

  initialize();

	if(count < sizeof(struct ifc_context)){
    return -ENOMEM;
  }
  if(copy_to_user(buf, cifc, sizeof(struct ifc_context))){
    return -EAGAIN;
  }
  return sizeof(struct ifc_context);
}

static const struct file_operations ifc_self_ops = {
	.write		= ifc_write_self,
  .read     = ifc_read_self,
	.llseek		= generic_file_llseek,
};

static ssize_t ifc_write_tag(struct file *file, const char __user *buf,
				 size_t count, loff_t *ppos)

{
	return -EPERM; // does nothing for now
}

static ssize_t ifc_read_tag(struct file *filp, char __user *buf,
				size_t count, loff_t *ppos)
{
	struct ifc_context *cifc = current_ifc();
	tag_t tag;
	int rv=0;

	if(count<sizeof(tag_t))
		return -ENOMEM;

	tag = ifc_create_tag();

	rv |= ifc_add_privilege(cifc, IFC_SECRECY_P, tag);
	rv |= ifc_add_privilege(cifc, IFC_INTEGRITY_P, tag);
	rv |= ifc_add_privilege(cifc, IFC_SECRECY_N, tag);
	rv |= ifc_add_privilege(cifc, IFC_INTEGRITY_N, tag);

	if(rv<0){
		return rv;
	}

	if(copy_to_user(buf, &tag, sizeof(tag_t))){
    return -EAGAIN;
  }

	return sizeof(tag_t);
}

static const struct file_operations ifc_tag_ops = {
	.write		= ifc_write_tag,
  .read     = ifc_read_tag,
	.llseek		= generic_file_llseek,
};

static ssize_t ifc_write_process(struct file *file, const char __user *buf,
				 size_t count, loff_t *ppos)

{
	struct ifc_context *cifc = current_ifc();
	struct ifc_context *oifc = NULL;
  struct ifc_tag_msg *msg;
  int rv=-EINVAL;

  if(count < sizeof(struct ifc_tag_msg)){
    return -ENOMEM;
  }

  msg = (struct ifc_tag_msg*)buf;

  if(!ifc_tag_valid(msg->tag)){
    return -EINVAL;
  }

	oifc = context_from_pid(msg->pid);
	if(!oifc){ // did not find anything
		return -EINVAL;
	}

  if(msg->op==IFC_ADD_TAG){
    switch(msg->tag_type){
      case IFC_SECRECY_P:
				if(!ifc_contains_value(&cifc->secrecy_p, msg->tag))
					return -EPERM;
        rv=ifc_add_privilege(oifc, IFC_SECRECY_P, msg->tag);
        break;
      case IFC_INTEGRITY_P:
				if(!ifc_contains_value(&cifc->integrity_p, msg->tag))
					return -EPERM;
        rv=ifc_add_privilege(oifc, IFC_INTEGRITY_P, msg->tag);
        break;
      case IFC_SECRECY_N:
				if(!ifc_contains_value(&cifc->secrecy_n, msg->tag))
					return -EPERM;
        rv=ifc_add_privilege(oifc, IFC_SECRECY_N, msg->tag);
        break;
      case IFC_INTEGRITY_N:
				if(!ifc_contains_value(&cifc->integrity_n, msg->tag))
					return -EPERM;
        rv=ifc_add_privilege(oifc, IFC_INTEGRITY_N, msg->tag);
        break;
    }
  }
  if(!rv){
    return sizeof(struct ifc_tag_msg);
  }
  return rv; // return error
}

static ssize_t ifc_read_process(struct file *filp, char __user *buf,
				size_t count, loff_t *ppos)
{
	struct ifc_context *oifc = NULL;
  struct ifc_context_msg *msg;

  if(count < sizeof(struct ifc_context_msg)){
    return -ENOMEM;
  }

  msg = (struct ifc_context_msg*)buf;

  oifc = context_from_pid(msg->pid);
	if(!oifc){ // did not find anything
		return -EINVAL;
	}

  if(copy_to_user(&msg->context, oifc, sizeof(struct ifc_context))){
    return -EAGAIN;
  }
  return sizeof(struct ifc_context_msg);
}

static const struct file_operations ifc_process_ops = {
	.write		= ifc_write_process,
  .read     = ifc_read_process,
	.llseek		= generic_file_llseek,
};

static ssize_t ifc_write_bridge(struct file *file, const char __user *buf,
				 size_t count, loff_t *ppos)

{
  pid_t pid = task_pid_vnr(current);
  struct ifc_bridge_config *config;
  char **argv;

  if(count < sizeof(struct ifc_bridge_config))
    return -ENOMEM;

  config = (struct ifc_bridge_config*)buf;

  switch(config->op){
    case IFC_ADD_BRIDGE:
      break;
    case IFC_START_BRIDGE:
      argv=kzalloc(3*sizeof(char*), GFP_KERNEL);
      argv[0]=kzalloc(PATH_MAX, GFP_KERNEL);
      if(copy_from_user (argv[0], config->path, PATH_MAX)!=0){
        return -ENOMEM;
      }
      argv[1]=kzalloc(PARAM_MAX, GFP_KERNEL);
      if(copy_from_user (argv[1], config->param, PARAM_MAX)!=0){
        return -ENOMEM;
      }
      argv[2] = NULL;
      ifc_create_bridge(pid, &argv);
      kfree(argv[0]);
      kfree(argv[1]);
      kfree(argv);
      break;
    default:
      return -EINVAL;
  }
	return 0;
}

static ssize_t ifc_read_bridge(struct file *filp, char __user *buf,
				size_t count, loff_t *ppos)
{
  struct ifc_struct *cifc = current_ifc();
  uint32_t pid=0;
  int i=0;

  if(count<sizeof(uint32_t))
    return -EINVAL;

  if(cifc->bridge.bridge==true){
    pid = cifc->bridge.remote_pid;
  }else{
    /* we try to read the pid of the started bridge usher */
    while(i<100){
      i++;
      if(cifc->bridge.remote_pid!=0){
        pid = cifc->bridge.remote_pid;
        cifc->bridge.remote_pid = 0;
        break;
      }
      msleep(10);
    }
    if(i>=100){
      return -EAGAIN; // could not get the remote_pid
    }
  }

  if(copy_to_user(buf, &pid, sizeof(uint32_t))){
    return -EAGAIN;
  }
	return sizeof(uint32_t);
}

static const struct file_operations ifc_bridge_ops = {
	.write		= ifc_write_bridge,
  .read     = ifc_read_bridge,
	.llseek		= generic_file_llseek,
};

static ssize_t ifc_write_file(struct file *file, const char __user *buf,
				 size_t count, loff_t *ppos)

{
  struct ifc_file_change* change;
  struct inode* in;
  struct ifc_struct* ifc;
    int rv = -EINVAL;

  if(count < sizeof(struct ifc_file_change)){
    printk(KERN_INFO "IFC: Too short.");
    return -EINVAL;
  }

  change = (struct ifc_file_change*)buf;

  if(!ifc_tag_valid(change->tag)){
    return -EINVAL;
  }

  in = file_name_to_inode(change->name);
  if(!in){
    printk(KERN_ERR "IFC: could not find %s file.", change->name);
    return -EINVAL;
  }
  ifc = inode_get_ifc(in);


  if(change->op==IFC_ADD_TAG){
    switch(change->tag_type){
      case IFC_SECRECY:
        rv=ifc_add_tag_no_check(&ifc->context, IFC_SECRECY, change->tag);
        break;
      case IFC_INTEGRITY:
        rv=ifc_add_tag_no_check(&ifc->context, IFC_INTEGRITY, change->tag);
        break;
    }
  }else{
    switch(change->tag_type){
      case IFC_SECRECY:
        rv=ifc_remove_tag_no_check(&ifc->context, IFC_SECRECY, change->tag);
        break;
      case IFC_INTEGRITY:
        rv=ifc_remove_tag_no_check(&ifc->context, IFC_INTEGRITY, change->tag);
        break;
    }
  }

  return rv;
}

static ssize_t ifc_read_file(struct file *filp, char __user *buf,
				size_t count, loff_t *ppos)
{
  struct ifc_file_config *msg;
  struct inode* in;
  struct ifc_struct* ifc;

  if(count < sizeof(struct ifc_file_config)){
    printk(KERN_INFO "IFC: Too short.");
    return -EINVAL;
  }

  msg = (struct ifc_file_config*)buf;
  in = file_name_to_inode(msg->name);
  if(!in){
    printk(KERN_ERR "IFC: could not find %s file.", msg->name);
    return -EINVAL;
  }else{
    ifc = inode_get_ifc(in);
    if(copy_to_user(&msg->context, &ifc->context, sizeof(struct ifc_context))){
      printk(KERN_INFO "IFC: error copying.");
      return -ENOMEM;
    }
  }
  return sizeof(struct ifc_file_config);
}

static const struct file_operations ifc_file_ops = {
	.write		= ifc_write_file,
  .read     = ifc_read_file,
	.llseek		= generic_file_llseek,
};

#define CRYPTO_DRIVER_NAME "blowfish"
struct crypto_cipher *ifc_tfm = NULL;
static const uint64_t ifc_key=0xAEF; // not safe

int ifc_crypto_init(void){
  ifc_tfm = crypto_alloc_cipher(CRYPTO_DRIVER_NAME, 0, 0);
  if(IS_ERR((void *)ifc_tfm)){
    printk(KERN_ERR "IFC: Failed to load transform for %s: %ld\n", CRYPTO_DRIVER_NAME, PTR_ERR(ifc_tfm));
    ifc_tfm = NULL;
    return PTR_ERR((void *)ifc_tfm);
  }
  return crypto_cipher_setkey(ifc_tfm, (const u8*)&ifc_key, sizeof(uint64_t));
}

static int __init init_ifc_fs(void)
{
  int rc;
  struct dentry *ifc_dir= securityfs_create_dir("ifc", NULL);

  securityfs_create_file("self", 0666, ifc_dir, NULL, &ifc_self_ops);
  securityfs_create_file("tag", 0644, ifc_dir, NULL, &ifc_tag_ops);
  securityfs_create_file("process", 0666, ifc_dir, NULL, &ifc_process_ops);
  securityfs_create_file("bridge", 0666, ifc_dir, NULL, &ifc_bridge_ops);
  securityfs_create_file("file", 0600, ifc_dir, NULL, &ifc_file_ops);
  rc = ifc_crypto_init();
  if(rc){
    printk(KERN_ERR "IFC: cannot alloc crypto cipher. Error: %d.\n", rc);
  }
#ifdef CONFIG_SECURITY_PROVENANCE
  printk(KERN_INFO "IFC: activivating provenance capture.");
  prov_enabled = true;
#endif
  return 0;
}

__initcall(init_ifc_fs);
