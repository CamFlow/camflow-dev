/*
*
* /linux/security/ifc/hooks.c
*
* Author: Thomas Pasquier <tfjmp2@cam.ac.uk>
*
* Copyright (C) 2016 University of Cambridge
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License version 2, as
* published by the Free Software Foundation.
*
*/

#include <linux/kmod.h>
#include <linux/ifc.h>
#include <net/net_namespace.h>
#include <net/netlink.h>

int prepare_bridge_usher(struct subprocess_info *info, struct cred *new){
  pid_t parent_pid = (*((pid_t*)info->data));
  struct task_struct* dest;
  const struct cred* old;
  struct ifc_struct *new_ifc = new->ifc;
  if(new_ifc==NULL){
    printk(KERN_ALERT "IFC: no context attached to this process.");
    return -EFAULT;
  }

  dest = find_task_by_vpid(parent_pid);
  if(dest==NULL){
    return -EFAULT;
  }
  old = __task_cred(dest);

  new_ifc->bridge.remote_pid = parent_pid;
  new_ifc->bridge.spawner=true;
  /* set process to run with proper uid/gid */
  new->uid = old->uid;
  new->gid = old->gid;
  new->euid = old->euid;
  new->egid = old->egid;
  new->suid = old->suid;
  new->sgid = old->sgid;
  new->fsuid = old->fsuid;
  new->fsgid = old->fsgid;
  return 0;
}

int create_bridge_usher(pid_t parent_pid, char **argv){
  struct subprocess_info *sub_info;
  static char *envp[] = {
        "HOME=/",
        "TERM=linux",
        "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };

  sub_info = call_usermodehelper_setup(argv[0], argv, envp, GFP_KERNEL,
    prepare_bridge_usher, NULL, &parent_pid);

  if (sub_info == NULL){
    return -ENOMEM;
  }
  return call_usermodehelper_exec(sub_info, UMH_NO_WAIT);
}

static struct sock *nl_sk = NULL;

int ifc_bridge_send_message(void* data, size_t size)
{
  return 0;
}

static void _bridge_rcv(struct sk_buff *skb)
{
  printk(KERN_INFO "IFC: Received something");
}

enum selinux_nlgroups {
	CAMNLGRP_NONE,
#define CAMNLGRP_NONE	CAMNLGRP_NONE
	CAMNLGRP_AVC,
#define CAMNLGRP_AVC	CAMNLGRP_AVC
	__CAMNLGRP_MAX
};
#define CAMNLGRP_MAX	(__CAMNLGRP_MAX - 1)

int __init ifc_bridge_init(void)
{
  struct netlink_kernel_cfg cfg = {
    .input  = _bridge_rcv,
    .groups = CAMNLGRP_MAX,
  };
  nl_sk = netlink_kernel_create(&init_net, NETLINK_CAMFLOW_IFC_BRIDGE, &cfg);
  if(nl_sk==NULL){
    printk(KERN_ERR "IFC: Cannot create bridge netlink socket.");
    return -ENOMEM;
  }
  printk(KERN_INFO "IFC: bridge ready.");
  return 0;
}

__initcall(ifc_bridge_init);
