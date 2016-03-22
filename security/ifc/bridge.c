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
#include <linux/sched.h>
#include <net/net_namespace.h>
#include <net/netlink.h>

int prepare_bridge_usher(struct subprocess_info *info, struct cred *new){
  pid_t parent_pid = (*((pid_t*)info->data));
  struct task_struct* dest;
  const struct cred* old;
  struct ifc_struct *new_ifc = new->ifc;

  if(new_ifc==NULL){
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

int ifc_create_bridge(pid_t parent_pid, char **argv[]){
  struct subprocess_info *sub_info;
  static char *envp[] = {
        "HOME=/",
        "TERM=linux",
        "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };

  sub_info = call_usermodehelper_setup((*argv)[0], *argv, envp, GFP_KERNEL,
    prepare_bridge_usher, NULL, &parent_pid);

  if (sub_info == NULL){
    printk(KERN_INFO "IFC: Creating bridge failed setup.");
    return -ENOMEM;
  }
  return call_usermodehelper_exec(sub_info, UMH_WAIT_EXEC);
}

static struct sock *nl_sk = NULL;

static inline int send_to(struct sock* sk, const pid_t target, void* data, const size_t size){
  struct nlmsghdr *nlh;
  struct sk_buff *skb_out = nlmsg_new(size,0);
  if(!skb_out){
    return -ENOMEM;
  }
  if(target==0){
    return -EFAULT;
  }

  nlh=nlmsg_put(skb_out,0,0,NLMSG_DONE,size,0);
  if(nlh==NULL){
    printk(KERN_INFO "IFC: tailroom of the skb is insufficient to store the message header and payload.");
    return -ENOMEM;
  }
  NETLINK_CB(skb_out).dst_group = 0;
  memcpy(nlmsg_data(nlh), data, size);
  return nlmsg_unicast(sk,skb_out,target);
}

static inline bool _bridge_can_send(pid_t remote_pid){
  pid_t cpid;
  struct ifc_struct *cifc = current_ifc(), *rifc;
  struct task_struct* dest;
  const struct cred* rcred;

  /* checking permission */
  if(cifc->bridge.bridge==true){
    if(cifc->bridge.remote_pid!=remote_pid){
      printk(KERN_ALERT "IFC: bridge perm refused %u-%u.", cifc->bridge.remote_pid, remote_pid);
      return false;
    }
  }else{
    cpid = task_pid_vnr(current);
    dest = find_task_by_vpid(remote_pid);
    if(dest==NULL){
      return false;
    }
    rcred = __task_cred(dest);
    rifc = rcred->ifc;
    if(rifc->bridge.remote_pid!=cpid){
      printk(KERN_ALERT "IFC: not bridge perm refused %u-%u.", rifc->bridge.remote_pid, cpid);
      return false;
    }
  }

  return true;
}

static void _bridge_rcv(struct sk_buff *skb)
{
  int rc=0;
  struct nlmsghdr *nlh=(struct nlmsghdr*)skb->data;
  if(_bridge_can_send(nlh->nlmsg_pid)){
    rc = send_to(nl_sk, nlh->nlmsg_pid, nlmsg_data(nlh), nlmsg_len(nlh));
    if(rc){
      printk(KERN_ALERT "IFC: problem while forwarding message %d.", rc);
    }
  }else{
    printk(KERN_INFO "IFC: bridge invalid target");
  }
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
