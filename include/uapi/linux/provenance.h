/*
*
* /linux/provenance.h
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
#ifndef _UAPI_LINUX_PROVENANCE_H
#define _UAPI_LINUX_PROVENANCE_H

#ifndef __KERNEL__
#include <linux/limits.h>
#include <linux/ifc.h>
#else
#include <uapi/linux/ifc.h>
#include <uapi/linux/limits.h>
#endif

#define PROV_ENABLE_FILE           "/sys/kernel/security/provenance/enable"
#define PROV_ALL_FILE              "/sys/kernel/security/provenance/all"
#define PROV_OPAQUE_FILE           "/sys/kernel/security/provenance/opaque"
#define PROV_NODE_FILE             "/sys/kernel/security/provenance/node"
#define PROV_EDGE_FILE             "/sys/kernel/security/provenance/edge"
#define PROV_SELF_FILE             "/sys/kernel/security/provenance/self"

#define MSG_STR           0
#define MSG_EDGE          1
#define MSG_TASK          2
#define MSG_INODE         3
#define MSG_LINK          4
#define MSG_UNLINK        5
#define MSG_DISC_NODE     6
#define MSG_MSG           7
#define MSG_SHM           8
#define MSG_SOCK          9
#define MSG_ADDR          10
#define MSG_SB            11
#define MSG_FILE_NAME     12
#define MSG_IFC           13

#define ED_DATA           0
#define ED_CREATE         1
#define ED_PASS           2
#define ED_CHANGE         3
#define ED_MMAP           4
#define ED_ATTACH         5
#define ED_ASSOCIATE      6
#define ED_BIND           7
#define ED_CONNECT        8
#define ED_LISTEN         9
#define ED_ACCEPT         10
#define ED_OPEN           11
#define ED_PARENT         12
#define ED_VERSION        13

#define FLOW_DISALLOWED   0
#define FLOW_ALLOWED      1

#define NODE_TRACKED      1
#define NODE_NOT_TRACKED  0

#define NODE_RECORDED     1
#define NODE_UNRECORDED   0

#define NAME_RECORDED     1
#define NAME_UNRECORDED   0

#define NODE_OPAQUE       1
#define NODE_NOT_OPAQUE   0

#define INODE_LINKED      1
#define INODE_UNLINKED    0

#define STR_MAX_SIZE      128

struct basic_msg_info{
  uint8_t type;
  uint32_t machine_id;
  uint32_t boot_id;
  uint64_t id;
};

struct basic_node_info{
  uint64_t id;
  uint32_t boot_id;
  uint32_t machine_id;
  uint32_t version;
};

struct node_kern{
  uint8_t recorded;
  uint8_t name_recorded;
  uint8_t tracked;
  uint8_t opaque;
};

struct msg_struct{
  struct basic_msg_info msg_info;
};

struct edge_struct{
  struct basic_msg_info msg_info;
  uint8_t type;
  uint8_t allowed;
  struct basic_node_info snd;
  struct basic_node_info rcv;
};

struct node_struct{
  struct basic_msg_info msg_info;
  struct basic_node_info node_info;
  struct node_kern node_kern;
};

struct disc_node_struct{
  struct basic_msg_info msg_info;
  struct basic_node_info node_info;
  struct node_kern node_kern;
};

struct task_prov_struct{
  struct basic_msg_info msg_info;
  struct basic_node_info node_info;
  struct node_kern node_kern;
  uint32_t uid;
  uint32_t gid;
};

struct inode_prov_struct{
  struct basic_msg_info msg_info;
  struct basic_node_info node_info;
  struct node_kern node_kern;
  uint32_t uid;
  uint32_t gid;
  uint16_t mode;
  uint8_t sb_uuid[16];
};

struct sb_struct{
  struct basic_msg_info msg_info;
  uint8_t uuid[16];
};

struct msg_msg_struct{
  struct basic_msg_info msg_info;
  struct basic_node_info node_info;
  struct node_kern node_kern;
  long type;
};

struct shm_struct{
  struct basic_msg_info msg_info;
  struct basic_node_info node_info;
  struct node_kern node_kern;
  uint16_t mode;
};

struct sock_struct{
  struct basic_msg_info msg_info;
  struct basic_node_info node_info;
  struct node_kern node_kern;
  uint16_t type;
  uint16_t family;
  uint8_t protocol;
};

typedef union prov_msg{
  struct msg_struct           msg_info;
  struct node_struct          node_info;
  struct disc_node_struct     disc_node_info;
  struct task_prov_struct     task_info;
  struct inode_prov_struct    inode_info;
  struct edge_struct          edge_info;
  struct msg_msg_struct       msg_msg_info;
  struct shm_struct           shm_info;
  struct sock_struct          sock_info;
  struct sb_struct            sb_info;
} prov_msg_t;

struct str_struct{
  struct basic_msg_info msg_info;
  size_t length;
  char str[PATH_MAX];
};

struct link_struct{
  struct basic_msg_info msg_info;
  size_t length;
  char name[PATH_MAX];
  uint64_t dir_id;
  uint64_t task_id;
  uint64_t inode_id;
};

struct file_name_struct{
  struct basic_msg_info msg_info;
  size_t length;
  char name[PATH_MAX];
  uint64_t inode_id;
};

struct unlink_struct{
  struct basic_msg_info msg_info;
  size_t length;
  char name[PATH_MAX];
  uint64_t dir_id;
  uint64_t task_id;
  uint64_t inode_id;
};

struct address_struct{
  struct basic_msg_info msg_info;
  struct basic_node_info sock_info;
  size_t length;
  struct sockaddr addr;
};

struct ifc_context_struct{
  struct basic_msg_info msg_info;
  struct basic_node_info node_info;
  uint32_t version;
  struct ifc_context context;
};

typedef union long_msg{
  struct msg_struct           msg_info;
  struct str_struct           str_info;
  struct link_struct          link_info;
  struct unlink_struct        unlink_info;
  struct file_name_struct     file_name_info;
  struct address_struct       address_info;
  struct ifc_context_struct   ifc_info;
} long_prov_msg_t;

#endif
