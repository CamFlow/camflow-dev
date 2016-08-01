/*
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
#define PROV_TRACKED_FILE          "/sys/kernel/security/provenance/tracked"
#define PROV_NODE_FILE             "/sys/kernel/security/provenance/node"
#define PROV_EDGE_FILE             "/sys/kernel/security/provenance/edge"
#define PROV_SELF_FILE             "/sys/kernel/security/provenance/self"
#define PROV_MACHINE_ID_FILE       "/sys/kernel/security/provenance/machine_id"
#define PROV_TRACK_DIR_FILE        "/sys/kernel/security/provenance/dir"

#define MSG_STR               0x00000001UL
#define MSG_EDGE              0x00000002UL
#define MSG_TASK              0x00000004UL
#define MSG_INODE_UNKNOWN     0x00000008UL
#define MSG_INODE_LINK        0x00000010UL
#define MSG_INODE_FILE        0x00000020UL
#define MSG_INODE_DIRECTORY   0x00000040UL
#define MSG_INODE_CHAR        0x00000080UL
#define MSG_INODE_BLOCK       0x00000100UL
#define MSG_INODE_FIFO        0x00000200UL
#define MSG_INODE_SOCKET      0x00000400UL
#define MSG_MSG               0x00000800UL
#define MSG_SHM               0x00001000UL
#define MSG_SOCK              0x00002000UL
#define MSG_ADDR              0x00004000UL
#define MSG_SB                0x00008000UL
#define MSG_FILE_NAME         0x00010000UL
#define MSG_IFC               0x00020000UL
#define MSG_DISC_ENTITY       0x00040000UL
#define MSG_DISC_ACTIVITY     0x00080000UL
#define MSG_DISC_AGENT        0x00100000UL
#define MSG_DISC_NODE         0x00200000UL

#define ED_READ             0
#define ED_WRITE            1
#define ED_CREATE           2
#define ED_PASS             3
#define ED_CHANGE           4
#define ED_MMAP             5
#define ED_ATTACH           6
#define ED_ASSOCIATE        7
#define ED_BIND             8
#define ED_CONNECT          9
#define ED_LISTEN           10
#define ED_ACCEPT           11
#define ED_OPEN             12
#define ED_PARENT           13
#define ED_VERSION          14
#define ED_LINK             15
#define ED_NAMED            16
#define ED_IFC              17
#define ED_EXEC             18
#define ED_FORK             19
#define ED_UNKNOWN          20
#define ED_VERSION_PROCESS  21
#define ED_SEARCH           22

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

#define node_kern(prov) ((prov)->node_info.node_kern)
#define prov_type(prov) (prov)->node_info.identifier.node_id.type
#define node_identifier(node) (node)->node_info.identifier.node_id
#define edge_identifier(edge) (edge)->edge_info.identifier.edge_id

struct node_identifier{
  uint32_t type;
  uint64_t id;
  uint32_t boot_id;
  uint32_t machine_id;
  uint32_t version;
};

struct edge_identifier{
  uint32_t  type;
  uint64_t id;
  uint32_t boot_id;
  uint32_t machine_id;
};

#define PROV_IDENTIFIER_BUFFER_LENGTH sizeof(struct node_identifier)

typedef union prov_identifier{
  struct node_identifier node_id;
  struct edge_identifier edge_id;
  uint8_t buffer[PROV_IDENTIFIER_BUFFER_LENGTH];
} prov_identifier_t;

struct node_kern{
  uint8_t recorded;
  uint8_t name_recorded;
  uint8_t tracked;
  uint8_t opaque;
  uint8_t propagate;
};

struct msg_struct{
  prov_identifier_t identifier;
};

struct edge_struct{
  prov_identifier_t identifier;
  uint32_t type;
  uint8_t allowed;
  prov_identifier_t snd;
  prov_identifier_t rcv;
};

struct node_struct{
  prov_identifier_t identifier;
  struct node_kern node_kern;
};

struct task_prov_struct{
  prov_identifier_t identifier;
  struct node_kern node_kern;
  uint32_t uid;
  uint32_t gid;
};

struct inode_prov_struct{
  prov_identifier_t identifier;
  struct node_kern node_kern;
  uint32_t uid;
  uint32_t gid;
  uint16_t mode;
  uint8_t sb_uuid[16];
};

struct sb_struct{
  prov_identifier_t identifier;
  struct node_kern node_kern;
  uint8_t uuid[16];
};

struct msg_msg_struct{
  prov_identifier_t identifier;
  struct node_kern node_kern;
  long type;
};

struct shm_struct{
  prov_identifier_t identifier;
  struct node_kern node_kern;
  uint16_t mode;
};

struct sock_struct{
  prov_identifier_t identifier;
  struct node_kern node_kern;
  uint16_t type;
  uint16_t family;
  uint8_t protocol;
};

typedef union prov_msg{
  struct msg_struct           msg_info;
  struct edge_struct          edge_info;
  struct node_struct          node_info;
  struct task_prov_struct     task_info;
  struct inode_prov_struct    inode_info;
  struct msg_msg_struct       msg_msg_info;
  struct shm_struct           shm_info;
  struct sock_struct          sock_info;
  struct sb_struct            sb_info;
} prov_msg_t;

struct str_struct{
  prov_identifier_t identifier;
  size_t length;
  char str[PATH_MAX];
};

struct file_name_struct{
  prov_identifier_t identifier;
  size_t length;
  char name[PATH_MAX];
};

struct address_struct{
  prov_identifier_t identifier;
  struct sockaddr addr;
  size_t length;
};

struct ifc_context_struct{
  prov_identifier_t identifier;
  struct ifc_context context;
};

struct disc_node_struct{
  prov_identifier_t identifier;
  struct node_kern node_kern;
  size_t length;
  char content[PATH_MAX];
  prov_identifier_t parent;
};

typedef union long_msg{
  struct msg_struct           msg_info;
  struct node_struct          node_info;
  struct str_struct           str_info;
  struct file_name_struct     file_name_info;
  struct address_struct       address_info;
  struct ifc_context_struct   ifc_info;
  struct disc_node_struct     disc_node_info;
} long_prov_msg_t;

#endif
