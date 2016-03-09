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

#define MSG_STR           0
#define MSG_EDGE          1
#define MSG_TASK          2
#define MSG_INODE         3
#define MSG_LINK          4
#define MSG_UNLINK        5
#define MSG_DISC_NODE     6
#define MSG_MSG           7

#define ED_DATA           0
#define ED_CREATE         1
#define ED_PASS           2
#define ED_CHANGE         3
#define ED_MMAP           4

#define FLOW_DISALLOWED   0
#define FLOW_ALLOWED      1

#define NODE_TRACKED      1
#define NODE_NOT_TRACKED  0

#define NODE_RECORDED     1
#define NODE_UNRECORDED   0

#define NODE_OPAQUE       1
#define NODE_NOT_OPAQUE   0

#define INODE_LINKED      1
#define INODE_UNLINKED    0

#define STR_MAX_SIZE      128

typedef uint64_t event_id_t;
typedef uint64_t node_id_t;
typedef uint8_t edge_type_t;
typedef uint8_t message_type_t;

struct edge_struct{
  message_type_t message_type;
  event_id_t event_id;
  edge_type_t type;
  uint8_t allowed;
  node_id_t snd_id;
  node_id_t rcv_id;
};

struct node_struct{
  message_type_t message_type;
  event_id_t event_id;
  node_id_t node_id;
  uint8_t recorded;
  uint8_t tracked;
  uint8_t opaque;
  uint32_t uid;
  uint32_t gid;
};

struct disc_node_struct{
  message_type_t message_type;
  event_id_t event_id;
  node_id_t node_id;
};

struct task_prov_struct{
  message_type_t message_type;
  event_id_t event_id;
  node_id_t node_id;
  uint8_t recorded;
  uint8_t tracked;
  uint8_t opaque;
  uint32_t uid;
  uint32_t gid;
};

struct inode_prov_struct{
  message_type_t message_type;
  event_id_t event_id;
  node_id_t node_id;
  uint8_t recorded;
  uint8_t tracked;
  uint8_t opaque;
  uint32_t uid;
  uint32_t gid;
  uint16_t mode;
  uint32_t rdev;
};

struct msg_prov_struct{
  message_type_t message_type;
  event_id_t event_id;
  node_id_t node_id;
  long type;
};

struct msg_struct{
  message_type_t message_type;
  event_id_t event_id;
};

typedef union prov_msg{
  struct msg_struct           msg_info;
  struct node_struct          node_info;
  struct disc_node_struct     disc_node_info;
  struct task_prov_struct     task_info;
  struct inode_prov_struct    inode_info;
  struct edge_struct          edge_info;
  struct msg_prov_struct      msg_msg_info;
} prov_msg_t;

struct str_struct{
  message_type_t message_type;
  event_id_t event_id;
  size_t length;
  char str[4096];
};

struct link_struct{
  message_type_t message_type;
  event_id_t event_id;
  size_t length;
  char name[4096];
  node_id_t dir_id;
  node_id_t task_id;
  node_id_t inode_id;
};

struct unlink_struct{
  message_type_t message_type;
  event_id_t event_id;
  size_t length;
  char name[4096];
  node_id_t dir_id;
  node_id_t task_id;
  node_id_t inode_id;
};

typedef union long_msg{
  struct msg_struct           msg_info;
  struct str_struct           str_info;
  struct link_struct          link_info;
  struct unlink_struct        unlink_info;
} long_prov_msg_t;

#endif
