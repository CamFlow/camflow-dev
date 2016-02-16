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

#define MSG_STR   0
#define MSG_EDGE  1
#define MSG_NODE  2

#define ED_DATA   0
#define ED_CREATE 1
#define ED_PASS   2
#define ED_CHANGE 3

#define ND_TASK   0
#define ND_INODE  1

#define FLOW_DISALLOWED   0
#define FLOW_ALLOWED      1

#define STR_MAX_SIZE 128

typedef uint64_t event_id_t;
typedef uint64_t node_id_t;
typedef uint8_t edge_type_t;
typedef uint8_t node_type_t;
typedef uint8_t message_type_t;

struct edge_struct{
  message_type_t message_type;
  event_id_t event_id;
  edge_type_t type;
  uint8_t allowed;
  node_id_t snd_id;
  dev_t snd_dev;
  node_id_t rcv_id;
  dev_t rcv_dev;
};

struct node_struct{
  message_type_t message_type;
  event_id_t event_id;
  node_type_t type;
  node_id_t node_id;
  uid_t uid;
  gid_t gid;
  dev_t dev;
};

struct msg_struct{
  message_type_t message_type;
  event_id_t event_id;
};

struct str_struct{
  message_type_t message_type;
  event_id_t event_id;
  size_t length;
  char str[STR_MAX_SIZE];
};

typedef union msg{
  struct msg_struct msg_info;
  struct str_struct str_info;
  struct node_struct node_info;
  struct edge_struct edge_info;
} prov_msg_t;

#endif
