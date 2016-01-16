/*
*
* provenancelib.h
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
#ifndef __PROVENANCE_H
#define __PROVENANCE_H

#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>

#define MSG_MAX_SIZE 256
#define STR_MAX_SIZE (MSG_MAX_SIZE-sizeof(message_type_t)-sizeof(event_id_t)-sizeof(size_t))

typedef uint64_t event_id_t;
typedef uint64_t node_id_t;

typedef enum {MSG_EDGE=1, MSG_NODE=2, MSG_STR=3} message_type_t;

typedef enum {ED_DATA=0, ED_CREATE=1, ED_PASS=2, ED_CHANGE=3} edge_type_t;
char* edge_str[]={"data", "create", "pass", "change"};

typedef enum {ND_TASK=0, ND_FILE=1, ND_FIFO=2, ND_SOCKET=3, ND_DIRECTORY=4, ND_LINK=5, ND_CHAR_SPECIAL=6, ND_BLOCK_SPECIAL=7, ND_MESSAGE=8, ND_SHM=9, ND_SEM=10, ND_UNKOWN=11} node_type_t;
char* node_str[]={"task", "file", "fifo", "socket", "directory", "link", "char_special", "block_special", "message", "unknown"};


struct edge_struct{
  message_type_t message_id;
  event_id_t event_id;
  node_id_t snd_id;
  node_id_t rcv_id;
  bool allowed;
  edge_type_t type;
};

struct node_struct{
  message_type_t message_id;
  event_id_t event_id;
  node_id_t node_id;
  node_type_t type;
  uid_t uid;
  gid_t gid;
};

struct msg_struct{
  message_type_t message_id;
  event_id_t event_id;
};

struct str_struct{
  message_type_t message_id;
  event_id_t event_id;
  size_t length;
  char str[STR_MAX_SIZE];
};

typedef union msg{
  uint8_t raw[MSG_MAX_SIZE];
  struct msg_struct msg_info;
  struct str_struct str_info;
  struct node_struct node_info;
  struct edge_struct edge_info;
} prov_msg_t;

struct provenance_ops{
  void (*init)(void);
  void (*log_edge)(struct edge_struct*);
  void (*log_node)(struct node_struct*);
  void (*log_str)(struct str_struct*);
};

int provenance_register(struct provenance_ops* ops);
void provenance_stop(void);

#endif /* __PROVENANCE_H */
