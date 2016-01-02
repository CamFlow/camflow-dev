/*
*
* /linux/include/linux/provenance.h
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
#ifndef _LINUX_PROVENANCE_H
#define _LINUX_PROVENANCE_H

#include <linux/types.h>
#include <linux/bug.h>
#include <linux/relay.h>

#define MSG_MAX_SIZE 256

typedef uint64_t entity_id_t;
typedef uint64_t event_id_t;
typedef uint64_t nodeid_t;
typedef enum {MSG_EDGE=1, MSG_NODE=2} message_type_t;
typedef enum {FL_DATA=0, FL_CREATE=1, FL_PASS=2, FL_CHANGE=3} flow_type_t;
typedef enum {ENT_PROCESS=0, ENT_FILE=1, ENT_FIFO=2, ENT_SOCKET=3, ENT_DIRECTORY=4, ENT_LINK=5, ENT_CHAR_SPECIAL=6, ENT_BLOCK_SPECIAL=7, ENT_MESSAGE=8, ENT_SHM=9, ENT_SEM=10, ENT_UNKOWN=11} entity_type_t;

struct edge_struct{
  message_type_t message_id;
  event_id_t event_id;
  entity_id_t snd_id;
  entity_id_t rcv_id;
  bool allowed;
  flow_type_t type;
  uid_t user_id;
};

struct node_struct{
  message_type_t message_id;
  event_id_t event_id;
  nodeid_t node_id;
  entity_type_t type;
};

struct msg_struct{
  message_type_t message_id;
  event_id_t event_id;
};

typedef union node{
  uint8_t raw[MSG_MAX_SIZE];
  struct msg_struct msg_info;
  struct node_struct node_info;
  struct edge_struct edge_info;
} prov_msg_t;

extern atomic64_t prov_evt_count;

static inline event_id_t prov_next_evtid( void ){
  return (event_id_t)atomic64_inc_return(&prov_evt_count);
}

extern struct rchan *prov_chan;

static inline void prov_write(prov_msg_t* msg)
{
  BUILD_BUG_ON(sizeof(struct edge_struct)>MSG_MAX_SIZE || sizeof(struct node_struct)>MSG_MAX_SIZE);
  msg->msg_info.event_id=prov_next_evtid(); /* assign an event id */
  relay_write(prov_chan, &(msg->raw), sizeof(prov_msg_t));
}
#endif /* _LINUX_PROVENANCE_H */
