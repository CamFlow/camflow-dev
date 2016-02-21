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

#define NODE_TRACKED      1
#define NODE_NOT_TRACKED  0

#define NODE_RECORDED     1
#define NODE_UNRECORDED   0

#define NODE_OPAQUE       1
#define NODE_NOT_OPAQUE   0

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
  uint8_t recorded;
  uint8_t tracked;
  uint8_t opaque;
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

extern atomic64_t prov_evt_count;

static inline event_id_t prov_next_evtid( void ){
  return (event_id_t)atomic64_inc_return(&prov_evt_count);
}

extern struct rchan *prov_chan;
extern bool prov_enabled;
extern bool prov_all;

static inline void prov_write(prov_msg_t* msg)
{
  if(prov_chan==NULL) // not set yet
  {
    printk(KERN_ERR "Provenance: trying to write before nchan ready\n");
    return;
  }
  msg->msg_info.event_id=prov_next_evtid(); /* assign an event id */
  relay_write(prov_chan, msg, sizeof(prov_msg_t));
}

static inline int prov_print(const char *fmt, ...)
{
  prov_msg_t msg;
  va_list args;
  va_start(args, fmt);
  /* set message type */
  msg.str_info.message_type=MSG_STR;
  msg.str_info.length = vscnprintf(msg.str_info.str, sizeof(msg.str_info.str), fmt, args);
  prov_write(&msg);
  va_end(args);
  return msg.str_info.length;
}
#endif /* _LINUX_PROVENANCE_H */
