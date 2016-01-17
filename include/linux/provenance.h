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
#define STR_MAX_SIZE (MSG_MAX_SIZE-sizeof(message_type_t)-sizeof(event_id_t)-sizeof(size_t))

typedef uint64_t event_id_t;
typedef uint64_t node_id_t;
typedef enum {MSG_EDGE=1, MSG_NODE=2, MSG_STR=3} message_type_t;
typedef enum {ED_DATA=0, ED_CREATE=1, ED_PASS=2, ED_CHANGE=3} edge_type_t;
typedef enum {ND_TASK=0, ND_INODE=1} node_type_t;

struct edge_struct{
  message_type_t message_id;
  event_id_t event_id;
  node_id_t snd_id;
  dev_t snd_dev;
  node_id_t rcv_id;
  dev_t rcv_dev;
  bool allowed;
  edge_type_t type;
};

struct node_struct{
  message_type_t message_id;
  event_id_t event_id;
  node_id_t node_id;
  node_id_t type;
  uid_t uid;
  gid_t gid;
  dev_t dev;
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

extern atomic64_t prov_evt_count;

static inline event_id_t prov_next_evtid( void ){
  return (event_id_t)atomic64_inc_return(&prov_evt_count);
}

extern struct rchan *prov_chan;
extern bool prov_enabled;
extern bool prov_all;

static inline void prov_write(prov_msg_t* msg)
{
  if(!prov_chan) // not set yet
  {
    printk(KERN_ERR "Provenance: trying to write before nchan ready\n");
    return;
  }
  msg->msg_info.event_id=prov_next_evtid(); /* assign an event id */
  relay_write(prov_chan, &(msg->raw), sizeof(prov_msg_t));
}

static inline int prov_print(const char *fmt, ...)
{
  prov_msg_t msg;
  va_list args;
  va_start(args, fmt);
  /* set message type */
  msg.str_info.message_id=MSG_STR;
  memset(msg.str_info.str, 0, sizeof(msg.str_info.str));
  msg.str_info.length = vscnprintf(msg.str_info.str, sizeof(msg.str_info.str), fmt, args);
  prov_write(&msg);
  va_end(args);
  return msg.str_info.length;
}

#endif /* _LINUX_PROVENANCE_H */
