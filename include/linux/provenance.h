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
#include <uapi/linux/mman.h>
#include <uapi/linux/provenance.h>

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
