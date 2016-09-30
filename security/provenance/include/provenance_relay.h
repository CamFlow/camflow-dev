/*
*
* Author: Thomas Pasquier <tfjmp@seas.harvard.edu>
*
* Copyright (C) 2016 Harvard University
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License version 2, as
* published by the Free Software Foundation; either version 2 of the License, or
*	(at your option) any later version.
*
*/
#ifndef _LINUX_PROVENANCE_RELAY_H
#define _LINUX_PROVENANCE_RELAY_H

#include <linux/relay.h>
#include "provenance_filter.h"

extern struct rchan *prov_chan;
extern struct rchan *long_prov_chan;

static inline void prov_write(prov_msg_t* msg)
{
  if(unlikely(prov_chan==NULL)) // not set yet
  {
    printk(KERN_ERR "Provenance: trying to write before nchan ready\n");
    return;
  }
  relay_write(prov_chan, msg, sizeof(prov_msg_t));
}

static inline void long_prov_write(long_prov_msg_t* msg){
  if(unlikely(long_prov_chan==NULL)) // not set yet
  {
    printk(KERN_ERR "Provenance: trying to write before nchan ready\n");
    return;
  }
  relay_write(long_prov_chan, msg, sizeof(long_prov_msg_t));
}

/* force sub-buffer switch */
static inline void prov_flush( void ){
  relay_flush(prov_chan);
  relay_flush(long_prov_chan);
}

#endif
