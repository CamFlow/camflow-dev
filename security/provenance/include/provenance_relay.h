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
#include <linux/spinlock.h>
#include <linux/jiffies.h>

#include "provenance_filter.h"

extern struct rchan *prov_chan;
extern spinlock_t prov_chan_lock;

static inline void prov_write(prov_msg_t* msg)
{
  unsigned long flags;
  spin_lock_irqsave(&prov_chan_lock, flags);
  if(unlikely(prov_chan==NULL)) // not set yet
  {
    // TODO deal with record before relay is ready
  }else{
    prov_jiffies(msg) = get_jiffies_64();
    relay_write(prov_chan, msg, sizeof(prov_msg_t));
  }
  spin_unlock_irqrestore(&prov_chan_lock, flags);
}

extern struct rchan *long_prov_chan;
extern spinlock_t long_prov_chan_lock;

static inline void long_prov_write(long_prov_msg_t* msg){
  unsigned long flags;
  spin_lock_irqsave(&long_prov_chan_lock, flags);
  if(unlikely(long_prov_chan==NULL)) // not set yet
  {
    // TODO deal with record before relay is ready
  }else{
    prov_jiffies(msg) = get_jiffies_64();
    relay_write(long_prov_chan, msg, sizeof(long_prov_msg_t));
  }
  spin_unlock_irqrestore(&long_prov_chan_lock, flags);
}

/* force sub-buffer switch */
static inline void prov_flush( void ){
  unsigned long flags;
  spin_lock_irqsave(&prov_chan_lock, flags);
  relay_flush(prov_chan);
  spin_unlock_irqrestore(&prov_chan_lock, flags);
  spin_lock_irqsave(&long_prov_chan_lock, flags);
  relay_flush(long_prov_chan);
  spin_unlock_irqrestore(&long_prov_chan_lock, flags);
}

#endif
