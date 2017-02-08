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

#define PROV_RELAY_BUFF_EXP         22 // 4MB
#define PROV_RELAY_BUFF_SIZE        ((1 << PROV_RELAY_BUFF_EXP) * sizeof(uint8_t))
#define PROV_NB_SUBBUF              32
#define PROV_INITIAL_BUFF_SIZE      (1024 * 4)
#define PROV_INITIAL_LONG_BUFF_SIZE 256

extern bool relay_ready;

struct prov_boot_buffer {
	union prov_msg buffer[PROV_INITIAL_BUFF_SIZE];
	uint32_t nb_entry;
};

struct prov_long_boot_buffer {
	union long_prov_msg buffer[PROV_INITIAL_LONG_BUFF_SIZE];
	uint32_t nb_entry;
};

extern struct prov_boot_buffer *boot_buffer;
extern struct rchan *prov_chan;
extern spinlock_t prov_chan_lock;

static inline void prov_write(union prov_msg *msg)
{
	unsigned long flags;

	spin_lock_irqsave(&prov_chan_lock, flags);
	prov_jiffies(msg) = get_jiffies_64();
	if (unlikely(!relay_ready)) {
		if (likely(boot_buffer->nb_entry < PROV_INITIAL_BUFF_SIZE)) {
			memcpy(&(boot_buffer->buffer[boot_buffer->nb_entry]), msg, sizeof(union prov_msg));
			boot_buffer->nb_entry++;
		} else
			printk(KERN_ERR "Provenance: boot buffer is full.\n");
	} else
		relay_write(prov_chan, msg, sizeof(union prov_msg));
	spin_unlock_irqrestore(&prov_chan_lock, flags);
}


extern struct prov_long_boot_buffer *long_boot_buffer;
extern struct rchan *long_prov_chan;
extern spinlock_t long_prov_chan_lock;

static inline void long_prov_write(union long_prov_msg *msg)
{
	unsigned long flags;

	spin_lock_irqsave(&long_prov_chan_lock, flags);
	prov_jiffies(msg) = get_jiffies_64();
	if (unlikely(!relay_ready)) {
		if (likely(long_boot_buffer->nb_entry < PROV_INITIAL_LONG_BUFF_SIZE))
			memcpy(&long_boot_buffer->buffer[long_boot_buffer->nb_entry++], msg, sizeof(union long_prov_msg));
		else
			printk(KERN_ERR "Provenance: long boot buffer is full.\n");
	} else
		relay_write(long_prov_chan, msg, sizeof(union long_prov_msg));
	spin_unlock_irqrestore(&long_prov_chan_lock, flags);
}

/* force sub-buffer switch */
static inline void prov_flush(void)
{
	unsigned long flags;

	spin_lock_irqsave(&prov_chan_lock, flags);
	relay_flush(prov_chan);
	spin_unlock_irqrestore(&prov_chan_lock, flags);
	spin_lock_irqsave(&long_prov_chan_lock, flags);
	relay_flush(long_prov_chan);
	spin_unlock_irqrestore(&long_prov_chan_lock, flags);
}

#endif
