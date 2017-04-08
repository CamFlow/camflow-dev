/*
 *
 * Author: Thomas Pasquier <tfjmp@seas.harvard.edu>
 *
 * Copyright (C) 2016 Harvard University
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 */
#ifndef CONFIG_SECURITY_PROVENANCE_RELAY_H
#define CONFIG_SECURITY_PROVENANCE_RELAY_H

#include <linux/relay.h>
#include <linux/spinlock.h>
#include <linux/jiffies.h>

#include "provenance_filter.h"
#include "provenance_query.h"

#define PROV_RELAY_BUFF_EXP         22 // 4MB
#define PROV_RELAY_BUFF_SIZE        ((1 << PROV_RELAY_BUFF_EXP) * sizeof(uint8_t))
#define PROV_NB_SUBBUF              32
#define PROV_INITIAL_BUFF_SIZE      (1024 * 4)
#define PROV_INITIAL_LONG_BUFF_SIZE 256

extern bool relay_ready;

struct prov_boot_buffer {
	union prov_elt buffer[PROV_INITIAL_BUFF_SIZE];
	uint32_t nb_entry;
};

struct prov_long_boot_buffer {
	union long_prov_elt buffer[PROV_INITIAL_LONG_BUFF_SIZE];
	uint32_t nb_entry;
};

extern struct prov_boot_buffer *boot_buffer;
extern struct rchan *prov_chan;

static inline void prov_write(union prov_elt *msg)
{
	prov_jiffies(msg) = get_jiffies_64();
	if (unlikely(!relay_ready)) {
		if (likely(boot_buffer->nb_entry < PROV_INITIAL_BUFF_SIZE)) {
			memcpy(&(boot_buffer->buffer[boot_buffer->nb_entry]), msg, sizeof(union prov_elt));
			boot_buffer->nb_entry++;
		} else
			pr_err("Provenance: boot buffer is full.\n");
	} else
		relay_write(prov_chan, msg, sizeof(union prov_elt));
}


extern struct prov_long_boot_buffer *long_boot_buffer;
extern struct rchan *long_prov_chan;

static inline void long_prov_write(union long_prov_elt *msg)
{
	prov_jiffies(msg) = get_jiffies_64();
	if (unlikely(!relay_ready)) {
		if (likely(long_boot_buffer->nb_entry < PROV_INITIAL_LONG_BUFF_SIZE))
			memcpy(&(long_boot_buffer->buffer[long_boot_buffer->nb_entry++]), msg, sizeof(union long_prov_elt));
		else
			pr_err("Provenance: long boot buffer is full.\n");
	} else
		relay_write(long_prov_chan, msg, sizeof(union long_prov_elt));
}

/* force sub-buffer switch */
static inline void prov_flush(void)
{
	relay_flush(prov_chan);
	relay_flush(long_prov_chan);
}

extern atomic64_t prov_relation_id;
extern atomic64_t prov_node_id;
extern uint32_t prov_machine_id;
extern uint32_t prov_boot_id;

#define prov_next_relation_id() ((uint64_t)atomic64_inc_return(&prov_relation_id))
#define prov_next_node_id() ((uint64_t)atomic64_inc_return(&prov_node_id))

static inline void write_node(union prov_elt *node)
{
	if (filter_node((prov_entry_t *)node) || provenance_is_recorded(node))  // filtered or already recorded
		return;
	set_recorded(node);
	if (unlikely(node_identifier(node).machine_id != prov_machine_id))
		node_identifier(node).machine_id = prov_machine_id;
	prov_write(node);
}

static inline void write_long_node(union long_prov_elt *node)
{
	if (provenance_is_recorded(node))
		return;
	set_recorded(node);
	long_prov_write(node);
}

static inline void copy_identifier(union prov_identifier *dest, union prov_identifier *src)
{
	memcpy(dest, src, sizeof(union prov_identifier));
}

static inline int write_relation(uint64_t type,
				      void *from,
				      void *to,
				      struct file *file)
{
	union prov_elt relation;
	prov_entry_t *f = from;
	prov_entry_t *t = to;
	int rc = 0;

	memset(&relation, 0, sizeof(union prov_elt));
	prov_type(&relation) = type;
	relation_identifier(&relation).id = prov_next_relation_id();
	relation_identifier(&relation).boot_id = prov_boot_id;
	relation_identifier(&relation).machine_id = prov_machine_id;
	copy_identifier(&relation.relation_info.snd, &get_prov_identifier(f));
	copy_identifier(&relation.relation_info.rcv, &get_prov_identifier(t));
	if (file) {
		relation.relation_info.set = FILE_INFO_SET;
		relation.relation_info.offset = file->f_pos;
	}
	rc = call_query_hooks(f, t, (prov_entry_t *)&relation);
	prov_write(&relation);
	return rc;
}
#endif
