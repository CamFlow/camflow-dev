/*
 *
 * Author: Thomas Pasquier <thomas.pasquier@cl.cam.ac.uk>
 *
 * Copyright (C) 2015-2018 University of Cambridge, Harvard University
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 */
#ifndef _PROVENANCE_RELAY_H
#define _PROVENANCE_RELAY_H

#include <linux/relay.h>
#include <linux/spinlock.h>
#include <linux/jiffies.h>

#include "provenance_filter.h"
#include "provenance_query.h"

#define PROV_RELAY_BUFF_EXP         24 // 16MB
#define PROV_RELAY_BUFF_SIZE        ((1 << PROV_RELAY_BUFF_EXP) * sizeof(uint8_t))
#define PROV_NB_SUBBUF              32
#define PROV_INITIAL_BUFF_SIZE      (1024 * 4)
#define PROV_INITIAL_LONG_BUFF_SIZE 256

extern bool relay_ready;

struct relay_list {
	struct list_head list;
	char *name;
	struct rchan *prov;
	struct rchan *long_prov;
};

extern struct list_head relay_list;

int prov_create_channel(char *buffer, size_t len);

static inline void prov_add_relay(char *name, struct rchan *prov, struct rchan *long_prov)
{
	struct relay_list *list;

	list = kzalloc(sizeof(struct relay_list), GFP_KERNEL);
	list->name = name;
	list->prov = prov;
	list->long_prov = long_prov;
	list_add_tail(&(list->list), &relay_list);
}

struct prov_boot_buffer {
	union prov_elt buffer[PROV_INITIAL_BUFF_SIZE];
	uint32_t nb_entry;
};

struct prov_long_boot_buffer {
	union long_prov_elt buffer[PROV_INITIAL_LONG_BUFF_SIZE];
	uint32_t nb_entry;
};

extern struct prov_boot_buffer *boot_buffer;

static __always_inline void prov_write(union prov_elt *msg)
{
	struct relay_list *tmp;
	union prov_elt *provtmp;

	prov_jiffies(msg) = get_jiffies_64();
	if (unlikely(!relay_ready)) {
		if (likely(boot_buffer->nb_entry < PROV_INITIAL_BUFF_SIZE)) {
			provtmp = &(boot_buffer->buffer[boot_buffer->nb_entry]);
			memcpy(provtmp, msg, sizeof(union prov_elt));
			boot_buffer->nb_entry++;
		} else
			pr_err("Provenance: boot buffer is full.\n");
	} else {
		prov_policy.prov_written = true;
		list_for_each_entry(tmp, &relay_list, list) {
			relay_write(tmp->prov, msg, sizeof(union prov_elt));
		}
	}
}


extern struct prov_long_boot_buffer *long_boot_buffer;

static inline void long_prov_write(union long_prov_elt *msg)
{
	struct relay_list *tmp;
	union long_prov_elt *provtmp;

	prov_jiffies(msg) = get_jiffies_64();
	if (unlikely(!relay_ready)) {
		if (likely(long_boot_buffer->nb_entry < PROV_INITIAL_LONG_BUFF_SIZE)) {
			provtmp = &(long_boot_buffer->buffer[long_boot_buffer->nb_entry]);
			memcpy(provtmp, msg, sizeof(union long_prov_elt));
			long_boot_buffer->nb_entry++;
		} else
			pr_err("Provenance: long boot buffer is full.\n");
	} else {
		prov_policy.prov_written = true;
		list_for_each_entry(tmp, &relay_list, list) {
			relay_write(tmp->long_prov, msg, sizeof(union long_prov_elt));
		}
	}
}

/* force sub-buffer switch */
static inline void prov_flush(void)
{
	struct relay_list *tmp;

	if (unlikely(!relay_ready)) {
		list_for_each_entry(tmp, &relay_list, list) {
			relay_flush(tmp->prov);
			relay_flush(tmp->long_prov);
		}
	}
}

static __always_inline void __write_node(prov_entry_t *node)
{
	// filtered or already recorded
	if (provenance_is_recorded(node) && !prov_policy.should_duplicate)
		return;
	// need to make sure it has not been recorded in case duplicate config is on.
	if (!prov_is_packet(node) && !provenance_is_recorded(node)) {
		node_identifier(node).machine_id = prov_machine_id;
		node_identifier(node).boot_id = prov_boot_id;
	}
	if ( provenance_is_long(node) )
		long_prov_write(node);
	else
		prov_write((union prov_elt*)node);
	set_recorded(node);
}

static inline void copy_identifier(union prov_identifier *dest, union prov_identifier *src)
{
	memcpy(dest, src, sizeof(union prov_identifier));
}

static __always_inline int __write_relation(const uint64_t type,
					    void *from,
					    void *to,
					    const struct file *file,
					    const uint64_t flags)
{
	union prov_elt relation;
	prov_entry_t *f = from;
	prov_entry_t *t = to;
	int rc = 0;

	if (!should_record_relation(type, f, t))
		return 0;

	// record the two concerned nodes
	__write_node(f);
	__write_node(t);
	// prepare the relation
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
	relation.relation_info.flags = flags;
	// run camquery framework
	rc = call_query_hooks(f, t, (prov_entry_t*)&relation);
	// finally write down the relation
	prov_write(&relation);
	return rc;
}
#endif
