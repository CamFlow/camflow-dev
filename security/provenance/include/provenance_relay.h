/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2015-2019 University of Cambridge, Harvard University, University of Bristol
 *
 * Author: Thomas Pasquier <thomas.pasquier@bristol.ac.uk>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 */
#ifndef _PROVENANCE_RELAY_H
#define _PROVENANCE_RELAY_H

#include <linux/relay.h>
#include <linux/spinlock.h>
#include <linux/jiffies.h>
#include <linux/list.h>
#include <uapi/linux/provenance.h>

#include "provenance_filter.h"
#include "provenance_query.h"
#include "memcpy_ss.h"

#define PROV_RELAY_BUFF_EXP             20
#define PROV_RELAY_BUFF_SIZE            ((1 << PROV_RELAY_BUFF_EXP) * sizeof(uint8_t))
#define PROV_NB_SUBBUF                  64
#define PROV_INITIAL_BUFF_SIZE          (1024 * 16)
#define PROV_INITIAL_LONG_BUFF_SIZE     512

struct boot_buffer {
	struct list_head list;
	union prov_elt msg;
};

struct long_boot_buffer {
	struct list_head list;
	union long_prov_elt msg;
};

int prov_create_channel(char *buffer, size_t len);
void write_boot_buffer(void);
bool is_relay_full(struct rchan *chan, int cpu);
void prov_add_relay(char *name, struct rchan *prov, struct rchan *long_prov);
void prov_flush(void);

extern struct kmem_cache *boot_buffer_cache;
extern spinlock_t lock_buffer;
extern struct list_head buffer_list;

extern struct kmem_cache *long_boot_buffer_cache;
extern spinlock_t lock_long_buffer;
extern struct list_head long_buffer_list;

extern bool relay_ready;

void prov_write(union prov_elt *msg, size_t size);
void long_prov_write(union long_prov_elt *msg, size_t size);

static __always_inline void tighten_identifier(union prov_identifier *id)
{
	if (id->node_id.type == ENT_PACKET)
		return;
	if (id->node_id.boot_id == 0)
		id->node_id.boot_id = prov_boot_id;
	id->node_id.machine_id = prov_machine_id;
}

/*!
 * @brief Write provenance node to relay buffer.
 *
 * There are some checks before the provenance node is written to the relay buffer which can be consumed by userspace client.
 * If those checks are passed and the provenance node should be written to the relay buffer,
 * Call either "prov_write" or "long_prov_write" depending on whether the node is a regular or a long provenance node.
 * Then mark the provenance node as recorded.
 * The checks include:
 * 1. If the node has already been recorded and the user policy is set to not duplicate recorded node, then do not record again.
 * 2. If the provenance is not a packet node (which means it should have machine ID) and the provenacne is not recorded,
 *              record the machine and boot ID because during boot it is possible that these information is not ready yet (in camconfd) and need to be set again here.
 * @param node Provenance node (could be either regular or long)
 *
 */
static __always_inline void __write_node(prov_entry_t *node)
{
	BUG_ON(prov_type_is_relation(node_type(node)));

	if (provenance_is_recorded(node) && !prov_policy.should_duplicate)
		return;
	tighten_identifier(&get_prov_identifier(node));
	set_recorded(node);
	if (prov_type_is_long(node_type(node)))
		long_prov_write(node, sizeof(union long_prov_elt));
	else
		prov_write((union prov_elt *)node, sizeof(union prov_elt));
}


static __always_inline uint64_t current_provid(void)
{
	struct provenance *prov = provenance_task(current);

	if (!prov)
		return 0;
	return node_identifier(prov_elt(prov)).id;
}

static __always_inline void __prepare_relation(const uint64_t type,
					       union prov_elt *relation,
					       prov_entry_t *f,
					       prov_entry_t *t,
					       const struct file *file,
					       const uint64_t flags)
{
	memset(relation, 0, sizeof(union prov_elt)); // Allocate memory for the relation edge.
	prov_type(relation) = type;
	relation_identifier(relation).id = prov_next_relation_id();
	relation_identifier(relation).boot_id = prov_boot_id;
	relation_identifier(relation).machine_id = prov_machine_id;
	__memcpy_ss(&(relation->relation_info.snd), sizeof(union prov_identifier), &get_prov_identifier(f), sizeof(union prov_identifier));
	__memcpy_ss(&(relation->relation_info.rcv), sizeof(union prov_identifier), &get_prov_identifier(t), sizeof(union prov_identifier));
	if (file) {
		relation->relation_info.set = FILE_INFO_SET;
		relation->relation_info.offset = file->f_pos;
	}
	relation->relation_info.flags = flags;
	relation->msg_info.epoch = epoch;
	relation->relation_info.task_id = current_provid();
}

/*!
 * @brief Write provenance relation to relay buffer.
 *
 * The relation will only be recorded if no user-supplied filter is applicable to the type of the relation or the end nodes.
 * This is checked by "should_record_relation" function.
 * Two end nodes are recorded by calling "__write_node" function before the relation itself is recorded.
 * CamQuery is called for provenance runtime analysis of this provenance relation (i.e., edge) before the relation is recorded to relay.
 * @param type The type of the relation (i.e., edge)
 * @param from The source node of the provenance edge
 * @param to The destination node of the provenance edge
 * @param file Information related to LSM hooks
 * @param flags Information related to LSM hooks
 * @return 0 if no error occurred. Other error codes unknown.
 *
 */
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

	// Record the two end nodes
	__write_node(f);
	__write_node(t);
	__prepare_relation(type, &relation, f, t, file, flags);
	rc = call_query_hooks(f, t, (prov_entry_t *)&relation); // Call query hooks for propagate tracking.
	prov_write(&relation, sizeof(union prov_elt));          // Finally record the relation (i.e., edge) to relay buffer.
	return rc;
}

static __always_inline int __write_hook(const uint64_t type)
{
	union prov_elt hook;
	int rc = 0;

	memset(&hook, 0, sizeof(union prov_elt));
	prov_type(&hook) = type;
	relation_identifier(&hook).id = prov_next_relation_id();
	relation_identifier(&hook).boot_id = prov_boot_id;
	relation_identifier(&hook).machine_id = prov_machine_id;
	hook.msg_info.epoch = epoch;
	hook.relation_info.task_id = current_provid();

	prov_write(&hook, sizeof(union prov_elt));
	return rc;
}
#endif
