/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2015-2016 University of Cambridge,
 * Copyright (C) 2016-2017 Harvard University,
 * Copyright (C) 2017-2018 University of Cambridge,
 * Copyright (C) 2018-2021 University of Bristol,
 * Copyright (C) 2021-2022 University of British Columbia
 *
 * Author: Thomas Pasquier <tfjmp@cs.ubc.ca>
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

#define PROV_INITIAL_BUFF_SIZE (1024 * 16)
#define PROV_INITIAL_LONG_BUFF_SIZE 512

#define prov_relay_size(exp) ((1 << exp) * sizeof(uint8_t))

int relay_prov_init(struct relay_conf *conf);
void prov_flush(void);

struct boot_buffer {
	struct list_head list;
	union prov_elt msg;
};

struct long_boot_buffer {
	struct list_head list;
	union long_prov_elt msg;
};

extern struct kmem_cache *boot_buffer_cache;
extern spinlock_t lock_buffer;
extern struct list_head buffer_list;

extern struct kmem_cache *long_boot_buffer_cache;
extern spinlock_t lock_long_buffer;
extern struct list_head long_buffer_list;

extern bool relay_ready;
extern bool relay_initialized;

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
 * There are some checks before the provenance node is written to the relay
 * buffer which can be consumed by userspace client.
 * If those checks are passed and the provenance node should be written to the
 * relay buffer,
 * Call either "prov_write" or "long_prov_write" depending on whether the node
 * is a regular or a long provenance node.
 * Then mark the provenance node as recorded.
 * The checks include:
 * 1. If the node has already been recorded and the user policy is set to not
 * duplicate recorded node, then do not record again.
 * 2. If the provenance is not a packet node (which means it should have machine
 * ID) and the provenacne is not recorded,
 *              record the machine and boot ID because during boot it is
 * possible that these information is not ready yet (in camconfd) and need to be
 * set again here.
 * @param node Provenance node (could be either regular or long)
 *
 */
static __always_inline void __write_node(prov_entry_t *node)
{
	BUG_ON(prov_type_is_relation(node_type(node)));

	if (provenance_is_recorded(node) && !prov_policy.should_duplicate)
		return;
	tighten_identifier(&get_prov_identifier(node));
	tighten_identifier(&get_prov_name_id(node));
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
	memset(relation, 0, sizeof(union prov_elt));
	prov_type(relation) = type;
	relation_identifier(relation).id = prov_next_relation_id();
	relation_identifier(relation).boot_id = prov_boot_id;
	relation_identifier(relation).machine_id = prov_machine_id;
	__memcpy_ss(&(relation->relation_info.snd),
		    sizeof(union prov_identifier),
		    &get_prov_identifier(f),
		    sizeof(union prov_identifier));
	__memcpy_ss(&(relation->relation_info.rcv),
		    sizeof(union prov_identifier),
		    &get_prov_identifier(t),
		    sizeof(union prov_identifier));
	if (file) {
		relation->relation_info.set = FILE_INFO_SET;
		relation->relation_info.offset = file->f_pos;
	}
	relation->relation_info.flags = flags;
	rcu_read_lock();
	relation->msg_info.epoch = *epoch;
	rcu_read_unlock();
	relation->relation_info.task_id = current_provid();
}

/*!
 * @brief Write provenance relation to relay buffer.
 *
 * The relation will only be recorded if no user-supplied filter is applicable
 * to the type of the relation or the end nodes.
 * This is checked by "should_record_relation" function.
 * Two end nodes are recorded by calling "__write_node" function before the
 * relation itself is recorded.
 * CamQuery is called for provenance runtime analysis of this provenance
 * relation (i.e., edge) before the relation is recorded to relay.
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
	// Call query hooks for propagate tracking.
	rc = call_query_hooks(f, t, (prov_entry_t *)&relation);
	// Finally record the relation (i.e., edge) to relay buffer.
	prov_write(&relation, sizeof(union prov_elt));
	return rc;
}
#endif
