/*
 *
 * Author: Thomas Pasquier <thomas.pasquier@bristol.ac.uk>
 *
 * Copyright (C) 2015-2019 University of Cambridge, Harvard University, University of Bristol
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

#define PROV_RELAY_BUFF_EXP         20
#define PROV_RELAY_BUFF_SIZE        ((1 << PROV_RELAY_BUFF_EXP) * sizeof(uint8_t))
#define PROV_NB_SUBBUF              64
#define PROV_INITIAL_BUFF_SIZE      (1024 * 16)
#define PROV_INITIAL_LONG_BUFF_SIZE 512

/*!
 * @brief A list of relay channel data structure.
 *
 * struct rchan is defined in /include/linux/relay.h Linux kernel source code.
 */
struct relay_list {
	struct list_head list;
	char *name;                     // The name of the relay channel.
	struct rchan *prov;             // Relay buffer for regular provenance entries.
	struct rchan *long_prov;        // Relay buffer for long provenance entries.
};

extern struct list_head relay_list;

int prov_create_channel(char *buffer, size_t len);
void write_boot_buffer(void);

extern bool relay_ready;

/*!
 * @brief Add an element to the tail end of the relay list, which is identified by the "extern struct list_head relay_list" above.
 * @param name Member of the element in the relay list
 * @param prov Member of the element in the relay list. This is a relay channel pointer.
 * @param long_prov Member of the element in the relay list. This is a relay channel pointer.
 *
 * @todo Failure case checking is missing.
 */
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
	struct prov_boot_buffer *next;
};

struct prov_long_boot_buffer {
	union long_prov_elt buffer[PROV_INITIAL_LONG_BUFF_SIZE];
	uint32_t nb_entry;
	struct prov_long_boot_buffer *next;
};

#define declare_insert_buffer_fcn(fcn_name, msg_type, buffer_type, max_entry) \
	static inline void fcn_name(msg_type * msg, buffer_type * buf) \
	{ \
		buffer_type *tmp = buf; \
		while (tmp->next != NULL) { \
			tmp = tmp->next; \
		} \
		if (tmp->nb_entry >= max_entry) { \
			tmp->next = kzalloc(sizeof(buffer_type), GFP_ATOMIC); \
			if (unlikely(!tmp->next)) \
				panic("Provenance: could not allocate boot_buffer."); \
			tmp = tmp->next; \
		} \
		memcpy(&(tmp->buffer[tmp->nb_entry]), msg, sizeof(msg_type)); \
		tmp->nb_entry++; \
	} \

declare_insert_buffer_fcn(insert_boot_buffer,
			  union prov_elt,
			  struct prov_boot_buffer,
			  PROV_INITIAL_BUFF_SIZE);
declare_insert_buffer_fcn(insert_long_boot_buffer,
			  union long_prov_elt,
			  struct prov_long_boot_buffer,
			  PROV_INITIAL_LONG_BUFF_SIZE);

extern struct prov_boot_buffer *boot_buffer;

/*!
 * @brief Write provenance information to relay buffer or to boot buffer if relay buffer is not ready yet during boot.
 *
 * If in an unlikely event that relay is not ready, provenance information should be written to the boot buffer.
 * However, in an unlikely event that the boot buffer is full, an error is thrown.
 * Otherwise (i.e., boot buffer is not full) provenance information is written to the next empty slot in the boot buffer.
 * If relay buffer is ready, write to relay buffer.
 * It will write to every relay buffer in the relay_list for every CamQuery query use.
 * This is because once provenance is read from a relay buffer, it will be consumed from the buffer.
 * We therefore need to write to multiple relay buffers if we want to consume/use same provenance data multiple times.
 * @param msg Provenance information to be written to either boot buffer or relay buffer.
 * @return NULL
 *
 */
static __always_inline void prov_write(union prov_elt *msg)
{
	struct relay_list *tmp;

	prov_jiffies(msg) = get_jiffies_64();
	if (unlikely(!relay_ready))
		insert_boot_buffer(msg, boot_buffer);
	else {
		prov_policy.prov_written = true;
		list_for_each_entry(tmp, &relay_list, list) {
			relay_write(tmp->prov, msg, sizeof(union prov_elt));
		}
	}
}


extern struct prov_long_boot_buffer *long_boot_buffer;

/*!
 * @brief Write long provenance information to relay buffer or to boot buffer if relay buffer is not ready yet during boot.
 *
 * This function performs the same function as "prov_write" function except that it writes a long provenance information,
 * instead of regular provenance information to the buffer.
 * @param msg Long provenance information to be written to either long boot buffer or long relay buffer.
 *
 */
static inline void long_prov_write(union long_prov_elt *msg)
{
	struct relay_list *tmp;

	prov_jiffies(msg) = get_jiffies_64();
	if (unlikely(!relay_ready)) {
		//insert_long_boot_buffer(msg, long_boot_buffer);
	} else {
		prov_policy.prov_written = true;
		list_for_each_entry(tmp, &relay_list, list) {
			relay_write(tmp->long_prov, msg, sizeof(union long_prov_elt));
		}
	}
}

/*!
 * @brief Flush every relay buffer element in the relay list.
 */
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
	if (provenance_is_recorded(node) && !prov_policy.should_duplicate)
		return;
	tighten_identifier(&get_prov_identifier(node));
	set_recorded(node);
	if ( provenance_is_long(node) )
		long_prov_write(node);
	else
		prov_write((union prov_elt*)node);
}

static __always_inline void prepare_relation(const uint64_t type,
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
	memcpy(&(relation->relation_info.snd), &get_prov_identifier(f), sizeof(union prov_identifier));
	memcpy(&(relation->relation_info.rcv), &get_prov_identifier(t), sizeof(union prov_identifier));
	if (file) {
		relation->relation_info.set = FILE_INFO_SET;
		relation->relation_info.offset = file->f_pos;
	}
	relation->relation_info.flags = flags;
	relation->msg_info.epoch = epoch;
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
	prepare_relation(type, &relation, f, t, file, flags);
	rc = call_query_hooks(f, t, (prov_entry_t*)&relation);  // Call query hooks for propagate tracking.
	prov_write(&relation);                                  // Finally record the relation (i.e., edge) to relay buffer.
	return rc;
}
#endif
