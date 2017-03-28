/*
 *
 * Author: Thomas Pasquier <thomas.pasquier@cl.cam.ac.uk>
 *
 * Copyright (C) 2015 University of Cambridge
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 */
#ifndef _LINUX_PROVENANCE_H
#define _LINUX_PROVENANCE_H

#ifdef CONFIG_SECURITY_PROVENANCE

#include <linux/slab.h>
#include <linux/types.h>
#include <linux/bug.h>
#include <linux/socket.h>
#include <uapi/linux/mman.h>
#include <uapi/linux/camflow.h>
#include <uapi/linux/provenance.h>
#include <uapi/linux/stat.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/xattr.h>

#include "provenance_filter.h"
#include "provenance_relay.h"
#include "provenance_query.h"

#define prov_next_relation_id() ((uint64_t)atomic64_inc_return(&prov_relation_id))
#define prov_next_node_id() ((uint64_t)atomic64_inc_return(&prov_node_id))

extern atomic64_t prov_relation_id;
extern atomic64_t prov_node_id;
extern struct kmem_cache *provenance_cache;

enum {
	PROVENANCE_LOCK_TASK,
	PROVENANCE_LOCK_DIR,
	PROVENANCE_LOCK_INODE,
	PROVENANCE_LOCK_MSG,
	PROVENANCE_LOCK_SHM,
	PROVENANCE_LOCK_SOCKET,
	PROVENANCE_LOCK_SOCK
};

struct provenance {
	union prov_elt msg;
	spinlock_t lock;
	uint8_t updt_mmap;
	uint8_t has_mmap;
	bool has_outgoing;
	bool initialised;
	bool saved;
};

#define prov_elt(provenance) (&(provenance->msg))
#define prov_lock(provenance) (&(provenance->lock))
#define prov_entry(provenance) ((prov_entry_t*)prov_elt(provenance))

#define ASSIGN_NODE_ID 0
extern uint32_t prov_machine_id;
extern uint32_t prov_boot_id;

static inline struct provenance *alloc_provenance(uint64_t ntype, gfp_t gfp)
{
	struct provenance *prov =  kmem_cache_zalloc(provenance_cache, gfp);

	if (!prov)
		return NULL;
	spin_lock_init(prov_lock(prov));
	prov_type(prov_elt(prov)) = ntype;
	node_identifier(prov_elt(prov)).id = prov_next_node_id();
	node_identifier(prov_elt(prov)).boot_id = prov_boot_id;
	node_identifier(prov_elt(prov)).machine_id = prov_machine_id;
	return prov;
}

static inline void free_provenance(struct provenance *prov)
{
	kmem_cache_free(provenance_cache, prov);
}

static inline void copy_node_info(union prov_identifier *dest, union prov_identifier *src)
{
	memcpy(dest, src, sizeof(union prov_identifier));
}

static inline void __record_node(union prov_elt *node)
{
	if (filter_node((prov_entry_t*)node) || provenance_is_recorded(node))  // filtered or already recorded
		return;

	set_recorded(node);
	if (unlikely(node_identifier(node).machine_id != prov_machine_id))
		node_identifier(node).machine_id = prov_machine_id;
	prov_write(node);
}

static inline void __prepare_relation(uint64_t type,
				      union prov_identifier *from,
				      union prov_identifier *to,
				      union prov_elt *relation,
				      struct file *file)
{
	prov_type(relation) = type;
	relation_identifier(relation).id = prov_next_relation_id();
	relation_identifier(relation).boot_id = prov_boot_id;
	relation_identifier(relation).machine_id = prov_machine_id;
	copy_node_info(&relation->relation_info.snd, from);
	copy_node_info(&relation->relation_info.rcv, to);
	if (file) {
		relation->relation_info.set = FILE_INFO_SET;
		relation->relation_info.offset = file->f_pos;
	}
}

static inline int __update_version(uint64_t type, struct provenance *prov)
{
	union prov_elt old_prov;
	union prov_elt relation;
	int rc = 0;

	if (!prov->has_outgoing) // there is no outgoing
		return 0;
	if (filter_update_node(type))
		return 0;

	memset(&relation, 0, sizeof(union prov_elt));
	memcpy(&old_prov, prov_elt(prov), sizeof(union prov_elt));
	memset(prov_taint(prov_elt(prov)), 0, PROV_N_BYTES);
	node_identifier(prov_elt(prov)).version++;
	clear_recorded(prov_elt(prov));
	if (node_identifier(prov_elt(prov)).type == ACT_TASK)
		__prepare_relation(RL_VERSION_PROCESS, &(old_prov.msg_info.identifier), &(prov_elt(prov)->msg_info.identifier), &relation, NULL);
	else
		__prepare_relation(RL_VERSION, &(old_prov.msg_info.identifier), &(prov_elt(prov)->msg_info.identifier), &relation, NULL);
	rc = call_query_hooks((prov_entry_t*)&old_prov, prov_entry(prov), (prov_entry_t*)&relation);
	prov_write(&relation);
	prov->has_outgoing = false; // we update there is no more outgoing edge
	prov->saved = false;
	return rc;
}

static inline int record_relation(uint64_t type,
				  struct provenance *from,
				  struct provenance *to,
				  uint8_t allowed,
				  struct file *file)
{
	union prov_elt relation;
	int rc = 0;

	// check if the nodes match some capture options
	apply_target(prov_elt(from));
	apply_target(prov_elt(to));

	if (!provenance_is_tracked(prov_elt(from)) && !provenance_is_tracked(prov_elt(to)) && !prov_all)
		return 0;
	if (!should_record_relation(type, prov_elt(from), prov_elt(to)))
		return 0;
	memset(&relation, 0, sizeof(union prov_elt));
	__record_node(prov_elt(from));
	__record_node(prov_elt(to));
	rc = __update_version(type, to);
	if (rc < 0)
		return rc;
	__record_node(prov_elt(to));
	__prepare_relation(type, &(prov_elt(from)->msg_info.identifier), &(prov_elt(to)->msg_info.identifier), &relation, file);
	rc = call_query_hooks(prov_entry(from), prov_entry(to), (prov_entry_t*)&relation);
	prov_write(&relation);
	from->has_outgoing = true; // there is an outgoing edge
	return rc;
}

static inline int flow_to_activity(uint64_t type,
				   struct provenance *from,
				   struct provenance *to,
				   uint8_t allowed,
				   struct file *file)
{
	int rc = record_relation(type, from, to, allowed, file);

	if (should_record_relation(type, prov_elt(from), prov_elt(to)))
		to->updt_mmap = 1;
	return rc;
}

static inline int flow_from_activity(uint64_t type,
				     struct provenance *from,
				     struct provenance *to,
				     uint8_t allowed,
				     struct file *file)
{
	return record_relation(type, from, to, allowed, file);
}

static inline int flow_between_entities(uint64_t type,
					struct provenance *from,
					struct provenance *to,
					uint8_t allowed,
					struct file *file)
{
	return record_relation(type, from, to, allowed, file);
}

static inline int flow_between_activities(uint64_t type,
					  struct provenance *from,
					  struct provenance *to,
					  uint8_t allowed,
					  struct file *file)
{
	return record_relation(type, from, to, allowed, file);
}

#endif
#endif
