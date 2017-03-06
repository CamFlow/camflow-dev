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
#ifndef _LINUX_PROVENANCE_FILTER_H
#define _LINUX_PROVENANCE_FILTER_H

#include <uapi/linux/provenance.h>
#include <provenance_cgroup.h>
#include <provenance_secctx.h>

extern bool prov_enabled;
extern bool prov_all;

#define HIT_FILTER(filter, data) ((filter & data) != 0)

extern uint64_t prov_node_filter;
extern uint64_t prov_propagate_node_filter;

#define filter_node(node) __filter_node(prov_node_filter, node)
#define filter_propagate_node(node) __filter_node(prov_propagate_node_filter, node)

/* return either or not the node should be filtered out */
static inline bool __filter_node(uint64_t filter, const union prov_msg *node)
{
	if (!prov_enabled)
		return true;
	if (provenance_is_opaque(node))
		return true;
	// we hit an element of the black list ignore
	if (HIT_FILTER(filter, node_identifier(node).type))
		return true;
	return false;
}

#define UPDATE_FILTER (SUBTYPE(RL_VERSION_PROCESS) | SUBTYPE(RL_VERSION) | SUBTYPE(RL_NAMED))
static inline bool filter_update_node(uint64_t relation_type, union prov_msg *to)
{
	if (HIT_FILTER(relation_type, UPDATE_FILTER)) // not update if relation is of above type
		return true;
	return false;
}

extern uint64_t prov_relation_filter;
extern uint64_t prov_propagate_relation_filter;

/* return either or not the relation should be filtered out */
static inline bool filter_relation(uint64_t type, uint8_t allowed)
{
	if (allowed == FLOW_DISALLOWED && HIT_FILTER(prov_relation_filter, RL_DISALLOWED))
		return true;
	if (allowed == FLOW_ALLOWED && HIT_FILTER(prov_relation_filter, RL_ALLOWED))
		return true;
	// we hit an element of the black list ignore
	if (HIT_FILTER(prov_relation_filter, type))
		return true;
	return false;
}

/* return either or not tracking should propagate */
static inline bool filter_propagate_relation(uint64_t type, uint8_t allowed)
{
	if (allowed == FLOW_DISALLOWED && HIT_FILTER(prov_propagate_relation_filter, RL_DISALLOWED))
		return true;
	if (allowed == FLOW_ALLOWED && HIT_FILTER(prov_propagate_relation_filter, RL_ALLOWED))
		return true;
	// the relation does not allow tracking propagation
	if (HIT_FILTER(prov_propagate_relation_filter, type))
		return true;
	return false;
}

static inline bool should_record_relation(uint64_t type, union prov_msg *from, union prov_msg *to, uint8_t allowed)
{
	// one of the node should not appear in the record, ignore the relation
	if (filter_node(from) || filter_node(to))
		return false;
	// should the relation appear
	if (filter_relation(type, allowed))
		return false;
	return true;
}

static inline bool prov_has_secid(union prov_msg *prov)
{
	switch (prov_type(prov)) {
	case ENT_INODE_UNKNOWN:
	case ENT_INODE_LINK:
	case ENT_INODE_FILE:
	case ENT_INODE_DIRECTORY:
	case ENT_INODE_CHAR:
	case ENT_INODE_BLOCK:
	case ENT_INODE_FIFO:
	case ENT_INODE_SOCKET:
	case ENT_INODE_MMAP:
		return true;
	default: return false;
	}
}

static inline void apply_target(union prov_msg *prov)
{
	uint8_t op;

	// track based on cgroup
	if (prov_type(prov) == ACT_TASK) {
		op = prov_cgroup_whichOP(prov->task_info.cid);
		if (unlikely(op != 0)) {
			printk(KERN_INFO "Provenance: apply cgroup filter %u.", op);
			if ((op & PROV_CGROUP_TRACKED) != 0)
				set_tracked(prov);
			if ((op & PROV_CGROUP_PROPAGATE) != 0)
				set_propagate(prov);
		}
	}
	if (prov_has_secid(prov)) {
		op = prov_secctx_whichOP(node_secid(prov));
		if (unlikely(op != 0)) {
			printk(KERN_INFO "Provenance: apply secctx filter %u.", op);
			if ((op & PROV_SEC_TRACKED) != 0)
				set_tracked(prov);
			if ((op & PROV_SEC_PROPAGATE) != 0)
				set_propagate(prov);
		}
	}
}

#endif
