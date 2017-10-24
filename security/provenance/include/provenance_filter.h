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
#ifndef _PROVENANCE_FILTER_H
#define _PROVENANCE_FILTER_H

#include <uapi/linux/provenance.h>

#include "provenance_policy.h"
#include "provenance_ns.h"

#define HIT_FILTER(filter, data) ((filter & data) != 0)

#define filter_node(node) __filter_node(prov_policy.prov_node_filter, node)
#define filter_propagate_node(node) __filter_node(prov_policy.prov_propagate_node_filter, node)

/* return either or not the node should be filtered out */
static inline bool __filter_node(uint64_t filter, prov_entry_t *node)
{
	if (!prov_policy.prov_enabled)
		return true;
	if (provenance_is_opaque(node))
		return true;
	// we hit an element of the black list ignore
	if (HIT_FILTER(filter, node_identifier(node).type))
		return true;
	return false;
}

#define UPDATE_FILTER (SUBTYPE(RL_VERSION_PROCESS) | SUBTYPE(RL_VERSION) | SUBTYPE(RL_NAMED))
static inline bool filter_update_node(const uint64_t relation_type)
{
	if (HIT_FILTER(UPDATE_FILTER, relation_type)) // not update if relation is of above type
		return true;
	return false;
}

/* return either or not the relation should be filtered out */
static inline bool filter_relation(const uint64_t type)
{
	// we hit an element of the black list ignore
	if (HIT_FILTER(prov_policy.prov_relation_filter, type))
		return true;
	return false;
}

/* return either or not tracking should propagate */
static inline bool filter_propagate_relation(uint64_t type)
{
	// the relation does not allow tracking propagation
	if (HIT_FILTER(prov_policy.prov_propagate_relation_filter, type))
		return true;
	return false;
}

static inline bool should_record_relation(const uint64_t type, union prov_elt *from, union prov_elt *to)
{
	if (filter_relation(type))
		return false;
	// one of the node should not appear in the record, ignore the relation
	if (filter_node((prov_entry_t*)from) || filter_node((prov_entry_t*)to))
		return false;
	return true;
}

static inline bool prov_has_secid(union prov_elt *prov)
{
	switch (prov_type(prov)) {
	case ACT_TASK:
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

static inline bool prov_has_uid_and_gid(union prov_elt *prov)
{
	switch (prov_type(prov)) {
	case ACT_TASK:
	case ENT_IATTR:
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

#define declare_filter_list(filter_name, type) \
	struct filter_name { \
		struct list_head list; \
		struct type filter; \
	}; \
	extern struct list_head filter_name;

#define declare_filter_whichOP(function_name, type, variable) \
	static inline uint8_t function_name(uint32_t variable) \
	{ \
		struct list_head *listentry, *listtmp; \
		struct type *tmp; \
		list_for_each_safe(listentry, listtmp, &type) {	\
			tmp = list_entry(listentry, struct type, list);	\
			if (tmp->filter.variable == variable) \
				return tmp->filter.op; \
		} \
		return 0; \
	}

#define declare_filter_delete(function_name, type, variable) \
	static inline uint8_t function_name(struct type *f) \
	{ \
		struct list_head *listentry, *listtmp; \
		struct type *tmp; \
		list_for_each_safe(listentry, listtmp, &type) {	\
			tmp = list_entry(listentry, struct type, list);	\
			if (tmp->filter.variable == f->filter.variable) { \
				list_del(listentry); \
				kfree(tmp); \
				return 0; \
			} \
		} \
		return 0; \
	}

#define declare_filter_add_or_update(function_name, type, variable) \
	static inline uint8_t function_name(struct type *f) \
	{ \
		struct list_head *listentry, *listtmp; \
		struct type *tmp; \
		list_for_each_safe(listentry, listtmp, &type) {	\
			tmp = list_entry(listentry, struct type, list);	\
			if (tmp->filter.variable == f->filter.variable) { \
				tmp->filter.op = f->filter.op; \
				return 0; \
			} \
		} \
		list_add_tail(&(f->list), &type); \
		return 0; \
	}

declare_filter_list(secctx_filters, secinfo);
declare_filter_whichOP(prov_secctx_whichOP, secctx_filters, secid);
declare_filter_delete(prov_secctx_delete, secctx_filters, secid);
declare_filter_add_or_update(prov_secctx_add_or_update, secctx_filters, secid);

declare_filter_list(user_filters, userinfo);
declare_filter_whichOP(prov_uid_whichOP, user_filters, uid);
declare_filter_delete(prov_uid_delete, user_filters, uid);
declare_filter_add_or_update(prov_uid_add_or_update, user_filters, uid);

declare_filter_list(group_filters, groupinfo);
declare_filter_whichOP(prov_gid_whichOP, group_filters, gid);
declare_filter_delete(prov_gid_delete, group_filters, gid);
declare_filter_add_or_update(prov_gid_add_or_update, group_filters, gid);

static inline void apply_target(union prov_elt *prov)
{
	uint8_t op = 0;

	// track based on ns
	if (prov_type(prov) == ACT_TASK)
		op |= prov_ns_whichOP(prov->task_info.utsns,
				      prov->task_info.ipcns,
				      prov->task_info.mntns,
				      prov->task_info.pidns,
				      prov->task_info.netns,
				      prov->task_info.cgroupns);

	if (prov_has_secid(prov))
		op |= prov_secctx_whichOP(node_secid(prov));

	if (prov_has_uid_and_gid(prov)) {
		op |= prov_uid_whichOP(node_uid(prov));
		op |= prov_gid_whichOP(node_gid(prov));
	}

	if (unlikely(op != 0)) {
		pr_info("Provenance: applying filter %u.", op);
		if ((op & PROV_SET_TRACKED) != 0)
			set_tracked(prov);
		if ((op & PROV_SET_PROPAGATE) != 0)
			set_propagate(prov);
		if ((op & PROV_SET_OPAQUE) != 0)
			set_opaque(prov);
	}
}
#endif
