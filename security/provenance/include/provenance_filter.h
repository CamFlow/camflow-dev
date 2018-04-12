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

static inline bool filter_update_node(const uint64_t relation_type)
{
	if (relation_type == RL_VERSION_TASK)
		return true;
	if (relation_type == RL_VERSION)
		return true;
	if (relation_type == RL_NAMED)
		return true;
	return false;
}

/* return either or not the relation should be filtered out */
static inline bool filter_relation(const uint64_t type)
{
	// we hit an element of the black list ignore
	if (prov_is_derived(type)) {
		if (HIT_FILTER(prov_policy.prov_derived_filter, type))
			return true;
	} else if (prov_is_generated(type)) {
		if (HIT_FILTER(prov_policy.prov_generated_filter, type))
			return true;
	} else if (prov_is_used(type)) {
		if (HIT_FILTER(prov_policy.prov_used_filter, type))
			return true;
	} else if (prov_is_informed(type))
		if (HIT_FILTER(prov_policy.prov_informed_filter, type))
			return true;
	return false;
}

/* return either or not tracking should propagate */
static inline bool filter_propagate_relation(uint64_t type)
{
	// the relation does not allow tracking propagation
	// we hit an element of the black list ignore
	if (prov_is_derived(type)) {
		if (HIT_FILTER(prov_policy.prov_propagate_derived_filter, type))
			return true;
	} else if (prov_is_generated(type)) {
		if (HIT_FILTER(prov_policy.prov_propagate_generated_filter, type))
			return true;
	} else if (prov_is_used(type)) {
		if (HIT_FILTER(prov_policy.prov_propagate_used_filter, type))
			return true;
	} else if (prov_is_informed(type))
		if (HIT_FILTER(prov_policy.prov_propagate_informed_filter, type))
			return true;
	return false;
}

static inline bool should_record_relation(const uint64_t type,
					  prov_entry_t *from,
					  prov_entry_t *to)
{
	if (filter_relation(type))
		return false;
	// one of the node should not appear in the record, ignore the relation
	if (filter_node(from) || filter_node(to))
		return false;
	return true;
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
		list_for_each_safe(listentry, listtmp, &type) { \
			tmp = list_entry(listentry, struct type, list); \
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
		list_for_each_safe(listentry, listtmp, &type) { \
			tmp = list_entry(listentry, struct type, list); \
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
		list_for_each_safe(listentry, listtmp, &type) { \
			tmp = list_entry(listentry, struct type, list); \
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
	if (prov_type(prov) == ENT_PROC)
		op |= prov_ns_whichOP(prov->proc_info.utsns,
				      prov->proc_info.ipcns,
				      prov->proc_info.mntns,
				      prov->proc_info.pidns,
				      prov->proc_info.netns,
				      prov->proc_info.cgroupns);

	if (prov_has_secid(node_type(prov)))
		op |= prov_secctx_whichOP(node_secid(prov));

	if (prov_has_uidgid(node_type(prov))) {
		op |= prov_uid_whichOP(node_uid(prov));
		op |= prov_gid_whichOP(node_gid(prov));
	}

	if (unlikely(op != 0)) {
		if ((op & PROV_SET_TRACKED) != 0)
			set_tracked(prov);
		if ((op & PROV_SET_PROPAGATE) != 0)
			set_propagate(prov);
		if ((op & PROV_SET_OPAQUE) != 0)
			set_opaque(prov);
	}
}
#endif
