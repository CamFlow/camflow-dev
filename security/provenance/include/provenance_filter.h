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
#ifndef _PROVENANCE_FILTER_H
#define _PROVENANCE_FILTER_H

#include <uapi/linux/provenance.h>
#include <uapi/linux/provenance_fs.h>

#include "provenance_policy.h"
#include "provenance_ns.h"

#define HIT_FILTER(filter, data)        ((filter & data) != 0)

#define filter_node(node)               __filter_node(prov_policy.prov_node_filter, node)
#define filter_propagate_node(node)     __filter_node(prov_policy.prov_propagate_node_filter, node)

/*!
 * @brief This function decides whether or not a node should be filtered.
 *
 * The decision is based on three criteria:
 * 1. If provenance capture is not enable, then the node should be filtered out.
 * 2. If the node is set to be opaque, then it should be filtered out.
 * 3. If the node hits the given filter, then it should be filtered out.
 * If one of the above criteria is met, then the node should be filtered out.
 * Otherwise, it should be recorded.
 * @param filter The supplied filter to be checked against the node.
 * @param node The node in question (i.e., whether or not to be filtered).
 * @return true (i.e., should be filtered out) or false (i.e., should not be filtered out).
 *
 */
static __always_inline bool __filter_node(uint64_t filter, prov_entry_t *node)
{
	if (!prov_policy.prov_enabled)
		return true;
	if (provenance_is_opaque(node))
		return true;
	if (HIT_FILTER(filter, node_identifier(node).type))
		return true;
	return false;
}

/*!
 * @brief If the relation type is VERSION_TASK or VERSION or NAMED or NAMED_PROCESS, updating a node's version is unnecessary.
 * @param relation_type The type of the relation (i.e., edge)
 *
 */
static __always_inline bool filter_update_node(const uint64_t relation_type)
{
	if (relation_type == RL_VERSION_TASK)
		return true;
	if (relation_type == RL_VERSION)
		return true;
	if (relation_type == RL_NAMED)
		return true;
	return false;
}

/*!
 * @brief This function decides whether or not a relation (i.e., edge) should be filtered.
 *
 * Based on the user supplied filter, a relation (i.e., edge) may be filtered out so as not to be recorded.
 * User supplies filter criterion based on the categories of the relations.
 * There are four categories of the relations: "derived", "generated", "used", and "informed".
 * Each category has its own filter supplied by the user.
 * Depending on the type of the current relation in question, test if the type of the relation hits the filter (i.e., should be filtered out).
 * @param type The type of the relation (i.e., edge).
 * @return true if the relation should be filtered out (i.e., not recorded) or false if otherwise.
 *
 */
static __always_inline bool filter_relation(const uint64_t type)
{
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

/*!
 * @brief This function decides whether or not tracking should propagate.
 *
 * Based on the user supplied filter, a relation (i.e., edge) may be filtered if it is tracked in the propagation.
 * User supplies filter criterion based on the categories of the relations as in the "filter_relation" function.
 * Depending on the type of the current relation in question, test if the type of the relation hits the filter (i.e., should be filtered out if it is part of propagation).
 * @param type The type of the relation (i.e., edge).
 * @return true if the relation should be filtered out during propagation or false if otherwise.
 *
 */
static __always_inline bool filter_propagate_relation(uint64_t type)
{
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

/*!
 * @brief Whether a provenance relation between two nodes should be recorded based on the user-defined filter.
 *
 * If either the relation type or at least one of the two end nodes are filtered out (i.e., not to be recorded as defined by the user),
 * Then this function will return false.
 * Otherwise, the relation should be recorded and thus the function will return true.
 * @param type The type of the relation
 * @param from The provenance node entry of the source node.
 * @param to The provenance node entry of the destination node.
 * @return True if the relation of type 'type' should be recorded; False if otherwise.
 *
 */
static __always_inline bool should_record_relation(const uint64_t type,
						   prov_entry_t *from,
						   prov_entry_t *to)
{
	if (filter_relation(type))
		return false;
	if (filter_node(from) || filter_node(to))
		return false;
	return true;
}

/*!
 * @brief Define an abstract list. See concrete example below.
 */
#define declare_filter_list(filter_name, type) \
	struct filter_name {		       \
		struct list_head list;	       \
		struct type filter;	       \
	};				       \
	extern struct list_head filter_name;

/*!
 * @brief Define an abstract operation that returns op value of an item in a list. See concrete example below.
 */
#define declare_filter_whichOP(function_name, type, variable)		\
	static __always_inline uint8_t function_name(uint32_t variable)	\
	{								\
		struct list_head *listentry, *listtmp;			\
		struct type *tmp;					\
		list_for_each_safe(listentry, listtmp, &type) {		\
			tmp = list_entry(listentry, struct type, list);	\
			if (tmp->filter.variable == variable) {		\
				return tmp->filter.op; }		\
		}							\
		return 0;						\
	}

/*!
 * @brief Define an abstract operation that deletes an item from a list. See concrete example below.
 */
#define declare_filter_delete(function_name, type, variable)		  \
	static __always_inline uint8_t function_name(struct type *f)	  \
	{								  \
		struct list_head *listentry, *listtmp;			  \
		struct type *tmp;					  \
		list_for_each_safe(listentry, listtmp, &type) {		  \
			tmp = list_entry(listentry, struct type, list);	  \
			if (tmp->filter.variable == f->filter.variable) { \
				list_del(listentry);			  \
				kfree(tmp);				  \
				return 0;				  \
			}						  \
		}							  \
		return 0;						  \
	}

/*!
 * @brief Define an abstract operation that adds/updates the op value of an item from a list. See concrete example below.
 */
#define declare_filter_add_or_update(function_name, type, variable)	  \
	static __always_inline uint8_t function_name(struct type *f)	  \
	{								  \
		struct list_head *listentry, *listtmp;			  \
		struct type *tmp;					  \
		list_for_each_safe(listentry, listtmp, &type) {		  \
			tmp = list_entry(listentry, struct type, list);	  \
			if (tmp->filter.variable == f->filter.variable) { \
				tmp->filter.op = f->filter.op;		  \
				return 0;				  \
			}						  \
		}							  \
		list_add_tail(&(f->list), &type);			  \
		return 0;						  \
	}

declare_filter_list(secctx_filters, secinfo);                                   // A list of secinfo structs (defined in /include/uapi/linux/provenance.h, same as the following)
declare_filter_whichOP(prov_secctx_whichOP, secctx_filters, secid);             // Return op value of an item of a specific secid in the secctx_filters list if exists; return 0 otherwise
declare_filter_delete(prov_secctx_delete, secctx_filters, secid);               // Delete the element in secctx_filters list with the same secid as the item given in the function argument
declare_filter_add_or_update(prov_secctx_add_or_update, secctx_filters, secid); // Add or update op value of an item of a specific secid, which is the same as the item given in the function argument.

/*!
 * @brief Same set of operations as above but operate on "userinfo" list.
 */
declare_filter_list(user_filters, userinfo);
declare_filter_whichOP(prov_uid_whichOP, user_filters, uid);
declare_filter_delete(prov_uid_delete, user_filters, uid);
declare_filter_add_or_update(prov_uid_add_or_update, user_filters, uid);

/*!
 * @brief Same set of operations as above but operate on "groupinfo" list.
 */
declare_filter_list(group_filters, groupinfo);
declare_filter_whichOP(prov_gid_whichOP, group_filters, gid);
declare_filter_delete(prov_gid_delete, group_filters, gid);
declare_filter_add_or_update(prov_gid_add_or_update, group_filters, gid);

/*!
 * @brief Based on "op" value of a provenance node, decide whether it should be tracked/propagated/opaque.
 *
 * "op" value is contingent upon "op" values of:
 * 1. ns (i.e., namespace) elements: ipcns, mntns, pidns, netns, cgroupns, if the node is of type ENT_PROC, and
 * 2. secctx (i.e., security context) element if it has secctx, and
 * 3. uid element if it has uid, and
 * 4. gid element if it has gid.
 * @param prov The provenance node in question.
 *
 */
static __always_inline void apply_target(union prov_elt *prov)
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
