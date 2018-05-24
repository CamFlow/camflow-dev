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
#ifndef _PROVENANCE_QUERY_H
#define _PROVENANCE_QUERY_H

#include <linux/provenance_query.h>

/*!
 * @brief Go through each element in provenance_query_hooks and call out_edge function.
 *
 * out_edge routine is defined propagate.c
 * @param node The node provenance entry pointer.
 * @param edge The edge provenance entry pointer.
 * @return 0 if no error occurred. Other error codes inherited or unknown.
 *
 */
static inline int call_provenance_out_edge(prov_entry_t *node,
					   prov_entry_t *edge)
{
	int rc = 0;
	struct list_head *listentry, *listtmp;
	struct provenance_query_hooks *fcn;

	list_for_each_safe(listentry, listtmp, &provenance_query_hooks) {
		fcn = list_entry(listentry, struct provenance_query_hooks, list);
		if (fcn->out_edge)
			rc |= fcn->out_edge(node, edge);
	}
	return rc;
}

/*!
 * @brief Go through each element in provenance_query_hooks and call in_edge function.
 *
 * in_edge routine is defined propagate.c
 * @param edge The edge provenance entry pointer.
 * @param node The node provenance entry pointer.
 * @return 0 if no error occurred. Other error codes inherited or unknown.
 *
 */
static inline int call_provenance_in_edge(prov_entry_t *edge,
					  prov_entry_t *node)
{
	int rc = 0;
	struct list_head *listentry, *listtmp;
	struct provenance_query_hooks *fcn;

	list_for_each_safe(listentry, listtmp, &provenance_query_hooks) {
		fcn = list_entry(listentry, struct provenance_query_hooks, list);
		if (fcn->in_edge)
			rc |= fcn->in_edge(edge, node);
	}
	return rc;
}

/*!
 * @brief Call out_edge and in_edge function.
 *
 * Simply call both call_provenance_out_edge and call_provenance_in_edge routine.
 * @param from The source node provenance entry pointer.
 * @param to The destination node provenance entry pointer.
 * @param edge The edge provenance entry pointer.
 * @return 0 if no error occurred; -EPERM if flow is disallowed. Other error codes inherited or unknown.
 *
 * @question What are all the warnings about?
 */
static inline int call_query_hooks(prov_entry_t *from,
				   prov_entry_t *to,
				   prov_entry_t *edge)
{
	int rc = 0;

	rc = call_provenance_out_edge(from, edge);
	if ((rc & PROVENANCE_RAISE_WARNING) == PROVENANCE_RAISE_WARNING)
		pr_warning("Provenance: warning raised.\n");
	if ((rc & PROVENANCE_PREVENT_FLOW) == PROVENANCE_PREVENT_FLOW) {
		pr_err("Provenance: error raised.\n");
		edge->relation_info.allowed = FLOW_DISALLOWED;
		return -EPERM;
	}
	rc = call_provenance_in_edge(edge, to);
	if ((rc & PROVENANCE_RAISE_WARNING) == PROVENANCE_RAISE_WARNING)
		pr_warning("Provenance: warning raised.\n");
	if ((rc & PROVENANCE_PREVENT_FLOW) == PROVENANCE_PREVENT_FLOW) {
		pr_err("Provenance: error raised.\n");
		edge->relation_info.allowed = FLOW_DISALLOWED;
		return -EPERM;
	}
	return 0;
}
#endif
