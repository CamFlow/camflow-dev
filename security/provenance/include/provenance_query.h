// SPDX-License-Identifier: GPL-2.0
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
#ifndef _PROVENANCE_QUERY_H
#define _PROVENANCE_QUERY_H

#include <linux/provenance_query.h>

int init_prov_propagate(void);

static inline int call_provenance_flow(prov_entry_t *from,
				       prov_entry_t *edge,
				       prov_entry_t *to)
{
	int rc = 0;
	struct list_head *listentry, *listtmp;
	struct provenance_query_hooks *fcn;

	list_for_each_safe(listentry, listtmp, &provenance_query_hooks) {
		fcn = list_entry(listentry, struct provenance_query_hooks, list);
		if (fcn->flow)
			rc |= fcn->flow(from, edge, to);
	}
	return rc;
}

static inline int call_provenance_alloc(prov_entry_t *elt)
{
	int rc = 0;
	struct list_head *listentry, *listtmp;
	struct provenance_query_hooks *fcn;

	list_for_each_safe(listentry, listtmp, &provenance_query_hooks) {
		fcn = list_entry(listentry, struct provenance_query_hooks, list);
		if (fcn->alloc)
			rc |= fcn->alloc(elt);
	}
	return rc;
}

static inline int call_provenance_free(prov_entry_t *elt)
{
	int rc = 0;
	struct list_head *listentry, *listtmp;
	struct provenance_query_hooks *fcn;

	list_for_each_safe(listentry, listtmp, &provenance_query_hooks) {
		fcn = list_entry(listentry, struct provenance_query_hooks, list);
		if (fcn->free)
			rc |= fcn->free(elt);
	}
	return rc;
}

/*!
 * @brief Call out_edge and in_edge function.
 *
 * Simply call both call_provenance_out_edge and call_provenance_in_edge function.
 * @param from The source node provenance entry pointer.
 * @param to The destination node provenance entry pointer.
 * @param edge The edge provenance entry pointer.
 * @return 0 if no error occurred; -EPERM if flow is disallowed. Other error codes inherited or unknown.
 *
 */
static inline int call_query_hooks(prov_entry_t *from,
				   prov_entry_t *to,
				   prov_entry_t *edge)
{
	int rc = 0;

	rc = call_provenance_flow(from, edge, to);
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
