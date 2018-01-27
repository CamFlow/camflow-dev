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
