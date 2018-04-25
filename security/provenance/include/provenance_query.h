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
