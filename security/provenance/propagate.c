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
#include "provenance.h"
#include "provenance_query.h"

/*!
 * @brief If a node has a new outgoing edge, check if the edge should be tracked by propagation.
 *
 * We set the outgoing edge to be tracked and propagated if
 * 1. The source node is set to be propagated, and
 * 2. The source node is set to be tracked, and
 * 3. The edge is not filtered out.
 * @param node The source provenance node entry pointer.
 * @param edge The outgoing edge provenance entry pointer.
 * @return 0 if no error occurred.
 *
 */
static int out_edge(prov_entry_t *node, prov_entry_t *edge)
{
	if (provenance_does_propagate(node) && provenance_is_tracked(node)) {
		if (!filter_propagate_relation(prov_type(edge))) {
			set_tracked(edge);
			set_propagate(edge);
			prov_bloom_merge(prov_taint(edge), prov_taint(node));
		}
	}
	return 0;
}

/*!
 * @brief Check if the destination node of an edge should be tracked by propagation.
 *
 * We set the destination node to be tracked and propagated if
 * 1. The edge is set to be propagated, and
 * 2. The edge is set to be tracked, and
 * 3. The node is not filtered out.
 * @param edge The edge provenance entry pointer.
 * @param node The destination provenance node entry pointer.
 * @return 0 if no error occurred.
 *
 */
static int in_edge(prov_entry_t *edge, prov_entry_t *node)
{
	if (provenance_does_propagate(edge) && provenance_is_tracked(edge)) {
		if (!filter_propagate_node(node)) {
			set_tracked(node);
			set_propagate(node);
			prov_bloom_merge(prov_taint(node), prov_taint(edge));
		}
	}
	return 0;
}

struct provenance_query_hooks hooks = {
	QUERY_HOOK_INIT(out_edge, out_edge),
	QUERY_HOOK_INIT(in_edge,  in_edge),
};

/*!
 * Register the propagate hooks.
 */
static int __init init_prov_propagate(void)
{
	register_provenance_query_hooks(&hooks);
	pr_info("Provenance: propagate ready.\n");
	return 0;
}
security_initcall(init_prov_propagate);
