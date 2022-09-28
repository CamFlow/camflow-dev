// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2016 University of Cambridge,
 * Copyright (C) 2016-2017 Harvard University,
 * Copyright (C) 2017-2018 University of Cambridge,
 * Copyright (C) 2018-2021 University of Bristol,
 * Copyright (C) 2021-2022 University of British Columbia
 *
 * Author: Thomas Pasquier <tfjmp@cs.ubc.ca>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 */
#include "provenance.h"
#include "provenance_query.h"

static int flow(prov_entry_t *from, prov_entry_t *edge, prov_entry_t *to)
{
	if (provenance_does_propagate(from) && provenance_is_tracked(from))
		// can propagate over edge?
		if (!filter_propagate_relation(prov_type(edge)) &&
		    !filter_propagate_node(to)) {
			set_tracked(to);
			set_propagate(to);
			provenance_taint_merge(prov_taint(to), prov_taint(from));
		}
	return 0;
}

static struct provenance_query_hooks hooks = {
	QUERY_HOOK_INIT(flow, flow),
};

/*!
 * Register the propagate hooks.
 */
int init_prov_propagate(void)
{
	register_provenance_query_hooks(&hooks);
	pr_info("Provenance: propagate ready.\n");
	return 0;
}
