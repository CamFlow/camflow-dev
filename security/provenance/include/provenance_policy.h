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
#ifndef _PROVENANCE_POLICY_H
#define _PROVENANCE_POLICY_H

struct capture_policy {
	bool prov_enabled;
	bool prov_all;
	bool prov_written;
	bool should_compress_node;
	bool should_compress_edge;
	bool should_duplicate;
	uint64_t prov_node_filter;
	uint64_t prov_propagate_node_filter;
	uint64_t prov_derived_filter;
	uint64_t prov_generated_filter;
	uint64_t prov_used_filter;
	uint64_t prov_informed_filter;
	uint64_t prov_propagate_derived_filter;
	uint64_t prov_propagate_generated_filter;
	uint64_t prov_propagate_used_filter;
	uint64_t prov_propagate_informed_filter;
};

extern struct capture_policy prov_policy;

#endif
