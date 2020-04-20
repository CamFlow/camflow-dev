/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2015-2016 University of Cambridge,
 * Copyright (C) 2016-2017 Harvard University,
 * Copyright (C) 2017-2018 University of Cambridge,
 * Copyright (C) 2018-2020 University of Bristol
 *
 * Author: Thomas Pasquier <thomas.pasquier@bristol.ac.uk>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 */
#ifndef _PROVENANCE_POLICY_H
#define _PROVENANCE_POLICY_H

/*!
 * @brief provenance capture policy defined by the user.
 *
 */
struct capture_policy {
	// Whether provenance capture is enabled.
	bool prov_enabled;
	// Whether to record provenance of all kernel object.
	bool prov_all;
	// Whether nodes should be compressed into one if possible.
	bool should_compress_node;
	// Whether edges should be compressed into one if possible.
	bool should_compress_edge;
	// every time a relation is recorded the two end nodes will be recorded
	// again if set to true.
	bool should_duplicate;
	// Node to be filtered out (i.e., not recorded).
	uint64_t prov_node_filter;
	// Node to be filtered out if it is part of propagate.
	uint64_t prov_propagate_node_filter;
	// Edge of category "derived" to be filtered out.
	uint64_t prov_derived_filter;
	// Edge of category "generated" to be filtered out.
	uint64_t prov_generated_filter;
	// Edge of category "used" to be filtered out.
	uint64_t prov_used_filter;
	// Edge of category "informed" to be filtered out.
	uint64_t prov_informed_filter;
	// Edge of category "derived" to be filtered out if it is part of
	// propagate.
	uint64_t prov_propagate_derived_filter;
	// Edge of category "generated" to be filtered out if it is part of
	// propagate.
	uint64_t prov_propagate_generated_filter;
	// Edge of category "used" to be filtered out if it is part of
	// propagate.
	uint64_t prov_propagate_used_filter;
	// Edge of category "informed" to be filtered out if it is part of
	// propagate.
	uint64_t prov_propagate_informed_filter;
};

extern struct capture_policy prov_policy;

#endif
