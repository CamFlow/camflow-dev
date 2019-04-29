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
#ifndef _PROVENANCE_POLICY_H
#define _PROVENANCE_POLICY_H

/*!
 * @brief provenance capture policy defined by the user.
 *
 */
struct capture_policy {
	bool prov_enabled;                              // Whether provenance capture is enabled.
	bool prov_all;                                  // Whether to record provenance of all kernel object.
	bool prov_written;                              // For SPADE: Whether provenance has ever been published by CamFlow since boot.
	bool should_compress_node;                      // Whether nodes should be compressed into one if possible.
	bool should_compress_edge;                      // Whether edges should be compressed into one if possible. (e.g., multiple same edge between two nodes.)
	bool should_duplicate;                          // For SPADE: every time a relation is recorded the two end nodes will be recorded again if set to true.
	uint64_t prov_node_filter;                      // Node to be filtered out (i.e., not recorded).
	uint64_t prov_propagate_node_filter;            // Node to be filtered out if it is part of propagate.
	uint64_t prov_derived_filter;                   // Edge of category "derived" to be filtered out.
	uint64_t prov_generated_filter;                 // Edge of category "generated" to be filtered out.
	uint64_t prov_used_filter;                      // Edge of category "used" to be filtered out.
	uint64_t prov_informed_filter;                  // Edge of category "informed" to be filtered out.
	uint64_t prov_propagate_derived_filter;         // Edge of category "derived" to be filtered out if it is part of propagate.
	uint64_t prov_propagate_generated_filter;       // Edge of category "generated" to be filtered out if it is part of propagate.
	uint64_t prov_propagate_used_filter;            // Edge of category "used" to be filtered out if it is part of propagate.
	uint64_t prov_propagate_informed_filter;        // Edge of category "informed" to be filtered out if it is part of propagate.
};

extern struct capture_policy prov_policy;

#endif
