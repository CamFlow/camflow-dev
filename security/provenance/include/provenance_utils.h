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
#ifndef _PROVENANCE_UTILS_H
#define _PROVENANCE_UTILS_H

/* djb2 hash implementation by Dan Bernstein */
static inline uint64_t djb2_hash(const char *str)
{
	uint64_t hash = 5381;
	int c = *str;

	while (c) {
		hash = ((hash << 5) + hash) + c;
		c = *++str;
	}
	return hash;
}

#endif
