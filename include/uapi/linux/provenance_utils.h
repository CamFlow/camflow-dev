/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
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

 #ifndef _UAPI_LINUX_PROVENANCE_UTILS_H
 #define _UAPI_LINUX_PROVENANCE_UTILS_H

#include <linux/provenance.h>

 #define PROV_GOLDEN_RATIO_64            0x61C8864680B583EBUL
static inline uint32_t prov_hash(uint64_t val)
{
	return (val * PROV_GOLDEN_RATIO_64) >> (64 - 8);
}

 #define PROV_BYTE_INDEX(a)      (a / 8)
 #define PROV_BIT_INDEX(a)       (a % 8)

static inline void prov_bloom_add(uint8_t bloom[PROV_N_BYTES], uint64_t val)
{
	uint8_t i;
	uint32_t pos;

	for (i = 0; i < PROV_K_HASH; i++) {
		pos = prov_hash(val + i) % PROV_M_BITS;
		bloom[PROV_BYTE_INDEX(pos)] |= 1 << PROV_BIT_INDEX(pos);
	}
}

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
 #define generate_label(str)    djb2_hash(str)

/* element in set belong to super */
static inline bool prov_bloom_match(const uint8_t super[PROV_N_BYTES], const uint8_t set[PROV_N_BYTES])
{
	uint8_t i;

	for (i = 0; i < PROV_N_BYTES; i++)
		if ((super[i] & set[i]) != set[i])
			return false;

	return true;
}

static inline bool prov_bloom_in(const uint8_t bloom[PROV_N_BYTES], uint64_t val)
{
	uint8_t tmp[PROV_N_BYTES];

	memset(tmp, 0, PROV_N_BYTES);
	prov_bloom_add(tmp, val);
	return prov_bloom_match(bloom, tmp);
}

/* merge src into dest (dest=dest U src) */
static inline void prov_bloom_merge(uint8_t dest[PROV_N_BYTES], const uint8_t src[PROV_N_BYTES])
{
	uint8_t i;

	for (i = 0; i < PROV_N_BYTES; i++)
		dest[i] |= src[i];
}


static inline bool prov_bloom_empty(const uint8_t bloom[PROV_N_BYTES])
{
	uint8_t i;

	for (i = 0; i < PROV_N_BYTES; i++)
		if (bloom[i] != 0)
			return false;

	return true;
}
#endif
