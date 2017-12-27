/*
 *
 * Author: Thomas Pasquier <thomas.pasquier@cl.cam.ac.uk>
 *
 * Copyright (C) 2015-2017 University of Cambridge, Harvard University
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 */
#ifndef _PROVENANCE_H
#define _PROVENANCE_H

#include <linux/slab.h>
#include <linux/types.h>
#include <linux/bug.h>
#include <linux/socket.h>
#include <uapi/linux/mman.h>
#include <uapi/linux/camflow.h>
#include <uapi/linux/provenance.h>
#include <uapi/linux/provenance_types.h>
#include <uapi/linux/stat.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/xattr.h>

#include "provenance_policy.h"
#include "provenance_filter.h"

extern atomic64_t prov_id;
extern uint32_t prov_machine_id;
extern uint32_t prov_boot_id;

#define prov_next_id() ((uint64_t)atomic64_inc_return(&prov_id))

enum {
	PROVENANCE_LOCK_TASK,
	PROVENANCE_LOCK_DIR,
	PROVENANCE_LOCK_INODE,
	PROVENANCE_LOCK_MSG,
	PROVENANCE_LOCK_SHM,
	PROVENANCE_LOCK_SOCKET,
	PROVENANCE_LOCK_SOCK
};

struct provenance {
	union prov_elt msg;
	spinlock_t lock;
	bool has_mmap;
	bool updt_mmap;
	bool has_outgoing;
	bool initialised;
	bool saved;
	uint64_t previous_id;
	uint64_t previous_type;
};

#define prov_elt(provenance) (&(provenance->msg))
#define prov_lock(provenance) (&(provenance->lock))
#define prov_entry(provenance) ((prov_entry_t*)prov_elt(provenance))

#define ASSIGN_NODE_ID 0

extern struct kmem_cache *provenance_cache;
extern struct kmem_cache *long_provenance_cache;

static inline struct provenance *alloc_provenance(uint64_t ntype, gfp_t gfp)
{
	struct provenance *prov =  kmem_cache_zalloc(provenance_cache, gfp);

	if (!prov)
		return NULL;
	spin_lock_init(prov_lock(prov));
	prov_type(prov_elt(prov)) = ntype;
	node_identifier(prov_elt(prov)).id = prov_next_id();
	node_identifier(prov_elt(prov)).boot_id = prov_boot_id;
	node_identifier(prov_elt(prov)).machine_id = prov_machine_id;
	return prov;
}

static inline void free_provenance(struct provenance *prov)
{
	kmem_cache_free(provenance_cache, prov);
}

static inline union long_prov_elt *alloc_long_provenance(uint64_t ntype)
{
	union long_prov_elt *tmp = kmem_cache_zalloc(long_provenance_cache, GFP_ATOMIC);

	if (!tmp)
		return NULL;
	prov_type(tmp) = ntype;
	node_identifier(tmp).id = prov_next_id();
	node_identifier(tmp).boot_id = prov_boot_id;
	node_identifier(tmp).machine_id = prov_machine_id;
	set_is_long(tmp);
	return tmp;
}

static inline void free_long_provenance(union long_prov_elt *prov)
{
	kmem_cache_free(long_provenance_cache, prov);
}
#endif
