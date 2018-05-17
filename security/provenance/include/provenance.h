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
#ifndef _PROVENANCE_H
#define _PROVENANCE_H

#include <linux/slab.h>
#include <linux/types.h>
#include <linux/bug.h>
#include <linux/socket.h>
#include <uapi/linux/mman.h>
#include <uapi/linux/provenance.h>
#include <uapi/linux/provenance_types.h>
#include <uapi/linux/stat.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/xattr.h>

#include "provenance_policy.h"
#include "provenance_filter.h"

extern atomic64_t prov_relation_id;
extern atomic64_t prov_node_id;
extern uint32_t prov_machine_id;
extern uint32_t prov_boot_id;

#define prov_next_relation_id() ((uint64_t)atomic64_inc_return(&prov_relation_id))
#define prov_next_node_id() ((uint64_t)atomic64_inc_return(&prov_node_id))

enum {
	PROVENANCE_LOCK_PROC,
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
};

#define prov_elt(provenance) (&(provenance->msg))
#define prov_lock(provenance) (&(provenance->lock))
#define prov_entry(provenance) ((prov_entry_t*)prov_elt(provenance))

#define ASSIGN_NODE_ID 0

extern struct kmem_cache *provenance_cache;
extern struct kmem_cache *long_provenance_cache;

/*!
 * @brief Allocate memory for a new provenance node and populate "node_identifier" information.
 *
 * The memory is allocated from "provenance_cache".
 * The type of the provenance node provided in the argument list must align with the allowed provenance node type.
 * Allowed provenance node types are defined in "include/uapi/linux/provenance_types.h"
 * The lock accompanied "provenance" structure is initialized as UNLOCK.
 * Implicitly, the "version" member of "node_identifier" structure is set to 0 through "zalloc".
 * This is because the version of a new node starts from 0.
 * @param ntype The type of the provenance node.
 * @param gfp GFP flags used in memory allocation in the kernel
 * @return The pointer to the provenance node or NULL if allocating memory from cache failed.
 */
static __always_inline struct provenance *alloc_provenance(uint64_t ntype, gfp_t gfp)
{
	struct provenance *prov =  kmem_cache_zalloc(provenance_cache, gfp);

	BUILD_BUG_ON(!prov_type_is_node(ntype));

	if (!prov)
		return NULL;
	spin_lock_init(prov_lock(prov));
	prov_type(prov_elt(prov)) = ntype;
	node_identifier(prov_elt(prov)).id = prov_next_node_id();
	node_identifier(prov_elt(prov)).boot_id = prov_boot_id;
	node_identifier(prov_elt(prov)).machine_id = prov_machine_id;
	return prov;
}

static inline void free_provenance(struct provenance *prov)
{
	kmem_cache_free(provenance_cache, prov);
}

static __always_inline union long_prov_elt *alloc_long_provenance(uint64_t ntype)
{
	union long_prov_elt *prov = kmem_cache_zalloc(long_provenance_cache, GFP_ATOMIC);

	BUILD_BUG_ON(!prov_type_is_node(ntype));

	if (!prov)
		return NULL;
	prov_type(prov) = ntype;
	node_identifier(prov).id = prov_next_node_id();
	node_identifier(prov).boot_id = prov_boot_id;
	node_identifier(prov).machine_id = prov_machine_id;
	set_is_long(prov);
	return prov;
}

static inline void free_long_provenance(union long_prov_elt *prov)
{
	kmem_cache_free(long_provenance_cache, prov);
}
#endif
