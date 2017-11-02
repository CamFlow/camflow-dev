/*
 *
 * Author: Thomas Pasquier <thomas.pasquier@cl.cam.ac.uk>
 *
 * Copyright (C) 2015 University of Cambridge
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
#include "provenance_relay.h"

extern struct kmem_cache *provenance_cache;
extern struct kmem_cache *long_provenance_cache;

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
	uint8_t updt_mmap;
	uint8_t has_mmap;
	bool has_outgoing;
	bool initialised;
	bool saved;
};

#define prov_elt(provenance) (&(provenance->msg))
#define prov_lock(provenance) (&(provenance->lock))
#define prov_entry(provenance) ((prov_entry_t*)prov_elt(provenance))

#define ASSIGN_NODE_ID 0

static inline struct provenance *alloc_provenance(uint64_t ntype, gfp_t gfp)
{
	struct provenance *prov =  kmem_cache_zalloc(provenance_cache, gfp);

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

static inline union long_prov_elt *alloc_long_provenance(uint64_t ntype)
{
	union long_prov_elt *tmp = kmem_cache_zalloc(long_provenance_cache, GFP_ATOMIC);

	if (!tmp)
		return NULL;
	prov_type(tmp) = ntype;
	node_identifier(tmp).id = prov_next_node_id();
	node_identifier(tmp).boot_id = prov_boot_id;
	node_identifier(tmp).machine_id = prov_machine_id;
	set_is_long(tmp);
	return tmp;
}

static inline void free_long_provenance(union long_prov_elt *prov)
{
	kmem_cache_free(long_provenance_cache, prov);
}

static inline int record_node_name(struct provenance *node, const char *name)
{
	union long_prov_elt *fname_prov;
	int rc;

	if (provenance_is_name_recorded(prov_elt(node)) || !provenance_is_recorded(prov_elt(node)))
		return 0;

	fname_prov = alloc_long_provenance(ENT_FILE_NAME);
	if (!fname_prov)
		return -ENOMEM;

	strlcpy(fname_prov->file_name_info.name, name, PATH_MAX);
	fname_prov->file_name_info.length = strnlen(fname_prov->file_name_info.name, PATH_MAX);

	// record the relation
	spin_lock(prov_lock(node));
	if (prov_type(prov_elt(node)) == ACT_TASK) {
		rc = write_relation(RL_NAMED_PROCESS, fname_prov, prov_elt(node), NULL);
		set_name_recorded(prov_elt(node));
	} else{
		rc = write_relation(RL_NAMED, fname_prov, prov_elt(node), NULL);
		set_name_recorded(prov_elt(node));
	}
	spin_unlock(prov_lock(node));
	free_long_provenance(fname_prov);
	return rc;
}

static inline int record_log(union prov_elt *cprov, const char __user *buf, size_t count)
{
	union long_prov_elt *str;
	int rc = 0;

	str = alloc_long_provenance(ENT_STR);
	if (!str) {
		rc = -ENOMEM;
		goto out;
	}
	if (copy_from_user(str->str_info.str, buf, count)) {
		rc = -EAGAIN;
		goto out;
	}
	str->str_info.str[count] = '\0'; // make sure the string is null terminated
	str->str_info.length = count;

	rc = write_relation(RL_LOG, str, cprov, NULL);
out:
	free_long_provenance(str);
	if (rc < 0)
		return rc;
	return count;
}

static inline int __update_version(const uint64_t type, struct provenance *prov)
{
	union prov_elt old_prov;
	int rc = 0;

	// there is no outgoing edge and we are compressing
	if (!prov->has_outgoing && prov_policy.should_compress)
		return 0;
	// are we recording this type
	if (filter_update_node(type))
		return 0;
	if (memcpy(&old_prov, prov_elt(prov), sizeof(union prov_elt)) == NULL)
		return -ENOMEM;
	node_identifier(prov_elt(prov)).version++;
	clear_recorded(prov_elt(prov));

	if (node_identifier(prov_elt(prov)).type == ACT_TASK)
		rc = write_relation(RL_VERSION_PROCESS, &old_prov, prov_elt(prov), NULL);
	else
		rc = write_relation(RL_VERSION, &old_prov, prov_elt(prov), NULL);
	prov->has_outgoing = false; // we update there is no more outgoing edge
	prov->saved = false;
	return rc;
}

static inline int record_relation(const uint64_t type,
				  struct provenance *from,
				  struct provenance *to,
				  struct file *file)
{
	int rc = 0;

	// check if the nodes match some capture options
	apply_target(prov_elt(from));
	apply_target(prov_elt(to));

	if (!provenance_is_tracked(prov_elt(from)) && !provenance_is_tracked(prov_elt(to)) && !prov_policy.prov_all)
		return 0;
	if (!should_record_relation(type, prov_entry(from), prov_entry(to)))
		return 0;
	rc = __update_version(type, to);
	if (rc < 0)
		return rc;

	rc = write_relation(type, prov_elt(from), prov_elt(to), file);
	from->has_outgoing = true; // there is an outgoing edge
	return rc;
}

static inline int uses(uint64_t type,
		       struct provenance *from,
		       struct provenance *to,
		       struct file *file)
{
	int rc = record_relation(type, from, to, file);

	//BUILD_BUG_ON(!IS_USED(type));

	if (should_record_relation(type, prov_entry(from), prov_entry(to)))
		to->updt_mmap = 1;
	return rc;
}

static inline int generates(const uint64_t type,
			    struct provenance *from,
			    struct provenance *to,
			    struct file *file)
{
	//BUILD_BUG_ON(!IS_GENERATED(type));
	return record_relation(type, from, to, file);
}

static inline int derives(const uint64_t type,
			  struct provenance *from,
			  struct provenance *to,
			  struct file *file)
{
	//BUILD_BUG_ON(!IS_DERIVED(type));
	return record_relation(type, from, to, file);
}

static inline int informs(const uint64_t type,
			  struct provenance *from,
			  struct provenance *to,
			  struct file *file)
{
	//BUILD_BUG_ON(!IS_INFORMED(type));
	return record_relation(type, from, to, file);
}
#endif
