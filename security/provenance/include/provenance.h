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
#ifndef _PROVENANCE_H
#define _PROVENANCE_H

#include <linux/slab.h>
#include <linux/types.h>
#include <linux/bug.h>
#include <linux/socket.h>
#include <linux/lsm_hooks.h>
#include <linux/msg.h>
#include <linux/cred.h>
#include <uapi/linux/mman.h>
#include <uapi/linux/provenance.h>
#include <uapi/linux/provenance_types.h>
#include <uapi/linux/stat.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/xattr.h>

#include "provenance_policy.h"
#include "provenance_filter.h"
#include "provenance_query.h"

extern atomic64_t prov_relation_id;
extern atomic64_t prov_node_id;
extern uint32_t prov_machine_id;
extern uint32_t prov_boot_id;
extern uint32_t epoch;

#define prov_next_relation_id()         ((uint64_t)atomic64_inc_return(&prov_relation_id))
#define prov_next_node_id()             ((uint64_t)atomic64_inc_return(&prov_node_id))

enum {
	PROVENANCE_LOCK_PROC,
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

#define prov_elt(provenance)            (&(provenance->msg))
#define prov_lock(provenance)           (&(provenance->lock))
#define prov_entry(provenance)          ((prov_entry_t *)prov_elt(provenance))

#define ASSIGN_NODE_ID    0

extern struct kmem_cache *provenance_cache;
extern struct kmem_cache *long_provenance_cache;

static __always_inline void init_provenance_struct(uint64_t ntype,
						   struct provenance *prov)
{
	spin_lock_init(prov_lock(prov));
	prov_type(prov_elt(prov)) = ntype;
	node_identifier(prov_elt(prov)).id = prov_next_node_id();
	node_identifier(prov_elt(prov)).boot_id = prov_boot_id;
	node_identifier(prov_elt(prov)).machine_id = prov_machine_id;
	call_provenance_alloc(prov_entry(prov));
}
/*!
 * @brief Allocate memory for a new provenance node and populate "node_identifier" information.
 *
 * The memory is allocated from "provenance_cache".
 * The type of the provenance node provided in the argument list must align with the allowed provenance node type (i.e., not a relation type).
 * Allowed provenance node types are defined in "include/uapi/linux/provenance_types.h"
 * The lock accompanied "provenance" structure is initialized as UNLOCK.
 * Implicitly, the "version" member of "node_identifier" structure is set to 0 through "zalloc".
 * This is because the version of a new node starts from 0.
 * @param ntype The type of the provenance node.
 * @param gfp GFP flags used in memory allocation in the kernel
 * @return The pointer to the provenance node (prov_elt + lock structure) or NULL if allocating memory from cache failed.
 *
 */
static __always_inline struct provenance *alloc_provenance(uint64_t ntype, gfp_t gfp)
{
	struct provenance *prov =  kmem_cache_zalloc(provenance_cache, gfp);

	BUILD_BUG_ON(!prov_type_is_node(ntype));

	if (!prov)
		return NULL;
	init_provenance_struct(ntype, prov);
	return prov;
}

/*!
 * @brief Free memory of a provenance node
 */
static inline void free_provenance(struct provenance *prov)
{
	call_provenance_free(prov_entry(prov));
	kmem_cache_free(provenance_cache, prov);
}

/*!
 * @brief Allocate memory for a new long provenance node and set the provenance "LONG" flag (in basic_elements).
 *
 * Similar to "alloc_provenance" function above, this function allocate memory for long_prove_elt union structure.
 * long_prov_elt contains more types of node structures than prov_elt.
 * "version" member of the identifier is also implicitly set to 0 due to "zalloc".
 * Spin lock is not needed because at most one thread will access the structure at a time, since it is a transient element.
 * @param ntype The type of the long provenance node.
 * @return The pointer to the long provenance node (long_prov_elt union structure) or NULL if allocating memory from cache failed.
 * @reference GFP_ATOMIC https://www.linuxjournal.com/article/6930
 *
 */
static __always_inline union long_prov_elt *alloc_long_provenance(uint64_t ntype, uint64_t id)
{
	union long_prov_elt *prov = kmem_cache_zalloc(long_provenance_cache, GFP_ATOMIC);

	BUILD_BUG_ON(!prov_type_is_node(ntype));
	BUILD_BUG_ON(!prov_type_is_long(ntype));

	if (!prov)
		return NULL;
	prov_type(prov) = ntype;
	if (id == 0)
		node_identifier(prov).id = prov_next_node_id();
	else
		node_identifier(prov).id = id;
	node_identifier(prov).boot_id = prov_boot_id;
	node_identifier(prov).machine_id = prov_machine_id;
	call_provenance_alloc(prov);
	return prov;
}

/*!
 * @brief Free memory of a long provenance node
 */
static inline void free_long_provenance(union long_prov_elt *prov)
{
	call_provenance_free(prov);
	kmem_cache_free(long_provenance_cache, prov);
}

#define set_recorded(node)                      __set_recorded((union long_prov_elt *)node)
static inline void __set_recorded(union long_prov_elt *node)
{
	node->msg_info.epoch = epoch;
}

#define clear_recorded(node)                    __clear_recorded((union long_prov_elt *)node)
static inline void __clear_recorded(union long_prov_elt *node)
{
	node->msg_info.epoch = 0;
}

#define provenance_is_recorded(node)            __provenance_is_recorded((union long_prov_elt *)node)
static inline bool __provenance_is_recorded(union long_prov_elt *node)
{
	if (epoch > node->msg_info.epoch)
		return false;
	return true;
}

#define set_name_recorded(node)                 __set_name_recorded((union long_prov_elt *)node)
static inline void __set_name_recorded(union long_prov_elt *node)
{
	node->msg_info.nepoch = epoch;
}

#define clear_name_recorded(node)               __clear_name_recorded((union long_prov_elt *)node)
static inline void __clear_name_recorded(union long_prov_elt *node)
{
	node->msg_info.nepoch = 0;
}

#define provenance_is_name_recorded(node)       __provenance_is_name_recorded((union long_prov_elt *)node)
static inline bool __provenance_is_name_recorded(union long_prov_elt *node)
{
	if (epoch > node->msg_info.nepoch)
		return false;
	return true;
}

// reference to node representing the machine/kernel
extern union long_prov_elt *prov_machine;

#define set_kernel_recorded(node)               __set_kernel_recorded((union long_prov_elt *)node)
static inline void __set_kernel_recorded(union long_prov_elt *node)
{
	node_kernel_version(node) = node_identifier(prov_machine).version;
}

#define provenance_is_kernel_recorded(node)     __provenance_is_kernel_recorded((union long_prov_elt *)node)
static inline bool __provenance_is_kernel_recorded(union long_prov_elt *node)
{
	if (node_kernel_version(node) < node_identifier(prov_machine).version)
		return false;
	return true;
}

extern struct lsm_blob_sizes provenance_blob_sizes;
static inline struct provenance *provenance_cred(const struct cred *cred)
{
	return cred->security + provenance_blob_sizes.lbs_cred;
}

static inline struct provenance *provenance_task(const struct task_struct *task)
{
	return task->security + provenance_blob_sizes.lbs_task;
}

static inline struct provenance *provenance_cred_from_task(
	struct task_struct *task)
{
	struct provenance *prov;
	const struct cred *cred = get_task_cred(task);

	prov = cred->security + provenance_blob_sizes.lbs_cred;
	put_cred(cred); // Release cred.
	return prov;
}

static inline struct provenance *provenance_file(const struct file *file)
{
	return file->f_security + provenance_blob_sizes.lbs_file;
}

static inline struct provenance *provenance_inode(
	const struct inode *inode)
{
	if (unlikely(!inode->i_security))
		return NULL;
	return inode->i_security + provenance_blob_sizes.lbs_inode;
}

static inline struct provenance *provenance_msg_msg(
	const struct msg_msg *msg_msg)
{
	return msg_msg->security + provenance_blob_sizes.lbs_msg_msg;
}

static inline struct provenance *provenance_ipc(
	const struct kern_ipc_perm *ipc)
{
	return ipc->security + provenance_blob_sizes.lbs_ipc;
}
#endif
