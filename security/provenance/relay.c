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
#include <linux/init.h>
#include <linux/module.h>
#include <linux/debugfs.h>
#include <linux/async.h>
#include <linux/delay.h>

#include "provenance.h"
#include "provenance_relay.h"
#include "memcpy_ss.h"

#define PROV_BASE_NAME          "provenance"
#define LONG_PROV_BASE_NAME     "long_provenance"

/*!
 * @brief A list of relay channel data structure.
 *
 * struct rchan is defined in /include/linux/relay.h Linux kernel source code.
 */
struct relay_list {
	struct list_head list;
	char *name;                     // The name of the relay channel.
	struct rchan *prov;             // Relay buffer for regular provenance entries.
	struct rchan *long_prov;        // Relay buffer for long provenance entries.
};
LIST_HEAD(relay_list);

/*!
 * @brief Add an element to the tail end of the relay list, which is identified by the "extern struct list_head relay_list" above.
 * @param name Member of the element in the relay list
 * @param prov Member of the element in the relay list. This is a relay channel pointer.
 * @param long_prov Member of the element in the relay list. This is a relay channel pointer.
 *
 * @todo Failure case checking is missing.
 */
void prov_add_relay(char *name, struct rchan *prov, struct rchan *long_prov)
{
	struct relay_list *list;

	list = kzalloc(sizeof(struct relay_list), GFP_KERNEL);
	list->name = name;
	list->prov = prov;
	list->long_prov = long_prov;
	list_add_tail(&(list->list), &relay_list);
}

/*!
 * @brief Flush every relay buffer element in the relay list.
 */
void prov_flush(void)
{
	struct relay_list *tmp;

	if (unlikely(!relay_ready))
		return;

	list_for_each_entry(tmp, &relay_list, list) {
		relay_flush(tmp->prov);
		relay_flush(tmp->long_prov);
	}
}

/* Global variables: variable declarations in provenance.h */
static struct rchan *prov_chan;
static struct rchan *long_prov_chan;
atomic64_t prov_relation_id = ATOMIC64_INIT(0);
atomic64_t prov_node_id = ATOMIC64_INIT(0);

bool is_relay_full(struct rchan *chan, int cpu)
{
	int ret;
	int rc = 0;
	struct rchan_buf __percpu *buf = *per_cpu_ptr(chan->buf, cpu);

	if (buf) {
		ret = relay_buf_full(buf);
		if (ret)
			pr_warn("Provenance: relay (%s) on core %d is full.", chan->base_filename, cpu);
		rc += ret;
	}
	if (rc)
		return true;
	return false;
}

/*!
 * @brief Callback function of function "create_buf_file". This callback function creates relay file in "debugfs".
 */
static struct dentry *create_buf_file_handler(const char *filename,
					      struct dentry *parent,
					      umode_t mode,
					      struct rchan_buf *buf,
					      int *is_global)
{
	return debugfs_create_file(filename, mode, parent, buf,
				   &relay_file_operations);
}

/*!
 * @brief Callback function of function "remove_buf_file". This callback function removes the relay file from "debugfs".
 */
static int remove_buf_file_handler(struct dentry *dentry)
{
	debugfs_remove(dentry);
	return 0;
}


/* Relay interface callback functions */
static struct rchan_callbacks relay_callbacks = {
	.create_buf_file = create_buf_file_handler,
	.remove_buf_file = remove_buf_file_handler,
};

extern union prov_elt *buffer_head;
extern union long_prov_elt *long_buffer_head;

static void __async_handle_boot_buffer(void *_buf, async_cookie_t cookie)
{
	int cpu;
	union prov_elt *tmp = buffer_head;

	msleep(1000);
	pr_info("Provenance: async boot buffer task %llu running...", cookie);

	while (tmp != NULL) {
		cpu = get_cpu();
		if (is_relay_full(prov_chan, cpu)) {
			cookie = async_schedule(__async_handle_boot_buffer, NULL);
			pr_info("Provenance: schedlued boot buffer async task %llu.", cookie);
			put_cpu();
			return;
		}
		put_cpu();
		tighten_identifier(&get_prov_identifier(tmp));
		if (prov_is_relation(tmp)) {
			tighten_identifier(&(tmp->relation_info.snd));
			tighten_identifier(&(tmp->relation_info.rcv));
		}
		relay_write(prov_chan, tmp, sizeof(union prov_elt));
		buffer_head = tmp->msg_info.next;
		kmem_cache_free(provenance_cache, tmp);
		tmp = buffer_head;
	}
	pr_info("Provenance: finished task %llu.", cookie);
}

static void __async_handle_long_boot_buffer(void *_buf, async_cookie_t cookie)
{
	int cpu;
	union long_prov_elt *tmp = long_buffer_head;

	msleep(1000);
	pr_info("Provenance: async boot buffer task %llu running...", cookie);

	while (tmp != NULL) {
		cpu = get_cpu();
		if (is_relay_full(prov_chan, cpu)) {
			cookie = async_schedule(__async_handle_long_boot_buffer, NULL);
			pr_info("Provenance: schedlued boot buffer async task %llu.", cookie);
			put_cpu();
			return;
		}
		put_cpu();
		tighten_identifier(&get_prov_identifier(tmp));
		relay_write(long_prov_chan, tmp, sizeof(union long_prov_elt));
		long_buffer_head = tmp->msg_info.next;
		kmem_cache_free(long_provenance_cache, tmp);
		tmp = long_buffer_head;
	}
	pr_info("Provenance: finished task %llu.", cookie);
}

bool relay_ready;
bool relay_initialized;
/*!
 * @brief Write whatever in boot buffer to relay buffer when relay buffer is ready.
 *
 * This function writes what's in boot_buffer to relay buffer for regular provenance entries,
 * and what's in long_boot_buffer to relay buffer for long provenance entries.
 * It also frees memory after it is done writing.
 * Once done, set boolean value relay_ready to true to signal that relay buffer is ready to be used.
 *
 */
extern union long_prov_elt *prov_machine;
void refresh_prov_machine(void);
void write_boot_buffer(void)
{
	async_cookie_t cookie;

	if (prov_machine_id == 0 || prov_boot_id == 0 || !relay_initialized)
		return;

	relay_ready = true;

	refresh_prov_machine();
	relay_write(long_prov_chan, prov_machine, sizeof(union long_prov_elt));

	// asynchronously empty the buffer
	cookie = async_schedule(__async_handle_boot_buffer, NULL);
	pr_info("Provenance: schedlued boot buffer async task %llu.", cookie);

	// asynchronously empty the buffer
	cookie = async_schedule(__async_handle_long_boot_buffer, NULL);
	pr_info("Provenance: schedlued long boot buffer async task %llu.", cookie);
}

/*!
 * @brief Create a provenance relay buffer channel for both regular and long provenance entries.
 *
 * Each relay channel in the list must have a unique name.
 * Each relay channel contains a relay buffer for regular provenance entries and a relay buffer for long provenance entries.
 * @param buffer Contains the name of the relay buffer for regular provenance entries (prepend "long_" for the relay buffer name for long provenance entries)
 * @param len The length of the name of the regular relay buffer.
 * @return 0 if no error occurred; -EFAULT if name already exists for relay buffer or opening new relay buffer failed; -ENOMEM if length of the name of the relay buffer is too long. Other error codes unknown.
 *
 */
int prov_create_channel(char *buffer, size_t len)
{
	struct relay_list *tmp;
	char *long_name = kzalloc(PATH_MAX, GFP_KERNEL);
	struct rchan *chan;
	struct rchan *long_chan;
	int rc = 0;

	// Test if channel already exists based on the name.
	list_for_each_entry(tmp, &relay_list, list) {
		if (strcmp(tmp->name, buffer) == 0) {
			rc = -EFAULT;
			goto out;
		}
	}

	if (len > PATH_MAX - 5)
		return -ENOMEM;
	snprintf(long_name, PATH_MAX, "long_%s", buffer);
	chan = relay_open(buffer, NULL, PROV_RELAY_BUFF_SIZE, PROV_NB_SUBBUF, &relay_callbacks, NULL);
	if (!chan) {
		rc = -EFAULT;
		goto out;
	}
	long_chan = relay_open(long_name, NULL, PROV_RELAY_BUFF_SIZE, PROV_NB_SUBBUF, &relay_callbacks, NULL);
	if (!long_chan) {
		rc = -EFAULT;
		goto out;
	}
	prov_add_relay(buffer, chan, long_chan);
out:
	kfree(long_name);
	return rc;
}


static void insert_boot_buffer(union prov_elt *msg)
{
	union prov_elt *tmp = kmem_cache_alloc(provenance_cache, GFP_ATOMIC);

	__memcpy_ss(tmp, sizeof(struct provenance), msg, sizeof(union prov_elt));
	tmp->msg_info.next = buffer_head;
	buffer_head = tmp;
}

/*!
 * @brief Write provenance information to relay buffer or to boot buffer if relay buffer is not ready yet during boot.
 *
 * If in an unlikely event that relay is not ready, provenance information should be written to the boot buffer.
 * However, in an unlikely event that the boot buffer is full, an error is thrown.
 * Otherwise (i.e., boot buffer is not full) provenance information is written to the next empty slot in the boot buffer.
 * If relay buffer is ready, write to relay buffer.
 * It will write to every relay buffer in the relay_list for every CamQuery query use.
 * This is because once provenance is read from a relay buffer, it will be consumed from the buffer.
 * We therefore need to write to multiple relay buffers if we want to consume/use same provenance data multiple times.
 * @param msg Provenance information to be written to either boot buffer or relay buffer.
 * @return NULL
 *
 */
void prov_write(union prov_elt *msg, size_t size)
{
	struct relay_list *tmp;

	BUG_ON(prov_type_is_long(prov_type(msg)));

	prov_jiffies(msg) = get_jiffies_64();
	if (unlikely(!relay_ready))
		insert_boot_buffer(msg);
	else {
		prov_policy.prov_written = true;
		list_for_each_entry(tmp, &relay_list, list) {
			relay_write(tmp->prov, msg, size);
		}
	}
}

static void insert_long_boot_buffer(union long_prov_elt *msg)
{
	union long_prov_elt *tmp = kmem_cache_alloc(long_provenance_cache, GFP_ATOMIC);

	__memcpy_ss(tmp, sizeof(union long_prov_elt), msg, sizeof(union long_prov_elt));
	tmp->msg_info.next = long_buffer_head;
	long_buffer_head = tmp;
}

/*!
 * @brief Write long provenance information to relay buffer or to boot buffer if relay buffer is not ready yet during boot.
 *
 * This function performs the same function as "prov_write" function except that it writes a long provenance information,
 * instead of regular provenance information to the buffer.
 * @param msg Long provenance information to be written to either long boot buffer or long relay buffer.
 *
 */
void long_prov_write(union long_prov_elt *msg, size_t size)
{
	struct relay_list *tmp;

	BUG_ON(!prov_type_is_long(prov_type(msg)));

	prov_jiffies(msg) = get_jiffies_64();
	if (unlikely(!relay_ready))
		insert_long_boot_buffer(msg);
	else {
		prov_policy.prov_written = true;
		list_for_each_entry(tmp, &relay_list, list) {
			relay_write(tmp->long_prov, msg, size);
		}
	}
}

/*!
 * @brief Initialize relay buffer for provenance.
 *
 * Initialize provenance relay buffer with a base relay buffer for regular provenance entries,
 * and a base relay buffer for long provenance entries.
 * This will become the first relay channel in the relay_list.
 * Then we can write down whatever is in the boot buffer to relay buffer.
 * Head of the relay_list is defined in hooks.c file.
 * @return 0 if no error occurred.
 *
 */
static int __init relay_prov_init(void)
{
	prov_chan = relay_open(PROV_BASE_NAME, NULL, PROV_RELAY_BUFF_SIZE, PROV_NB_SUBBUF, &relay_callbacks, NULL);
	if (!prov_chan)
		panic("Provenance: relay_open failure\n");

	long_prov_chan = relay_open(LONG_PROV_BASE_NAME, NULL, PROV_RELAY_BUFF_SIZE, PROV_NB_SUBBUF, &relay_callbacks, NULL);
	if (!long_prov_chan)
		panic("Provenance: relay_open failure\n");
	prov_add_relay(PROV_BASE_NAME, prov_chan, long_prov_chan);
	relay_initialized = true;
	write_boot_buffer();
	pr_info("Provenance: relay ready.\n");
	return 0;
}
core_initcall(relay_prov_init);
