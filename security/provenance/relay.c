// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2016 University of Cambridge,
 * Copyright (C) 2016-2017 Harvard University,
 * Copyright (C) 2017-2018 University of Cambridge,
 * Copyright (C) 2018-2021 University of Bristol
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
#include "provenance_machine.h"
#include "memcpy_ss.h"

#define PROV_BASE_NAME          "provenance"
#define LONG_PROV_BASE_NAME     "long_provenance"

static struct rchan *prov_chan;
static struct rchan *long_prov_chan;

/* Global variables: variable declarations in provenance.h */
atomic64_t prov_relation_id = ATOMIC64_INIT(0);
atomic64_t prov_node_id = ATOMIC64_INIT(0);
atomic64_t prov_drop = ATOMIC64_INIT(0);

/*!
 * @brief Flush every relay buffer element in the relay list.
 */
void prov_flush(void)
{
	if (unlikely(!relay_ready))
		return;

	relay_flush(prov_chan);
	relay_flush(long_prov_chan);
}

static bool __is_relay_full(struct rchan *chan)
{
	int ret;
	int rc = 0;
	struct rchan_buf *buf = *this_cpu_ptr(chan->buf);

	if (buf) {
		ret = relay_buf_full(buf);
		if (ret)
			pr_warn("Provenance: relay (%s) is full.",
				chan->base_filename);
		rc += ret;
	}
	if (rc)
		return true;
	return false;
}

/*!
 * @brief Callback function of function "create_buf_file". This callback
 * function creates relay file in "debugfs".
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
 * @brief Callback function of function "remove_buf_file". This callback
 * function removes the relay file from "debugfs".
 */
static int remove_buf_file_handler(struct dentry *dentry)
{
	debugfs_remove(dentry);
	return 0;
}

/*
 * subbuf_start - called on buffer-switch to a new sub-buffer
 * @buf: the channel buffer containing the new sub-buffer
 * @subbuf: the start of the new sub-buffer
 * @prev_subbuf: the start of the previous sub-buffer
 * @prev_padding: unused space at the end of previous sub-buffer
 *
 * return 1 do not log
 * return 0 do not log
 */
static int subbuf_start_handler(struct rchan_buf *buf,
				void *subbuf,
				void *prev_subbuf,
				size_t prev_padding)
{
	// the relay is full let's not log
	// this avoid overwritting
	if (relay_buf_full(buf)) {
		// count the number of element dropped
		atomic64_inc(&prov_drop);
		return 0;
	}
	return 1;
}


/* Relay interface callback functions */
static struct rchan_callbacks relay_callbacks = {
	.subbuf_start = subbuf_start_handler,
	.create_buf_file = create_buf_file_handler,
	.remove_buf_file = remove_buf_file_handler,
};

static void __async_handle_boot_buffer(void *_buf, async_cookie_t cookie)
{
	struct list_head *ele, *next;
	struct boot_buffer *entry;
	unsigned long irqflags;

	msleep(1000);
	pr_info("Provenance: async boot buffer task %llu running...", cookie);

	spin_lock_irqsave(&lock_buffer, irqflags);
	list_for_each_safe(ele, next, &buffer_list) {
		entry = list_entry(ele, struct boot_buffer, list);

		// check if relay is full
		if (__is_relay_full(prov_chan)) {
			cookie = async_schedule(__async_handle_boot_buffer,
						NULL);
			pr_info("Provenance: schedlued async task %llu.",
				cookie);
			goto out;
		}

		// tighten provenance entry
		tighten_identifier(&get_prov_identifier(&(entry->msg)));
		if (prov_is_relation(&(entry->msg))) {
			tighten_identifier(&(entry->msg.relation_info.snd));
			tighten_identifier(&(entry->msg.relation_info.rcv));
		}

		relay_write(prov_chan, &(entry->msg), sizeof(union prov_elt));

		list_del(&(entry->list));
		kmem_cache_free(boot_buffer_cache, entry);
	}
	pr_info("Provenance: finished task %llu.", cookie);
out:
	spin_unlock_irqrestore(&lock_buffer, irqflags);
}

static void __async_handle_long_boot_buffer(void *_buf, async_cookie_t cookie)
{
	struct list_head *ele, *next;
	struct long_boot_buffer *entry;
	unsigned long irqflags;

	msleep(1000);
	pr_info("Provenance: async long boot buffer task %llu running...",
		cookie);

	spin_lock_irqsave(&lock_long_buffer, irqflags);
	list_for_each_safe(ele, next, &long_buffer_list) {
		entry = list_entry(ele, struct long_boot_buffer, list);

		// check if relay is full
		if (__is_relay_full(prov_chan)) {
			cookie = async_schedule(__async_handle_long_boot_buffer,
						NULL);
			pr_info("Provenance: schedlued long async task %llu.",
				cookie);
			goto out;
		}

		// tighten provenance entry
		tighten_identifier(&get_prov_identifier(&(entry->msg)));

		relay_write(long_prov_chan, &(entry->msg),
			    sizeof(union long_prov_elt));

		list_del(&(entry->list));
		kmem_cache_free(long_boot_buffer_cache, entry);
	}
	pr_info("Provenance: finished task %llu.", cookie);
out:
	spin_unlock_irqrestore(&lock_long_buffer, irqflags);
}

bool relay_ready;
bool relay_initialized;
/*!
 * @brief Write whatever in boot buffer to relay buffer when relay buffer is
 * ready.
 *
 * This function writes what's in boot_buffer to relay buffer for regular
 * provenance entries,
 * and what's in long_boot_buffer to relay buffer for long provenance entries.
 * It also frees memory after it is done writing.
 * Once done, set boolean value relay_ready to true to signal that relay buffer
 * is ready to be used.
 *
 */
static void __write_boot_buffer(void)
{
	async_cookie_t cookie;

	relay_ready = true;

	refresh_prov_machine();
	relay_write(long_prov_chan, prov_machine, sizeof(union long_prov_elt));

	// asynchronously empty the buffer
	if (!list_empty(&buffer_list)) {
		cookie = async_schedule(__async_handle_boot_buffer, NULL);
		pr_info("Provenance: schedlued async task %llu.",
			cookie);
	}

	// asynchronously empty the buffer
	if (!list_empty(&long_buffer_list)) {
		cookie = async_schedule(__async_handle_long_boot_buffer, NULL);
		pr_info("Provenance: schedlued long async task %llu.", cookie);
	}
}

static void insert_boot_buffer(union prov_elt *msg)
{
	struct boot_buffer *tmp = kmem_cache_zalloc(boot_buffer_cache,
						    GFP_ATOMIC);
	unsigned long irqflags;

	__memcpy_ss(&(tmp->msg), sizeof(union prov_elt),
		    msg, sizeof(union prov_elt));
	INIT_LIST_HEAD(&(tmp->list));
	spin_lock_irqsave(&lock_buffer, irqflags);
	list_add(&(tmp->list), &buffer_list);
	spin_unlock_irqrestore(&lock_buffer, irqflags);
}

/*!
 * @brief Write provenance information to relay buffer or to boot buffer if
 * relay buffer is not ready yet during boot.
 *
 * If in an unlikely event that relay is not ready, provenance information
 * should be written to the boot buffer.
 * However, in an unlikely event that the boot buffer is full, an error is
 * thrown.
 * Otherwise (i.e., boot buffer is not full) provenance information is written
 * to the next empty slot in the boot buffer.
 * If relay buffer is ready, write to relay buffer.
 * This is because once provenance is read from a relay buffer, it will be
 * consumed from the buffer.
 * We therefore need to write to multiple relay buffers if we want to
 * consume/use same provenance data multiple times.
 * @param msg Provenance information to be written to either boot buffer or
 * relay buffer.
 * @return NULL
 *
 */
void prov_write(union prov_elt *msg, size_t size)
{
	BUG_ON(prov_type_is_long(prov_type(msg)));

	prov_jiffies(msg) = get_jiffies_64();
	if (unlikely(!relay_ready))
		insert_boot_buffer(msg);
	else {
		prov_written = true;
		relay_write(prov_chan, msg, size);
	}
}

static void insert_long_boot_buffer(union long_prov_elt *msg)
{
	struct long_boot_buffer *tmp = kmem_cache_zalloc(long_boot_buffer_cache,
							 GFP_ATOMIC);
	unsigned long irqflags;

	__memcpy_ss(&(tmp->msg), sizeof(union long_prov_elt),
		    msg, sizeof(union long_prov_elt));
	INIT_LIST_HEAD(&(tmp->list));
	spin_lock_irqsave(&lock_long_buffer, irqflags);
	list_add(&(tmp->list), &long_buffer_list);
	spin_unlock_irqrestore(&lock_long_buffer, irqflags);
}

/*!
 * @brief Write long provenance information to relay buffer or to boot buffer if
 * relay buffer is not ready yet during boot.
 *
 * This function performs the same function as "prov_write" function except that
 * it writes a long provenance information,
 * instead of regular provenance information to the buffer.
 * @param msg Long provenance information to be written to either long boot
 * buffer or long relay buffer.
 *
 */
void long_prov_write(union long_prov_elt *msg, size_t size)
{
	BUG_ON(!prov_type_is_long(prov_type(msg)));

	prov_jiffies(msg) = get_jiffies_64();
	if (unlikely(!relay_ready))
		insert_long_boot_buffer(msg);
	else {
		prov_written = true;
		relay_write(long_prov_chan, msg, size);
	}
}

/*!
 * @brief Initialize relay buffer for provenance.
 *
 * Initialize provenance relay buffer with a base relay buffer for regular
 * provenance entries,
 * and a base relay buffer for long provenance entries.
 * Then we can write down whatever is in the boot buffer to relay buffer.
 * @return 0 if no error occurred.
 *
 */
int relay_prov_init(struct relay_conf *conf)
{
	if (relay_initialized) // cannot be initialized twice
		return 0;

	// set boot and machine IDs
	prov_boot_id = conf->boot_id;
	prov_machine_id = conf->machine_id;

	// initializing relays
	prov_chan = relay_open(PROV_BASE_NAME, NULL, prov_relay_size(conf->buff_exp),
			       conf->subuf_nb, &relay_callbacks, NULL);
	if (!prov_chan)
		panic("Provenance: relay_open failure\n");

	long_prov_chan = relay_open(LONG_PROV_BASE_NAME, NULL,
				    prov_relay_size(conf->buff_exp),
				    conf->subuf_nb,
				    &relay_callbacks,
				    NULL);
	if (!long_prov_chan)
		panic("Provenance: relay_open failure\n");

	init_prov_machine();
	__write_boot_buffer();

	// all good logging info
	pr_info("Provenance: relay ready.\n");
	pr_info("Provenance: boot_id %u", conf->boot_id);
	pr_info("Provenance: machine_id %u", conf->machine_id);
	pr_info("Provenance: buff_exp %u", conf->buff_exp);
	pr_info("Provenance: subuf_nb %u", conf->subuf_nb);

	relay_initialized = true;

	return 0;
}
