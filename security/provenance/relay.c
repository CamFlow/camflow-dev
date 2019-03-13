/*
 *
 * Author: Thomas Pasquier <thomas.pasquier@bristol.ac.uk>
 *
 * Copyright (C) 2015-2019 University of Cambridge, Harvard University, University of Bristol
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/debugfs.h>
#include <linux/async.h>
#include <linux/delay.h>

#include "provenance.h"
#include "provenance_relay.h"

#define PROV_BASE_NAME          "provenance"
#define LONG_PROV_BASE_NAME     "long_provenance"

#define declare_insert_buffer_fcn(fcn_name, msg_type, buffer_type, max_entry)		\
	static __always_inline void fcn_name(msg_type * msg, buffer_type * buf)		\
	{										\
		buffer_type *tmp = buf;							\
		while (tmp->next != NULL) {						\
			tmp = tmp->next;						\
		}									\
		if (tmp->nb_entry >= max_entry) {					\
			tmp->next = kzalloc(sizeof(buffer_type), GFP_ATOMIC);		\
			if (unlikely(!tmp->next)) {					\
				panic("Provenance: could not allocate boot_buffer."); }	\
			tmp = tmp->next;						\
		}									\
		memcpy(&(tmp->buffer[tmp->nb_entry]), msg, sizeof(msg_type));		\
		tmp->nb_entry++;							\
	}										\

declare_insert_buffer_fcn(insert_boot_buffer,
			  union prov_elt,
			  struct prov_boot_buffer,
			  PROV_INITIAL_BUFF_SIZE);
declare_insert_buffer_fcn(insert_long_boot_buffer,
			  union long_prov_elt,
			  struct prov_long_boot_buffer,
			  PROV_INITIAL_LONG_BUFF_SIZE);

/* Global variables: variable declarations in provenance.h */
static struct rchan *prov_chan;
static struct rchan *long_prov_chan;
atomic64_t prov_relation_id = ATOMIC64_INIT(0);
atomic64_t prov_node_id = ATOMIC64_INIT(0);

bool is_relay_full(struct rchan *chan, int cpu)
{
	int ret;
	int rc = 0;
	struct rchan_buf *buf;

	if ((buf = *per_cpu_ptr(chan->buf, cpu))) {
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

static void __async_handle_boot_buffer(void *_buf, async_cookie_t cookie)
{
	int i;
	int cpu;
	struct prov_boot_buffer *tmp;
	struct prov_boot_buffer *buf = _buf;

	msleep(1000);
	pr_info("Provenance: async boot buffer task %llu running...", cookie);

	while (buf != NULL) {
		if (buf->nb_entry > 0) {
			cpu = get_cpu();
			for (i = 0; i < buf->nb_entry; i++) {
				tighten_identifier(&get_prov_identifier(&(buf->buffer[i])));
				if (prov_is_relation(&(buf->buffer[i]))) {
					tighten_identifier(&(buf->buffer[i].relation_info.snd));
					tighten_identifier(&(buf->buffer[i].relation_info.rcv));
				}
				if (is_relay_full(prov_chan, cpu)) {
					// we try again later
					cookie = async_schedule(__async_handle_boot_buffer, buf);
					pr_info("Provenance: schedlued boot buffer async task %llu.", cookie);
					return;
				} else
					relay_write(prov_chan, &buf->buffer[i], sizeof(union prov_elt));
			}
			put_cpu();
		}
		tmp = buf;
		buf = buf->next;
		kfree(tmp);
	}
	pr_info("Provenance: finished task %llu.", cookie);
}

static void __async_handle_long_boot_buffer(void *_buf, async_cookie_t cookie)
{
	int i;
	int cpu;
	struct prov_long_boot_buffer *tmp;
	struct prov_long_boot_buffer *buf = _buf;

	msleep(1000);
	pr_info("Provenance: async long boot buffer task %llu running...", cookie);

	while (buf != NULL) {
		if (buf->nb_entry > 0) {
			cpu = get_cpu();
			for (i = 0; i < buf->nb_entry; i++) {
				tighten_identifier(&get_prov_identifier(&(buf->buffer[i])));
				if (is_relay_full(long_prov_chan, cpu)) {
					// we try again later
					cookie = async_schedule(__async_handle_long_boot_buffer, buf);
					pr_info("Provenance: schedlued long boot buffer async task %llu.", cookie);
					return;
				} else
					relay_write(long_prov_chan, &buf->buffer[i], sizeof(union long_prov_elt));
			}
			put_cpu();
		}
		tmp = buf;
		buf = buf->next;
		kfree(tmp);
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
	struct prov_boot_buffer *tmp;
	struct prov_long_boot_buffer *ltmp;
	async_cookie_t cookie;

	if (prov_machine_id == 0 || prov_boot_id == 0 || !relay_initialized)
		return;

	relay_ready = true;
	tmp = boot_buffer;
	boot_buffer = NULL;
	ltmp = long_boot_buffer;
	long_boot_buffer = NULL;

	refresh_prov_machine();
	relay_write(long_prov_chan, prov_machine, sizeof(union long_prov_elt));

	// asynchronously empty the buffer
	cookie = async_schedule(__async_handle_boot_buffer, tmp);
	pr_info("Provenance: schedlued boot buffer async task %llu.", cookie);

	// asynchronously empty the buffer
	cookie = async_schedule(__async_handle_long_boot_buffer, ltmp);
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

	if (strlen(buffer) > len)
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
		insert_boot_buffer(msg, boot_buffer);
	else {
		prov_policy.prov_written = true;
		list_for_each_entry(tmp, &relay_list, list) {
			relay_write(tmp->prov, msg, size);
		}
	}
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
		insert_long_boot_buffer(msg, long_boot_buffer);
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
