/*
 *
 * Author: Thomas Pasquier <thomas.pasquier@bristol.ac.uk>
 *
 * Copyright (C) 2015-2018 University of Cambridge, Harvard University, University of Bristol
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

#include "provenance.h"
#include "provenance_relay.h"

#define PROV_BASE_NAME "provenance"
#define LONG_PROV_BASE_NAME "long_provenance"

/* Global variables: variable declarations in provenance.h */
static struct rchan *prov_chan;
static struct rchan *long_prov_chan;
atomic64_t prov_relation_id = ATOMIC64_INIT(0);
atomic64_t prov_node_id = ATOMIC64_INIT(0);

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
	.create_buf_file	= create_buf_file_handler,
	.remove_buf_file	= remove_buf_file_handler,
};

/*!
 * @brief Write whatever in boot buffer to relay buffer when relay buffer is ready.
 *
 * This function writes what's in boot_buffer to relay buffer for regular provenance entries,
 * and what's in long_boot_buffer to relay buffer for long provenance entries.
 * It also frees memory after it is done writing.
 *
 */
static void write_boot_buffer(void)
{
	if (boot_buffer->nb_entry > 0)
		relay_write(prov_chan, boot_buffer->buffer, boot_buffer->nb_entry * sizeof(union prov_elt));
	kfree(boot_buffer);
	boot_buffer = NULL;

	if (long_boot_buffer->nb_entry > 0)
		relay_write(long_prov_chan, long_boot_buffer->buffer, long_boot_buffer->nb_entry * sizeof(union long_prov_elt));
	kfree(long_boot_buffer);
	long_boot_buffer = NULL;
}

bool relay_ready;
extern struct workqueue_struct *prov_queue;

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
 * @brief Initialize relay buffer for provenance.
 *
 * Initialize provenance relay buffer with a base relay buffer for regular provenance entries,
 * and a base relay buffer for long provenance entries.
 * This will become the first relay channel in the relay_list.
 * Once done, set boolean value relay_ready to true to signal that relay buffer is ready to be used.
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
	relay_ready = true;

	write_boot_buffer();
	pr_info("Provenance: relay ready.\n");
	return 0;
}
core_initcall(relay_prov_init);
