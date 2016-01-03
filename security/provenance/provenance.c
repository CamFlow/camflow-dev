/*
*
* /linux/security/relay_prov/relay_prov.c
*
* Author: Thomas Pasquier <tfjmp2@cam.ac.uk>
*
* Copyright (C) 2015 University of Cambridge
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License version 2, as
* published by the Free Software Foundation.
*
*/

#include <linux/init.h>
#include <linux/module.h>
#include <linux/provenance.h>
#include <linux/debugfs.h>

#define BASE_NAME "provenance"

/* global variable, extern in relay_prov.h */
 struct rchan *prov_chan;
 atomic64_t prov_evt_count=ATOMIC64_INIT(1);

/*
 * create_buf_file() callback.  Creates relay file in debugfs.
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

/*
 * remove_buf_file() callback.  Removes relay file from debugfs.
 */
static int remove_buf_file_handler(struct dentry *dentry)
{
        debugfs_remove(dentry);
        return 0;
}

/*
 * relay interface callbacks
 */
static struct rchan_callbacks relay_callbacks =
{
        .create_buf_file = create_buf_file_handler,
        .remove_buf_file = remove_buf_file_handler,
};

static int __init relay_prov_init(void)
{
  printk(KERN_INFO "Provenance init.\n");
  prov_chan = relay_open(BASE_NAME, NULL, 8192, 4, &relay_callbacks, NULL);
  if(prov_chan==NULL){
    printk(KERN_ERR "Provenance: relay_open failure\n");
    return 0;
  }
  prov_print("Provenance module started!");
  return 0;
}

core_initcall(relay_prov_init);
