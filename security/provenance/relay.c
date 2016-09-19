/*
*
* Author: Thomas Pasquier <tfjmp2@cam.ac.uk>
*
* Copyright (C) 2015 University of Cambridge
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License version 2, as
* published by the Free Software Foundation; either version 2 of the License, or
*	(at your option) any later version.
*
*/

#include <linux/init.h>
#include <linux/module.h>
#include <linux/debugfs.h>

#include "provenance.h"

#define PROV_BASE_NAME "provenance"
#define LONG_PROV_BASE_NAME "long_provenance"

/* global variable, extern in provenance.h */
 struct rchan *prov_chan=NULL;
 struct rchan *long_prov_chan=NULL;
 atomic64_t prov_relation_id=ATOMIC64_INIT(0);
 atomic64_t prov_node_id=ATOMIC64_INIT(0);

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

/* VALUE WERE CHOSEN RANDOMLY, TODO select value that makes sense */

#define PROV_ELEMENT_IN_SUBBUF      64
#define LONG_PROV_ELEMENT_IN_SUBBUF 8
#define PROV_NB_SUBBUF              64

static int __init relay_prov_init(void)
{
  printk(KERN_INFO "Provenance init.\n");
  prov_chan = relay_open(PROV_BASE_NAME, NULL, PROV_ELEMENT_IN_SUBBUF*sizeof(prov_msg_t), PROV_NB_SUBBUF, &relay_callbacks, NULL);
  if(prov_chan==NULL){
    printk(KERN_ERR "Provenance: relay_open failure\n");
    return 0;
  }

  long_prov_chan = relay_open(LONG_PROV_BASE_NAME, NULL, LONG_PROV_ELEMENT_IN_SUBBUF*sizeof(long_prov_msg_t), PROV_NB_SUBBUF, &relay_callbacks, NULL);
  if(long_prov_chan==NULL){
    printk(KERN_ERR "Provenance: relay_open failure\n");
    return 0;
  }

  printk(KERN_INFO "Provenance module started!\n");
  return 0;
}

core_initcall(relay_prov_init);
