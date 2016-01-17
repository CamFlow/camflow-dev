/*
*
* /linux/security/provenance/fs.c
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

#include <linux/security.h>
#include <linux/provenance.h>

#include "fs.h"

bool prov_enabled=false;

static ssize_t prov_write_enable(struct file *file, const char __user *buf,
				 size_t count, loff_t *ppos)

{
  char* page = NULL;
  ssize_t length;
  bool new_value;
  int tmp;

  /* no partial write */
  if(*ppos > 0)
    return -EINVAL;

  if(__kuid_val(current_euid())!=0)
    return -EPERM;

  page = (char *)get_zeroed_page(GFP_KERNEL);
  if (!page)
    return ENOMEM;

  length=-EFAULT;
	if (copy_from_user(page, buf, count))
		goto out;

  length = -EINVAL;
  if (sscanf(page, "%d", &tmp) != 1)
		goto out;

  new_value=tmp;
  if(new_value!=prov_enabled){
    if(new_value)
      prov_print("Enabling provenance capture");
    else
      prov_print("Disabling provenance capture");
    prov_enabled=new_value;
  }
  length=count;
out:
  free_page((unsigned long)page);
  return length;
}

#define TMPBUFLEN	12

static ssize_t prov_read_enable(struct file *filp, char __user *buf,
				size_t count, loff_t *ppos)
{
	char tmpbuf[TMPBUFLEN];
	ssize_t length;
  int tmp = prov_enabled;

  /* no partial read */
  if(*ppos > 0)
    return -EINVAL;

	length = scnprintf(tmpbuf, TMPBUFLEN, "%d", tmp);
	return simple_read_from_buffer(buf, count, ppos, tmpbuf, length);
}

static const struct file_operations prov_enable_ops = {
	.write		= prov_write_enable,
  .read     = prov_read_enable,
	.llseek		= generic_file_llseek,
};

static int __init init_prov_fs(void)
{
   struct dentry *prov_dir;

   prov_dir = securityfs_create_dir("provenance", NULL);

   securityfs_create_file("enable", 0644, prov_dir, NULL, &prov_enable_ops);
   return 0;
}

__initcall(init_prov_fs);
