/*
*
* Author: Thomas Pasquier <tfjmp@seas.harvard.edu>
*
* Copyright (C) 2016 Harvard University
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License version 2, as
* published by the Free Software Foundation; either version 2 of the License, or
*	(at your option) any later version.
*
*/

#ifndef _CAMFLOW_UTILS_PROVENANCE_H
#define _CAMFLOW_UTILS_PROVENANCE_H

#include <linux/fs.h>
#include <linux/namei.h>

static inline struct inode* file_name_to_inode(const char* name){
  struct path path;
  struct inode* inode;
  if(kern_path(name, LOOKUP_FOLLOW, &path)){
    printk(KERN_ERR "CamFlow: Failed file look up (%s).", name);
    return NULL;
  }
  inode = path.dentry->d_inode;
  path_put(&path);
  return inode;
}

#endif
