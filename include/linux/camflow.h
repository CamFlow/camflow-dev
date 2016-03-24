/*
*
* /linux/include/linux/ifc.h
*
* Author: Thomas Pasquier <tfjmp2@cam.ac.uk>
*
* Copyright (C) 2016 University of Cambridge
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License version 2, as
* published by the Free Software Foundation.
*
*/

#ifndef _LINUX_CAMFLOW_HEAD_H
#define _LINUX_CAMFLOW_HEAD_H

#include <linux/fs.h>
#include <linux/namei.h>

// cause softlockup if both pointer directly added to inode
// no time to figure out why, work around
struct camflow_i_ptr{
  void* provenance;
  void* ifc;
};

extern struct kmem_cache *camflow_cache;

static inline void alloc_camflow(struct inode *inode, gfp_t gfp)
{
  if(!inode->i_camflow)
    inode->i_camflow = kmem_cache_zalloc(camflow_cache, gfp);
}

// free only if both ptr have been freed
static inline void free_camflow(struct inode *inode){
  struct camflow_i_ptr* camflow;
  if(!inode->i_camflow){
    camflow = inode->i_camflow;
    if(camflow->provenance==NULL&&camflow->ifc==NULL){ // nothing left in the structure
      kmem_cache_free(camflow_cache, camflow);
      inode->i_camflow = NULL;
    }
  }
}

static inline void* inode_get_provenance(const struct inode *inode){
  struct camflow_i_ptr* camflow = inode->i_camflow;
  return camflow->provenance;
}

static inline void inode_set_provenance(const struct inode *inode, void** provenance){
  struct camflow_i_ptr* camflow = inode->i_camflow;
  if(provenance==NULL){
    camflow->provenance=NULL;
  }else{
    camflow->provenance=(*provenance);
  }
}

static inline void* inode_get_ifc(const struct inode *inode){
  struct camflow_i_ptr* camflow = inode->i_camflow;
  return camflow->ifc;
}

static inline void inode_set_ifc(const struct inode *inode, void** ifc){
  struct camflow_i_ptr* camflow = inode->i_camflow;
  if(ifc==NULL){
    camflow->ifc=NULL;
  }else{
    camflow->ifc=(*ifc);
  }
}

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
