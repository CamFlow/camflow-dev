/*
*
* Author: Thomas Pasquier <thomas.pasquier@cl.cam.ac.uk>
*
* Copyright (C) 2016 University of Cambridge
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License version 2, as
* published by the Free Software Foundation; either version 2 of the License, or
*	(at your option) any later version.
*
*/

#ifndef _LINUX_CAMFLOW_HEAD_H
#define _LINUX_CAMFLOW_HEAD_H

#include <linux/security.h>
#include <linux/fs.h>

#include <uapi/linux/provenance.h>
#include <uapi/linux/ifc.h>

// cause softlockup if both pointer directly added to inode
// no time to figure out why, work around
struct camflow_i_ptr{
  void* provenance;
  void* ifc;
};

extern struct kmem_cache *camflow_cache;

static inline void alloc_camflow(struct inode *inode, gfp_t priority){
  if(!inode->i_camflow){ // if not already set
    inode->i_camflow = kmem_cache_zalloc(camflow_cache, priority);
  }
}

static inline prov_msg_t* __raw_inode_provenance(const struct inode *inode){
  if(inode->i_camflow == NULL){
    return NULL;
  }
  return ((prov_msg_t*)((struct camflow_i_ptr*)inode->i_camflow)->provenance);
}

static inline void inode_set_provenance(struct inode *inode, prov_msg_t *v){
  if(inode->i_camflow == NULL){
    return;
  }
  ((struct camflow_i_ptr*)inode->i_camflow)->provenance=v;
}


static inline struct ifc_struct* inode_get_ifc(const struct inode *inode){
  if(inode->i_camflow == NULL){
    return NULL;
  }
  return ((struct ifc_struct*)((struct camflow_i_ptr*)inode->i_camflow)->ifc);
}

static inline void inode_set_ifc(struct inode *inode, struct ifc_struct *v){
  if(inode->i_camflow == NULL){
    return;
  }
  ((struct camflow_i_ptr*)inode->i_camflow)->ifc=v;
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

int provenance_inode_init_security(struct inode *inode, struct inode *dir,
				       const struct qstr *qstr,
				       const char **name,
				       void **value, size_t *len);
#endif
