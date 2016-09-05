/*
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

#include <linux/security.h>
#include <linux/fs.h>

// cause softlockup if both pointer directly added to inode
// no time to figure out why, work around
struct camflow_i_ptr{
  void* provenance;
  void* ifc;
};

extern struct kmem_cache *camflow_cache;
#define alloc_camflow(inode, gfp) if(!inode->i_camflow) inode->i_camflow = kmem_cache_zalloc(camflow_cache, gfp);
#define inode_get_provenance(inode) ((prov_msg_t*)((struct camflow_i_ptr*)inode->i_camflow)->provenance)
#define inode_set_provenance(inode, v) ((struct camflow_i_ptr*)inode->i_camflow)->provenance=v
#define inode_get_ifc(inode) ((struct ifc_struct*)((struct camflow_i_ptr*)inode->i_camflow)->ifc)
#define inode_set_ifc(inode, v) ((struct camflow_i_ptr*)inode->i_camflow)->ifc=v

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
