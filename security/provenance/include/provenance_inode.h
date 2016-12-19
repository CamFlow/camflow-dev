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
#ifndef CONFIG_SECURITY_PROVENANCE_INODE
#define CONFIG_SECURITY_PROVENANCE_INODE
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/namei.h>

#include "provenance_long.h" // for record_inode_name

#define is_inode_dir(inode) S_ISDIR(inode->i_mode)
#define is_inode_socket(inode) S_ISSOCK(inode->i_mode)
#define is_inode_file(inode) S_ISREG(inode->i_mode)

static inline struct inode* file_name_to_inode(const char* name){
  struct path path;
  struct inode* inode;
  if(kern_path(name, LOOKUP_FOLLOW, &path)){
    printk(KERN_ERR "Provenance: Failed file look up (%s).", name);
    return NULL;
  }
  inode = path.dentry->d_inode;
  path_put(&path);
  return inode;
}

static inline void prov_read_inode_type(prov_msg_t* iprov, struct inode *inode){
  uint64_t type = ENT_INODE_UNKNOWN;
  iprov->inode_info.mode=inode->i_mode;
  if(S_ISBLK(inode->i_mode)){
    type=ENT_INODE_BLOCK;
  }else if(S_ISCHR(inode->i_mode)){
    type=ENT_INODE_CHAR;
  }else if(S_ISDIR(inode->i_mode)){
    type=ENT_INODE_DIRECTORY;
  }else if(S_ISFIFO(inode->i_mode)){
    type=ENT_INODE_FIFO;
  }else if(S_ISLNK(inode->i_mode)){
    type=ENT_INODE_LINK;
  }else if(S_ISREG(inode->i_mode)){
    type=ENT_INODE_FILE;
  }else if(S_ISSOCK(inode->i_mode)){
    type=ENT_INODE_SOCKET;
  }
  prov_type(iprov)=type;
}

static inline void provenance_mark_as_opaque(const char* name){
  struct inode* in;
  prov_msg_t* prov;

  in = file_name_to_inode(name);
  if(!in){
    printk(KERN_ERR "Provenance: could not find %s file.", name);
  }else{
    prov = in->i_provenance;
    if(prov){
      set_opaque(prov);
    }
  }
}

/*static inline prov_msg_t* inode_provenance_no_name(struct inode* inode)
{
  prov_msg_t* iprov = inode->i_provenance;
  if(unlikely(iprov==NULL)){
    return NULL;
  }
  prov_read_inode_type(iprov, inode);
  return iprov;
}

static inline prov_msg_t* inode_provenance(struct inode* inode)
{
  prov_msg_t* iprov = inode_provenance_no_name(inode);
  if(unlikely(iprov==NULL)){
    return NULL;
  }
  if(is_inode_dir(inode) || is_inode_file(inode)){
    record_inode_name(inode, iprov);
  }
	return iprov;
}*/

static inline struct provenance* inode_provenance(struct inode *inode){
  return inode->i_provenance;
}

static inline struct provenance* dentry_provenance(struct dentry *dentry)
{
  struct inode *inode = d_backing_inode(dentry);
  if(inode==NULL){
    return NULL;
  }
  return inode_provenance(inode);
}

static inline struct provenance* file_provenance(struct file *file)
{
  struct inode *inode = file_inode(file);
  if(inode==NULL){
    return NULL;
  }
  return inode_provenance(inode);
}

static inline struct provenance* branch_mmap(prov_msg_t* iprov, prov_msg_t* cprov){ //used for private MMAP
  struct provenance* prov;
  prov_msg_t relation;

  if( unlikely(iprov==NULL || cprov==NULL) ){ // should not occur
    return NULL;
  }

  if(!provenance_is_tracked(iprov) && !provenance_is_tracked(cprov) && !prov_all ){
    return NULL;
  }

  if( filter_node(iprov) || filter_node(cprov)){
    return NULL;
  }

  if(filter_relation(RL_CREATE, FLOW_ALLOWED)) {
    return NULL;
  }

  prov = alloc_provenance(ENT_INODE_MMAP, ASSIGN_NODE_ID, GFP_KERNEL);

  prov_msg(prov)->inode_info.uid = iprov->inode_info.uid;
  prov_msg(prov)->inode_info.gid = iprov->inode_info.gid;
  memcpy(prov_msg(prov)->inode_info.sb_uuid, iprov->inode_info.sb_uuid, 16*sizeof(uint8_t));
  prov_msg(prov)->inode_info.mode = iprov->inode_info.mode;
  __record_node(iprov);
  memset(&relation, 0, sizeof(prov_msg_t));
  __propagate(RL_MMAP, iprov, prov_msg(prov), &relation, FLOW_ALLOWED);
  __record_node(prov_msg(prov));
  __record_relation(RL_MMAP, &(iprov->msg_info.identifier), &(prov_msg(prov)->msg_info.identifier), &relation, FLOW_ALLOWED, NULL);
  return prov;
}
#endif
