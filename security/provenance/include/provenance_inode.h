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

#include "provenance_long.h" // for record_inode_name

static inline void prov_copy_inode_mode(prov_msg_t* iprov, struct inode *inode){
  uint32_t type = MSG_INODE_UNKNOWN;
  iprov->inode_info.mode=inode->i_mode;

  if(S_ISBLK(inode->i_mode)){
    type=MSG_INODE_BLOCK;
  }else if(S_ISCHR(inode->i_mode)){
    type=MSG_INODE_CHAR;
  }else if(S_ISDIR(inode->i_mode)){
    type=MSG_INODE_DIRECTORY;
  }else if(S_ISFIFO(inode->i_mode)){
    type=MSG_INODE_FIFO;
  }else if(S_ISLNK(inode->i_mode)){
    type=MSG_INODE_LINK;
  }else if(S_ISREG(inode->i_mode)){
    type=MSG_INODE_FILE;
  }else if(S_ISSOCK(inode->i_mode)){
    type=MSG_INODE_SOCKET;
  }
  node_identifier(iprov).type=type;
}

static inline prov_msg_t* inode_provenance(struct inode* inode){
	prov_msg_t* iprov = inode_get_provenance(inode);
	prov_copy_inode_mode(iprov, inode);
	if( provenance_is_recorded(iprov) ){ // the node has been recorded we need its name
		record_inode_name(inode, iprov);
	}
	return iprov;
}
#endif
