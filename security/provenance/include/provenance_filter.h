/*
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
#ifndef _LINUX_PROVENANCE_FILTER_H
#define _LINUX_PROVENANCE_FILTER_H

#include <uapi/linux/provenance.h>

#define provenance_is_opaque(node) (node_kern(node).opaque == NODE_OPAQUE)
#define provenance_is_tracked(node) (prov_all || node_kern(node).tracked == NODE_TRACKED)
#define provenance_is_name_recorded(node) (node_kern(node).name_recorded == NAME_RECORDED)

extern bool prov_enabled;
extern bool prov_all;
extern bool prov_track_dir;

/* return either or not the node should be filtered out */
static inline bool filter_node(prov_msg_t* node){
  if(!prov_enabled){
    return true;
  }

  if(provenance_is_opaque(node)){
    return true;
  }

  return false;
}

/* return either or not the edge should be filtered out */
static inline bool filter_edge(uint8_t type, prov_msg_t* from, prov_msg_t* to, uint8_t allowed){
  // if one of the node should not appear in the record, ignore the edge
  if(filter_node(to) || filter_node(from)){
    return true;
  }

  // ignore if none of the node are tracked and we are not capturing everything
  if(!provenance_is_tracked(from) && !provenance_is_tracked(to) && !prov_all){
    return true;
  }

  return false;
}

#endif
