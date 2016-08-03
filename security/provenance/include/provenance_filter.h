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
#define porvenance_is_recorded(node) (node_kern(node).recorded == NODE_RECORDED)

extern bool prov_enabled;
extern bool prov_all;

#define HIT_FILTER(filter, data) ( (filter&data) != 0 )

extern uint32_t prov_node_filter;

/* return either or not the node should be filtered out */
static inline bool filter_node(prov_msg_t* node){
  if(!prov_enabled){
    return true;
  }

  if(provenance_is_opaque(node)){
    return true;
  }

  // we hit an element of the black list ignore
  if( HIT_FILTER(prov_node_filter, node_identifier(node).type) ){
    return true;
  }

  return false;
}

extern uint32_t prov_edge_filter;

/* return either or not the edge should be filtered out */
static inline bool filter_edge(uint32_t type, prov_msg_t* from, prov_msg_t* to, uint8_t allowed){
  if(allowed==FLOW_DISALLOWED && HIT_FILTER(prov_edge_filter, ED_DISALLOWED)){
    return true;
  }

  if(allowed==FLOW_ALLOWED && HIT_FILTER(prov_edge_filter, ED_ALLOWED)){
    return true;
  }

  // we hit an element of the black list ignore
  if( HIT_FILTER(prov_edge_filter, type) ){
    return true;
  }

  // one of the node should not appear in the record, ignore the edge
  if(filter_node(to) || filter_node(from)){
    return true;
  }

  // ignore if none of the node are tracked and we are not capturing everything
  if(!(provenance_is_tracked(from)|porvenance_is_recorded(from)) && !(provenance_is_tracked(to)|porvenance_is_recorded(to)) && !prov_all){
    return true;
  }

  return false;
}

#endif
