/*
*
* Author: Thomas Pasquier <tfjmp@seas.harvard.edu>
*
* Copyright (C) 2016 Harvard University
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License version 2, as
* published by the Free Software Foundation.
*
*/
#ifndef _LINUX_PROVENANCE_FILTER_H
#define _LINUX_PROVENANCE_FILTER_H

#include <uapi/linux/provenance.h>

#define provenance_is_opaque(node)        ( node_kern(node).opaque == NODE_OPAQUE )
#define provenance_is_tracked(node)       ( node_kern(node).tracked == NODE_TRACKED )
#define provenance_propagate(node)          ( node_kern(node).propagate == NODE_PROPAGATE )
#define provenance_is_name_recorded(node) ( node_kern(node).name_recorded == NAME_RECORDED )
#define porvenance_is_recorded(node)      ( node_kern(node).recorded == NODE_RECORDED )

extern bool prov_enabled;
extern bool prov_all;

#define HIT_FILTER(filter, data) ( (filter&data) != 0 )

extern uint32_t prov_node_filter;
extern uint32_t prov_propagate_node_filter;

#define filter_node(node) __filter_node(prov_node_filter, node)
#define filter_propagate_node(node) __filter_node(prov_propagate_node_filter, node)

/* return either or not the node should be filtered out */
static inline bool __filter_node(uint32_t filter, prov_msg_t* node){
  if(!prov_enabled){
    return true;
  }

  if(provenance_is_opaque(node)){
    return true;
  }

  // we hit an element of the black list ignore
  if( HIT_FILTER(filter, node_identifier(node).type) ){
    return true;
  }

  return false;
}

extern uint32_t prov_relation_filter;
extern uint32_t prov_propagate_relation_filter;

/* return either or not the relation should be filtered out */
static inline bool filter_relation(uint32_t type, prov_msg_t* from, prov_msg_t* to, uint8_t allowed){
  // ignore if none of the node are tracked and we are not capturing everything
  if(!provenance_is_tracked(from) && !provenance_is_tracked(to) && !prov_all){
    return true;
  }

  if(allowed==FLOW_DISALLOWED && HIT_FILTER(prov_relation_filter, RL_DISALLOWED)){
    return true;
  }

  if(allowed==FLOW_ALLOWED && HIT_FILTER(prov_relation_filter, RL_ALLOWED)){
    return true;
  }

  // we hit an element of the black list ignore
  if( HIT_FILTER(prov_relation_filter, type) ){
    return true;
  }

  // one of the node should not appear in the record, ignore the relation
  if(filter_node(to) || filter_node(from)){
    return true;
  }

  return false;
}

/* return either or not tracking should propagate */
static inline bool filter_propagate_relation(uint32_t type, prov_msg_t* from, prov_msg_t* to, uint8_t allowed){
  // the origin does not propagate tracking
  if( !provenance_propagate(from) ){
    return true;
  }

  // the origin is not tracked
  if( !provenance_is_tracked(from) ){
    return true;
  }

  if(allowed==FLOW_DISALLOWED && HIT_FILTER(prov_propagate_relation_filter, RL_DISALLOWED)){
    return true;
  }

  if(allowed==FLOW_ALLOWED && HIT_FILTER(prov_propagate_relation_filter, RL_ALLOWED)){
    return true;
  }

  // the relation does not allow tracking propagation
  if( HIT_FILTER(prov_propagate_relation_filter, type) ){
    return true;
  }

  // the tracking should not propagate to the destination
  if( filter_propagate_node(to) ){
    return true;
  }

  return false;
}

static inline bool should_update_node(uint32_t relation_type, prov_msg_t* to){
  uint32_t filter=RL_VERSION_PROCESS|RL_VERSION|RL_NAMED;
  if(HIT_FILTER(filter, relation_type)){ // not update if relation is of above type
    return false;
  }
  return true;
}

#endif
