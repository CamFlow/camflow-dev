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
#ifndef CONFIG_SECURITY_PROVENANCE_NET
#define CONFIG_SECURITY_PROVENANCE_NET

#include <net/sock.h>
#include <net/ip.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/skbuff.h>

#include "provenance.h"

static inline struct provenance* socket_inode_provenance(struct socket *sock){
  struct provenance* iprov = SOCK_INODE(sock)->i_provenance;
  if(iprov==NULL){
    return NULL;
  }
  return iprov;
}

static inline struct provenance* sk_inode_provenance(struct sock *sk){
  struct socket *sock = sk->sk_socket;
  if(sock==NULL){
    return NULL;
  }
  return socket_inode_provenance(sock);
}

static inline struct provenance* sk_provenance(struct sock *sk){
  struct provenance* prov = sk->sk_provenance;
  return prov;
}

static inline unsigned int provenance_parse_skb_ipv4(struct sk_buff *skb, prov_msg_t* prov){
  struct packet_identifier* id;
  int offset, ihlen;
	struct iphdr _iph, *ih;
  struct tcphdr _tcph, *th;
  struct udphdr _udph, *uh;

  offset = skb_network_offset(skb);
  ih = skb_header_pointer(skb, offset, sizeof(_iph), &_iph); // we obtain the ip header
  if(ih == NULL){
    return -EINVAL;
  }

  ihlen = ih->ihl*4; // header size
  if(ihlen < sizeof(_iph)){
    return -EINVAL;
  }

  memset(prov, 0, sizeof(prov_msg_t));
  id = &packet_identifier(prov); // we are going fo fill this

  id->type = ENT_PACKET;
  // collect IP element of prov identifier
  id->id = ih->id;
  id->snd_ip = ih->saddr;
  id->rcv_ip = ih->daddr;
  id->protocol = ih->protocol;
  prov->pck_info.length = ih->tot_len;

  // now we collect
  switch(ih->protocol){
    case IPPROTO_TCP:
      if (ntohs(ih->frag_off) & IP_OFFSET){
        break;
      }

      offset +=ihlen; //point to tcp packet
      th = skb_header_pointer(skb, offset, sizeof(_tcph), &_tcph);
      if(th==NULL){
        break;
      }

      id->snd_port = th->source;
      id->rcv_port = th->dest;
      id->seq = th->seq;
      break;
    case IPPROTO_UDP:
      if (ntohs(ih->frag_off) & IP_OFFSET){
        break;
      }

      offset +=ihlen; //point to tcp packet
      uh = skb_header_pointer(skb, offset, sizeof(_udph), &_udph);
      if(uh==NULL){
        break;
      }

      id->snd_port = uh->source;
      id->rcv_port = uh->dest;
      break;
    default:
      break;
  }
  return 0;
}

struct ipv4_filters{
  struct list_head list;
  struct prov_ipv4_filter filter;
};

extern struct ipv4_filters ingress_ipv4filters;
extern struct ipv4_filters egress_ipv4filters;

#define prov_ipv4_ingressOP(ip, port) prov_ipv4_whichOP(&ingress_ipv4filters, ip, port)
#define prov_ipv4_egressOP(ip, port) prov_ipv4_whichOP(&egress_ipv4filters, ip, port)

static inline uint8_t prov_ipv4_whichOP(struct ipv4_filters* filters, uint32_t ip, uint32_t port){
  struct ipv4_filters* tmp;

  list_for_each_entry(tmp, &(filters->list), list){
    if( (tmp->filter.mask&ip) == (tmp->filter.mask&tmp->filter.ip) ){ // ip match filter
      if(tmp->filter.port==0 || tmp->filter.port==port){ // any port or match
        return tmp->filter.op;
      }
    }
  }
  return 0; // do nothing
}

static inline uint8_t prov_ipv4_delete(struct ipv4_filters* filters, struct ipv4_filters	*f){
  struct list_head *pos, *q;
  struct ipv4_filters* tmp;

  list_for_each_safe(pos, q, &(filters->list)){
    tmp= list_entry(pos, struct ipv4_filters, list);
    if(tmp->filter.mask==f->filter.mask &&
        tmp->filter.ip == f->filter.ip &&
        tmp->filter.port == f->filter.port){
      list_del(pos);
      kfree(tmp);
      return 0; // you should only get one
    }
  }
  return 0; // do nothing
}

static inline uint8_t prov_ipv4_add_or_update(struct ipv4_filters* filters, struct ipv4_filters	*f){
  struct list_head *pos, *q;
  struct ipv4_filters* tmp;

  list_for_each_safe(pos, q, &(filters->list)){
    tmp= list_entry(pos, struct ipv4_filters, list);
    if(tmp->filter.mask==f->filter.mask &&
        tmp->filter.ip == f->filter.ip &&
        tmp->filter.port == f->filter.port){
      tmp->filter.op = f->filter.op;
      return 0; // you should only get one
    }
  }
  list_add_tail(&(f->list), &filters->list); // not already on the list, we add it
  return 0;
}

// incoming packet
static inline void record_pck_to_inode(prov_msg_t* pck, prov_msg_t* inode){
  prov_msg_t relation;

  if( unlikely(pck==NULL || inode==NULL) ){ // should not occur
    return;
  }

  if(!provenance_is_tracked(inode) && !prov_all){
    goto out;
  }

  if( !should_record_relation(RL_RCV_PACKET, pck, inode, FLOW_ALLOWED) ){
    return;
  }
  memset(&relation, 0, sizeof(prov_msg_t));
  prov_write(pck);
  __record_node(inode);
  __update_version(RL_RCV_PACKET, inode);
  __record_node(inode);
  __record_relation(RL_RCV_PACKET, &(pck->msg_info.identifier), &(inode->msg_info.identifier), &relation, FLOW_ALLOWED, NULL);
out:
  return;
}

// outgoing packet
static inline void record_inode_to_pck(prov_msg_t* inode, prov_msg_t* pck){
  prov_msg_t relation;

  if( unlikely(pck==NULL || inode==NULL) ){ // should not occur
    return;
  }

  if(!provenance_is_tracked(inode) && !prov_all){
    goto out;
  }

  if( !should_record_relation(RL_SND_PACKET, inode, pck, FLOW_ALLOWED) ){
    return;
  }
  memset(&relation, 0, sizeof(prov_msg_t));
  __record_node(inode);
  prov_write(pck);
  __record_relation(RL_SND_PACKET, &(inode->msg_info.identifier), &(pck->msg_info.identifier), &relation, FLOW_ALLOWED, NULL);
out:
  return;
}

#endif
