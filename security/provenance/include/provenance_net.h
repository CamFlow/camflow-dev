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

static inline prov_msg_t* socket_inode_provenance(struct socket *sock){
  struct inode *inode = SOCK_INODE(sock);
  if(inode==NULL){
    return NULL;
  }
  return inode_get_provenance(inode);
}

static inline prov_msg_t* sk_inode_provenance(struct sock *sk){
  struct socket *sock = sk->sk_socket;
  if(sock==NULL){
    return NULL;
  }
  return socket_inode_provenance(sock);
}

static inline prov_msg_t* sk_provenance(struct sock *sk){
  prov_msg_t* prov = sk->sk_provenance;
  lock_node(prov);
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

  id->type = MSG_PACKET;
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

static inline prov_msg_t* skb_inode_prov(struct sk_buff *skb){
  struct sock *sk;
  if(skb==NULL){
    return NULL;
  }

  sk = skb->sk;
  if(sk==NULL){
    return NULL;
  }

  return sk_inode_provenance(sk);
}

#endif
