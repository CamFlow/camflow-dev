/*
*
* Author: Thomas Pasquier <tfjmp@seas.harvard.edu>
*
* Copyright (C) 2016 Havard University
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License version 2, as
* published by the Free Software Foundation; either version 2 of the License, or
*	(at your option) any later version.
*
*/

#if defined(CONFIG_NETFILTER)

#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <net/ip.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/skbuff.h>
#include <linux/camflow.h>

#include "provenance.h"
#include "provenance_net.h"

static inline unsigned int provenance_parse_skb_ipv4(struct sk_buff *skb, prov_msg_t* prov){
  struct packet_identifier* id = &packet_identifier(prov); // we are going fo fill this
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

static inline unsigned int __ipv4_in(struct sk_buff *skb)
{
  prov_msg_t* cprov = current_provenance();

  if(provenance_is_tracked(cprov)){
    printk(KERN_INFO "Provenance in packet.\n");
  }
  //prov_msg_t pckprov;
  //provenance_parse_skb_ipv4(skb, &pckprov);
  //prov_write(&pckprov); // we record the packet
  //printk(KERN_INFO "Provenance in packet.\n");
  return NF_ACCEPT;
}

static unsigned int provenance_ipv4_in(void *priv,
					struct sk_buff *skb,
					const struct nf_hook_state *state)
{
  return __ipv4_in(skb);
}

static inline unsigned int __ipv4_out(struct sk_buff *skb)
{
  prov_msg_t* cprov = current_provenance();
  prov_msg_t* iprov;
  prov_msg_t pckprov;

  if(provenance_is_tracked(cprov)){
    printk(KERN_INFO "Provenance out packet.\n");
    iprov = sk_inode_provenance(skb->sk);
    provenance_parse_skb_ipv4(skb, &pckprov);
    record_inode_to_pck(iprov, &pckprov);
  }
  return NF_ACCEPT;
}

static unsigned int provenance_ipv4_out(void *priv,
					struct sk_buff *skb,
					const struct nf_hook_state *state)
{
  return __ipv4_out(skb);
}

static struct nf_hook_ops provenance_nf_ops[] = {
  {
    .hook = provenance_ipv4_in,
    .pf = NFPROTO_IPV4,
    .hooknum = NF_INET_LOCAL_IN,
    .priority = NF_IP_PRI_FIRST,
  },
  {
    .hook = provenance_ipv4_out,
    .pf = NFPROTO_IPV4,
    .hooknum = NF_INET_LOCAL_OUT,
    .priority = NF_IP_PRI_LAST,
  },
};

// will initialise the hooks
static int __init provenance_nf_init(void)
{
  int err;

  err = nf_register_hooks(provenance_nf_ops, ARRAY_SIZE(provenance_nf_ops));
  if(err){
    panic("Provenance: nf_register_hooks: error %d\n", err);
  }

    printk(KERN_INFO "Provenance netfilter ready.\n");

  return 0;
}
__initcall(provenance_nf_init);
#endif
