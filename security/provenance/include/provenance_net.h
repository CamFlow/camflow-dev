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

static inline struct provenance *socket_inode_provenance(struct socket *sock)
{
	struct provenance *iprov = SOCK_INODE(sock)->i_provenance;

	return iprov;
}

static inline struct provenance *sk_inode_provenance(struct sock *sk)
{
	struct socket *sock = sk->sk_socket;

	if (sock == NULL)
		return NULL;
	return socket_inode_provenance(sock);
}

static inline struct provenance *sk_provenance(struct sock *sk)
{
	struct provenance *prov = sk->sk_provenance;

	return prov;
}

#define ihlen(ih) (ih->ihl * 4)

static inline void __extract_tcp_info(struct sk_buff *skb,
																			struct iphdr *ih,
																			int offset,
																			struct packet_identifier *id)
{
	struct tcphdr _tcph;
	struct tcphdr *th;
	int tcpoff;

	if (ntohs(ih->frag_off) & IP_OFFSET)
		return;
	tcpoff = offset + ihlen(ih); //point to tcp packet
	th = skb_header_pointer(skb, tcpoff, sizeof(_tcph), &_tcph);
	if (!th)
		return;
	id->snd_port = th->source;
	id->rcv_port = th->dest;
	id->seq = th->seq;
}

static inline void __extract_udp_info(struct sk_buff *skb,
																			struct iphdr *ih,
																			int offset,
																			struct packet_identifier *id)
{
	struct udphdr _udph;
	struct udphdr	*uh;
	int udpoff;

	if (ntohs(ih->frag_off) & IP_OFFSET)
		return;
	udpoff = offset + ihlen(ih); //point to udp packet
	uh = skb_header_pointer(skb, udpoff, sizeof(_udph), &_udph);
	if (!uh)
		return;
	id->snd_port = uh->source;
	id->rcv_port = uh->dest;
}

static inline unsigned int provenance_parse_skb_ipv4(struct sk_buff *skb, union prov_msg *prov)
{
	struct packet_identifier *id;
	int offset;
	struct iphdr _iph;
	struct iphdr *ih;

	offset = skb_network_offset(skb);
	ih = skb_header_pointer(skb, offset, sizeof(_iph), &_iph); // we obtain the ip header
	if (ih == NULL)
		return -EINVAL;

	if (ihlen(ih) < sizeof(_iph))
		return -EINVAL;

	memset(prov, 0, sizeof(union prov_msg));
	id = &packet_identifier(prov); // we are going fo fill this

	id->type = ENT_PACKET;
	// collect IP element of prov identifier
	id->id = ih->id;
	id->snd_ip = ih->saddr;
	id->rcv_ip = ih->daddr;
	id->protocol = ih->protocol;
	prov->pck_info.length = ih->tot_len;

	// now we collect
	switch (ih->protocol) {
	case IPPROTO_TCP:
		__extract_tcp_info(skb, ih, offset, id);
		break;
	case IPPROTO_UDP:
		__extract_udp_info(skb, ih, offset, id);
		break;
	default:
		break;
	}
	return 0;
}

struct ipv4_filters {
	struct list_head list;
	struct prov_ipv4_filter filter;
};

extern struct list_head ingress_ipv4filters;
extern struct list_head egress_ipv4filters;

#define prov_ipv4_ingressOP(ip, port) prov_ipv4_whichOP(&ingress_ipv4filters, ip, port)
#define prov_ipv4_egressOP(ip, port) prov_ipv4_whichOP(&egress_ipv4filters, ip, port)

static inline uint8_t prov_ipv4_whichOP(struct list_head *filters, uint32_t ip, uint32_t port)
{
	struct list_head *listentry, *listtmp;
	struct ipv4_filters *tmp;

	list_for_each_safe(listentry, listtmp, filters) {
		tmp = list_entry(listentry, struct ipv4_filters, list);
		if ((tmp->filter.mask & ip) == (tmp->filter.mask & tmp->filter.ip))     // ip match filter
			if (tmp->filter.port == 0 || tmp->filter.port == port)          // any port or match
				return tmp->filter.op;
	}
	return 0; // do nothing
}

static inline uint8_t prov_ipv4_delete(struct list_head *filters, struct ipv4_filters *f)
{
	struct list_head *listentry, *listtmp;
	struct ipv4_filters *tmp;

	list_for_each_safe(listentry, listtmp, filters) {
		tmp = list_entry(listentry, struct ipv4_filters, list);
		if (tmp->filter.mask == f->filter.mask &&
		    tmp->filter.ip == f->filter.ip &&
		    tmp->filter.port == f->filter.port) {
			list_del(listentry);
			kfree(tmp);
			return 0; // you should only get one
		}
	}
	return 0; // do nothing
}

static inline uint8_t prov_ipv4_add_or_update(struct list_head *filters, struct ipv4_filters *f)
{
	struct list_head *listentry, *listtmp;
	struct ipv4_filters *tmp;

	list_for_each_safe(listentry, listtmp, filters) {
		tmp = list_entry(listentry, struct ipv4_filters, list);
		if (tmp->filter.mask == f->filter.mask &&
		    tmp->filter.ip == f->filter.ip &&
		    tmp->filter.port == f->filter.port) {
			tmp->filter.op |= f->filter.op;
			return 0; // you should only get one
		}
	}
	list_add_tail(&(f->list), filters); // not already on the list, we add it
	return 0;
}

// incoming packet
static inline int record_pck_to_inode(union prov_msg *pck, struct provenance *inode)
{
	union prov_msg relation;
	int rc = 0;

	if (unlikely(pck == NULL || inode == NULL)) // should not occur
		return 0;
	if (!provenance_is_tracked(prov_msg(inode)) && !prov_all)
		return 0;
	if (!should_record_relation(RL_RCV_PACKET, pck, prov_msg(inode)))
		return 0;
	memset(&relation, 0, sizeof(union prov_msg));
	prov_write(pck);
	__record_node(prov_msg(inode));
	rc = __update_version(RL_RCV_PACKET, inode);
	if( rc < 0 )
		return rc;
	__record_node(prov_msg(inode));
	__prepare_relation(RL_RCV_PACKET, &(pck->msg_info.identifier), &(prov_msg(inode)->msg_info.identifier), &relation, NULL);
	rc = call_query_hooks(pck, prov_msg(inode), &relation);
	prov_write(&relation);
	return rc;
}

// outgoing packet
static inline int record_inode_to_pck(struct provenance *inode, union prov_msg *pck)
{
	union prov_msg relation;
	int rc = 0;

	if (unlikely(pck == NULL || inode == NULL)) // should not occur
		return 0;
	if (!provenance_is_tracked(prov_msg(inode)) && !prov_all)
		return 0;
	if (!should_record_relation(RL_SND_PACKET, prov_msg(inode), pck))
		return 0;
	memset(&relation, 0, sizeof(union prov_msg));
	__record_node(prov_msg(inode));
	prov_write(pck);
	__prepare_relation(RL_SND_PACKET, &(prov_msg(inode)->msg_info.identifier), &(pck->msg_info.identifier), &relation, NULL);
	rc = call_query_hooks(prov_msg(inode), pck, &relation);
	inode->has_outgoing = true;
	prov_write(&relation);
	return rc;
}
#endif
