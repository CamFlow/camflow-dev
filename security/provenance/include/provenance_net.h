/*
 *
 * Author: Thomas Pasquier <tfjmp@seas.harvard.edu>
 *
 * Copyright (C) 2016 Harvard University
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
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
#include "provenance_policy.h"

static inline struct provenance *socket_inode_provenance(struct socket *sock)
{
	struct provenance *iprov = SOCK_INODE(sock)->i_provenance;

	return iprov;
}

static inline struct provenance *sk_inode_provenance(struct sock *sk)
{
	struct socket *sock = sk->sk_socket;

	if (!sock)
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

static inline void __extract_tcp_info_v6(struct sk_buff *skb,
							int offset,
							struct packet_v6_identifier *id)
{
	struct tcphdr _tcph;
	struct tcphdr *th;

	th = skb_header_pointer(skb, offset, sizeof(_tcph), &_tcph);
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
	struct udphdr   *uh;
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

static inline void __extract_udp_info_v6(struct sk_buff *skb,
							int offset,
							struct packet_v6_identifier *id)
{
	struct udphdr _udph;
	struct udphdr *uh;

	uh = skb_header_pointer(skb, offset, sizeof(_udph), &_udph);
	if (!uh)
		return;

	id->snd_port = uh->source;
	id->rcv_port = uh->dest;
}

static inline unsigned int provenance_parse_skb_ipv4(struct sk_buff *skb, union prov_elt *prov)
{
	struct packet_identifier *id;
	int offset;
	struct iphdr _iph;
	struct iphdr *ih;

	offset = skb_network_offset(skb);
	ih = skb_header_pointer(skb, offset, sizeof(_iph), &_iph); // we obtain the ip header
	if (!ih)
		return -EINVAL;

	if (ihlen(ih) < sizeof(_iph))
		return -EINVAL;

	memset(prov, 0, sizeof(union prov_elt));
	id = &packet_identifier(prov); // we are going fo fill this

	id->type = ENT_PACKET;
	// collect IP element of prov identifier
	id->family = AF_INET;
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

static inline unsigned int provenance_parse_skb_ipv6(struct sk_buff *skb, union prov_elt *prov)
{
	struct packet_v6_identifier *id;
	int offset;
	uint8_t header;
	uint16_t frag_off;
	struct ipv6hdr _ipv6h;
	struct ipv6hdr *iv6h;

	offset = skb_network_offset(skb);
	iv6h = skb_header_pointer(skb, offset, sizeof(_ipv6h), &_ipv6h);
	if (!iv6h)
		return -EINVAL;

	memset(prov, 0, sizeof(union prov_elt));
	id = &packet_v6_identifier(prov); // we are going fo fill this

	id->type = ENT_PACKET;
	// collect IP element of prov identifier
	id->family = AF_INET6;
	memcpy((void *) id->snd_ip, (void *) iv6h->saddr.s6_addr, sizeof(uint8_t) * 16);
	memcpy((void *) id->rcv_ip, (void *) iv6h->daddr.s6_addr, sizeof(uint8_t) * 16);
	memcpy((void *) id->flow_label, (void *) iv6h->flow_lbl, sizeof(uint8_t) * 3);
	id->next_header = iv6h->nexthdr;//TODO: this can show either extension headers or protocol
	header = iv6h->nexthdr;
	prov->pck_info.length = iv6h->payload_len; // only record payload length; header length of 40 bytes not counted; payload includes extension headers as well

	offset += sizeof(_ipv6h);
	offset = ipv6_skip_exthdr(skb, offset, &header, &frag_off);
	if (offset < 0)
		return 0;
	id->protocol = header;

	// now we collect transport information. Old values in IPv4 protocol should still exist for IPv6 nexthdr
	switch (header) {
	case IPPROTO_TCP:
		__extract_tcp_info_v6(skb, offset, id);
		break;
	case IPPROTO_UDP:
		__extract_udp_info_v6(skb, offset, id);
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

struct ipv6_filters {
	struct list_head list;
	struct prov_ipv6_filter filter;
};

extern struct list_head ingress_ipv4filters;
extern struct list_head egress_ipv4filters;
extern struct list_head ingress_ipv6filters;
extern struct list_head egress_ipv6filters;

#define prov_ipv4_ingressOP(ip, port) prov_ipv4_whichOP(&ingress_ipv4filters, ip, port)
#define prov_ipv4_egressOP(ip, port) prov_ipv4_whichOP(&egress_ipv4filters, ip, port)
#define prov_ipv6_ingressOP(ip, port) prov_ipv6_whichOP(&ingress_ipv6filters, ip, port)
#define prov_ipv6_egressOP(ip, port) prov_ipv6_whichOP(&egress_ipv6filters, ip, port)

static inline uint8_t prov_ipv4_whichOP(struct list_head *filters, uint32_t ip, uint16_t port)
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

static inline uint8_t __ipv6_match_filter(struct prov_ipv6_filter filters, uint8_t *ip)
{
	uint32_t i;
	uint8_t *filter_ip = filters.ip;
	uint8_t *filter_mask = filters.mask;
	for (i = 0; i < 16; i++) {
		if ((filter_mask[i] & ip[i]) != (filter_mask[i] & filter_ip[i]))
			goto out;
	}
	return 1;
out:
	return 0;
}

static inline uint8_t prov_ipv6_whichOP(struct list_head *filters, uint8_t *ip, uint16_t port)
{
	struct list_head *listentry, *listtmp;
	struct ipv6_filters *tmp;

	list_for_each_safe(listentry, listtmp, filters) {
		tmp = list_entry(listentry, struct ipv6_filters, list);
		if (__ipv6_match_filter(tmp->filter, ip))
			if (tmp->filter.port == 0 || tmp->filter.port == port)
				return tmp->filter.op;
	}
	return 0;
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
static inline int record_pck_to_inode(union prov_elt *pck, struct provenance *inode)
{
	int rc = 0;

	if (unlikely(!pck || !inode)) // should not occur
		return 0;
	if (!provenance_is_tracked(prov_elt(inode)) && !prov_policy.prov_all)
		return 0;
	if (!should_record_relation(RL_RCV_PACKET, pck, prov_elt(inode)))
		return 0;
	rc = __update_version(RL_RCV_PACKET, inode);
	if (rc < 0)
		return rc;
	write_node(prov_elt(inode));
	prov_write(pck);
	rc = write_relation(RL_RCV_PACKET, pck, prov_elt(inode), NULL);
	return rc;
}

// outgoing packet
static inline int record_inode_to_pck(struct provenance *inode, union prov_elt *pck)
{
	int rc = 0;

	if (unlikely(!pck || !inode)) // should not occur
		return 0;
	if (!provenance_is_tracked(prov_elt(inode)) && !prov_policy.prov_all)
		return 0;
	if (!should_record_relation(RL_SND_PACKET, prov_elt(inode), pck))
		return 0;
	write_node(prov_elt(inode));
	prov_write(pck);
	rc = write_relation(RL_SND_PACKET, prov_elt(inode), pck, NULL);
	inode->has_outgoing = true;
	return rc;
}

static inline int provenance_record_address(struct sockaddr *address, int addrlen, struct provenance *prov)
{
	union long_prov_elt *addr_info;
	int rc = 0;

	if (provenance_is_name_recorded(prov_elt(prov)) || !provenance_is_recorded(prov_elt(prov)))
		return 0;
	addr_info = alloc_long_provenance(ENT_ADDR);
	if (!addr_info) {
		rc = -ENOMEM;
		goto out;
	}
	addr_info->address_info.length = addrlen;
	memcpy(&(addr_info->address_info.addr), address, addrlen);
	write_long_node(addr_info);
	rc = write_relation(RL_NAMED, addr_info, prov_elt(prov), NULL);
	set_name_recorded(prov_elt(prov));
out:
	free_long_provenance(addr_info);
	return rc;
}

static inline int record_packet_content(union prov_elt *pck, const struct sk_buff *skb)
{
	union long_prov_elt *cnt = alloc_long_provenance(ENT_PCKCNT);
	int rc;

	cnt->pckcnt_info.length = skb_end_offset(skb);
	if (cnt->pckcnt_info.length > PATH_MAX) {
		cnt->pckcnt_info.truncated = PROV_TRUNCATED;
		memcpy(cnt->pckcnt_info.content, skb->head, PATH_MAX);
	} else
		memcpy(cnt->pckcnt_info.content, skb->head, cnt->pckcnt_info.length);
	write_long_node(cnt);
	rc = write_relation(RL_READ, cnt, pck, NULL);
	free_long_provenance(cnt);
	return rc;
}
#endif
