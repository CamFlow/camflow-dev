/*
 *
 * Author: Thomas Pasquier <thomas.pasquier@cl.cam.ac.uk>
 *
 * Copyright (C) 2015-2018 University of Cambridge, Harvard University
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 */
#ifndef _PROVENANCE_NET_H
#define _PROVENANCE_NET_H

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
#include "provenance_inode.h"

/*!
 * @brief Returns the provenance entry pointer of the inode associated with sock.
 *
 * @param sock The socket structure whose provenance to be obtained.
 * @return The provenance entry pointer of the socket or NULL if it does not exist.
 *
 */
static inline struct provenance *socket_inode_provenance(struct socket *sock)
{
	struct inode *inode = SOCK_INODE(sock);
	struct provenance *iprov = NULL;

	if (inode)
		iprov = inode_provenance(inode, false);
	return iprov;
}

/*!
 * @brief Returns the provenance entry pointer of the inode associated with sk.
 *
 * This function calls the function socket_inode_provenance.
 * This is becasue only socket has an inode associated with it.
 * We obtain the socket structure from sk structure: @sk->sk_socket.
 * We obtain socket from sock and return the provenance entry pointer.
 * @param sk The sock structure whose provenance to be obtained.
 * @return The provenance entry pointer of the corresponding socket.
 *
 */
static inline struct provenance *sk_inode_provenance(struct sock *sk)
{
	struct socket *sock = sk->sk_socket;

	if (!sock)
		return NULL;
	return socket_inode_provenance(sock);
}

/*!
 * @brief Return the provenance entry pointer of sk.
 *
 * @param sk The sock structure.
 * @return The provenance entry pointer.
 *
 */
static inline struct provenance *sk_provenance(struct sock *sk)
{
	struct provenance *prov = sk->sk_provenance;

	return prov;
}

/*!
 * @brief Return the provenance entry pointer of sock.
 *
 * The provenance information is stored in the @sock->sk struct.
 * Therefore, we simply call the function sk_provenance.
 * @param sock The socket structure.
 * @return The provenance entry pointer.
 *
 */
static inline struct provenance *socket_provenance(struct socket *sock)
{
	struct sock *sk = sock->sk;

	if (!sk)
		return NULL;
	return sk_provenance(sk);
}

#define ihlen(ih) (ih->ihl * 4)

/*!
 * @brief Extract TCP header information and store it in packet_identifier struct of provenance entry.
 *
 * @param skb The socket buffer.
 * @param ih The IP header.
 * @param offset
 * @param id The packet identifier structure of provenance entry.
 *
 */
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
	tcpoff = offset + ihlen(ih);    //Point to tcp packet.
	th = skb_header_pointer(skb, tcpoff, sizeof(_tcph), &_tcph);
	if (!th)
		return;
	id->snd_port = th->source;
	id->rcv_port = th->dest;
	id->seq = th->seq;
}

/*!
 * @brief Extract UPD header information and store it in packet_identifier struct of provenance entry.
 *
 * @param skb The socket buffer.
 * @param ih The IP header.
 * @param offset
 * @param id The packet identifier structure of provenance entry.
 *
 */
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

/*!
 * @brief Parse network packet information @skb into a packet provenance entry @prov.
 *
 * We parse a series of IP information from @skb and create a provenance entry node ENT_PACKET.
 * Depending on the type of the packet (i.e., TCP or UDP), we call either __extract_tcp_info or __extract_udp_info subfunction to parse.
 * @param skb Socket buffer where packet information lies.
 * @param prov The provenance entry pointer.
 * @return 0 if no error occurred; -EINVAL if error during obtaining packet meta-data; Other error codes unknown.
 *
 */
static inline unsigned int provenance_parse_skb_ipv4(struct sk_buff *skb, union prov_elt *prov)
{
	struct packet_identifier *id;
	int offset;
	struct iphdr _iph;
	struct iphdr *ih;

	offset = skb_network_offset(skb);
	ih = skb_header_pointer(skb, offset, sizeof(_iph), &_iph);      // We obtain the IP header.
	if (!ih)
		return -EINVAL;

	if (ihlen(ih) < sizeof(_iph))
		return -EINVAL;

	memset(prov, 0, sizeof(union prov_elt));
	id = &packet_identifier(prov);  // We are going fo fill the information.

	id->type = ENT_PACKET;
	// Collect IP element of prov identifier.
	id->id = ih->id;
	id->snd_ip = ih->saddr;
	id->rcv_ip = ih->daddr;
	id->protocol = ih->protocol;
	prov->pck_info.length = ih->tot_len;

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

/*!
 * @brief Returns op value of the filter of a specific IP and/or port.
 *
 * This function goes through a filter list,
 * and attempts to match the given @ip and @port.
 * If matched, the op value of the matched element will be returned.
 * @param filters The list to go through.
 * @param ip The IP to match.
 * @param port The port to match.
 * @return 0 if not found or the op value of the matched element in the list.
 *
 */
static inline uint8_t prov_ipv4_whichOP(struct list_head *filters, uint32_t ip, uint32_t port)
{
	struct list_head *listentry, *listtmp;
	struct ipv4_filters *tmp;

	list_for_each_safe(listentry, listtmp, filters) {
		tmp = list_entry(listentry, struct ipv4_filters, list);
		if ((tmp->filter.mask & ip) == (tmp->filter.mask & tmp->filter.ip))     // Match IP
			if (tmp->filter.port == 0 || tmp->filter.port == port)          // Any port or a specific match
				return tmp->filter.op;
	}
	return 0;
}

/*!
 * @brief Delete an element in the filter list that matches a specific filter.
 *
 * This function goes through a filter list,
 * and attempts to match the given filter.
 * If matched, the matched element will be removed from the list.
 * @param filters The list to go through.
 * @param f The filter to match its mask, ip and port.
 * @return Always return 0.
 *
 */
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
			return 0;       // Should only get one.
		}
	}
	return 0;
}

/*!
 * @brief Add or update an element in the filter list that matches a specific filter.
 *
 * This function goes through a filter list,
 * and attempts to match the given filter.
 * If matched, the matched element's op value will be updated based on the given filter @f or the element will be added if no matches.
 * @param filters The list to go through.
 * @param f The filter to match its mask, ip and port.
 * @return Always return 0.
 *
 */
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
	list_add_tail(&(f->list), filters); // If not already in the list, we add it.
	return 0;
}

/*!
 * @brief Record the address provenance node that binds to the socket node.
 *
 * This function creates a long provenance entry node ENT_ADDR that binds to the socket provenance entry @prov.
 * Record provenance relation RL_NAMED by calling "record_relation" function.
 * Relation will not be recorded, if:
 * 1. The socket inode is not recorded or the name (addr) of the socket has been recorded already, or
 * 2. Failure occurs.
 * The information in the ENT_ADDR node is filled in from @address and @addrlen.
 * This provenance node is short-lived and thus we free the memory once we have recorded the relation.
 * @param address The address of the socket.
 * @param addrlen The length of the addres.
 * @param prov The provenance entry pointer of the socket.
 * @return 0 if no error occurred; -ENOMEM if no memory can be allocated for the new long provenance node ENT_ADDR; Other error codes inherited from record_relation function or unknown.
 *
 */
static __always_inline int provenance_record_address(struct sockaddr *address, int addrlen, struct provenance *prov)
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

	rc = record_relation(RL_NAMED, addr_info, prov_entry(prov), NULL, 0);
	set_name_recorded(prov_elt(prov));
out:
	free_long_provenance(addr_info);
	return rc;
}

static __always_inline void provenance_packet_content(struct sk_buff *skb,
						      struct provenance *pckprov)
{
	union long_prov_elt *cnt;

	cnt = alloc_long_provenance(ENT_PCKCNT);
	if (!cnt)
		return;

	cnt->pckcnt_info.length = skb_end_offset(skb);
	if (cnt->pckcnt_info.length >= PATH_MAX) {
		cnt->pckcnt_info.truncated = PROV_TRUNCATED;
		memcpy(cnt->pckcnt_info.content, skb->head, PATH_MAX);
	} else
		memcpy(cnt->pckcnt_info.content, skb->head, cnt->pckcnt_info.length);
	record_relation(RL_PCK_CNT, cnt, prov_entry(pckprov), NULL, 0);
	free_long_provenance(cnt);
}
#endif
