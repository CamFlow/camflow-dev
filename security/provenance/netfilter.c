/*
 *
 * Author: Thomas Pasquier <tfjmp@seas.harvard.edu>
 *
 * Copyright (C) 2016 Havard University
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 */
#include <net/net_namespace.h>

#include "provenance.h"
#include "provenance_net.h"
#include "provenance_task.h"

static inline unsigned int __ipv4_out(struct sk_buff *skb)
{
	struct provenance *cprov = get_current_provenance();
	struct provenance *iprov = NULL;
	union prov_elt pckprov;
	unsigned long irqflags;

	if (!cprov)
		return NF_ACCEPT;

	if (provenance_is_tracked(prov_elt(cprov))) {
		iprov = sk_inode_provenance(skb->sk);
		if (!iprov)
			return NF_ACCEPT;
		provenance_parse_skb_ipv4(skb, &pckprov);
		spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_TASK);
		spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
		record_inode_to_pck(iprov, &pckprov);
		if (provenance_records_packet(prov_elt(iprov)))
			record_packet_content(&pckprov, skb);
		spin_unlock(prov_lock(iprov));
		spin_unlock_irqrestore(prov_lock(cprov), irqflags);
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
		.hook = provenance_ipv4_out,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_LOCAL_OUT,
		.priority = NF_IP_PRI_LAST,
	},
};

// will initialise the hooks
static int __net_init provenance_nf_register(struct net *net)
{
	return nf_register_net_hooks(net, provenance_nf_ops, ARRAY_SIZE(provenance_nf_ops));
}

static void __net_exit provenance_nf_unregister(struct net *net)
{
	nf_unregister_net_hooks(net, provenance_nf_ops, ARRAY_SIZE(provenance_nf_ops));
}

static struct pernet_operations provenance_net_ops = {
	.init = provenance_nf_register,
	.exit = provenance_nf_unregister,
};

static int __init provenance_nf_ip_init(void)
{
	pr_info("Provenance: registering netfilter hooks.\n");
	return register_pernet_subsys(&provenance_net_ops);
}

__initcall(provenance_nf_ip_init);
