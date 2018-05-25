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
#include <net/net_namespace.h>

#include "provenance.h"
#include "provenance_net.h"
#include "provenance_task.h"
/*!
 * @brief Record provenance of an outgoing packets, which is done through NetFilter (instead of LSM) hooks.
 *
 * We record the provenance relation RL_SND_PACKET by calling "derives" routine.
 * Information flows from the sending socket to the outgoing packet.
 * We will not record the provenance if:
 * 1. The calling process cred's provenance (obtained from current_provenance) is not recorded or does not exist, or
 * 2. The socket inode's provenance does not exist.
 * We will create a new packet provenance node for this relation.
 * @param skb The socket buffer that contain packet information.
 * @return always return NF_ACCEPT.
 *
 * @todo The return value seems to be off. 
 */
static inline unsigned int __ipv4_out(struct sk_buff *skb)
{
	struct provenance *cprov = current_provenance();
	struct provenance *iprov = NULL;
	struct provenance pckprov;
	unsigned long irqflags;

	if (!cprov)
		return NF_ACCEPT;
	if (provenance_is_tracked(prov_elt(cprov))) {
		iprov = sk_inode_provenance(skb->sk);
		if (!iprov)
			return NF_ACCEPT;

		memset(&pckprov, 0, sizeof(struct provenance));
		provenance_parse_skb_ipv4(skb, prov_elt((&pckprov)));

		spin_lock_irqsave_nested(prov_lock(cprov), irqflags, PROVENANCE_LOCK_TASK);
		spin_lock_nested(prov_lock(iprov), PROVENANCE_LOCK_INODE);
		derives(RL_SND_PACKET, iprov, &pckprov, NULL, 0);
		spin_unlock(prov_lock(iprov));
		spin_unlock_irqrestore(prov_lock(cprov), irqflags);
	}
	return NF_ACCEPT;
}

/*!
 * @brief This routine records the provenance of outgoing packets using NetFilter.
 * 
 * It simply calls __ipv4_out routine to perform this task.
 * Parameters are netfilter specific.
 *
 */
static unsigned int provenance_ipv4_out(void *priv,
					struct sk_buff *skb,
					const struct nf_hook_state *state)
{
	return __ipv4_out(skb);
}

/* Netfilter hook operations */
static struct nf_hook_ops provenance_nf_ops[] = {
	{
		.hook = provenance_ipv4_out,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_LOCAL_OUT,
		.priority = NF_IP_PRI_LAST,
	},
};

/* Register the hooks */
static int __net_init provenance_nf_register(struct net *net)
{
	return nf_register_net_hooks(net, provenance_nf_ops, ARRAY_SIZE(provenance_nf_ops));
}
/* Unregister the hooks */
static void __net_exit provenance_nf_unregister(struct net *net)
{
	nf_unregister_net_hooks(net, provenance_nf_ops, ARRAY_SIZE(provenance_nf_ops));
}

static struct pernet_operations provenance_net_ops = {
	.init	= provenance_nf_register,
	.exit	= provenance_nf_unregister,
};

/*!
 * Initialization of netfilter hooks.
 */
static int __init provenance_nf_ip_init(void)
{
	int err;

	pr_info("Provenance: registering netfilter hooks.\n");
	err = register_pernet_subsys(&provenance_net_ops);
	if (err)
		panic("Provenance: register_pernet_subsys error %d\n", err);
	return 0;
}

__initcall(provenance_nf_ip_init);
