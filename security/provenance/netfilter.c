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
#include <linux/camflow.h>

#include "provenance.h"

static inline unsigned int __ipv4_in(struct sk_buff *skb)
{
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

  printk(KERN_INFO "Provenance netfilter ready.\n");

  err = nf_register_hooks(provenance_nf_ops, ARRAY_SIZE(provenance_nf_ops));
  if(err){
    panic("Provenance: nf_register_hooks: error %d\n", err);
  }
  return 0;
}
__initcall(provenance_nf_init);
#endif
