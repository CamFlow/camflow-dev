/*
 *
 * Author: Thomas Pasquier <tfjmp@g.harvard.edu>
 *
 * Copyright (C) 2017 Harvard University
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 */
 #ifndef __LINUX_CAMFLOW_POLICY_H
 #define __LINUX_CAMFLOW_POLICY_H

 #include <uapi/linux/provenance.h>

struct policy_hook {
  struct list_head list;
  int (*out_edge)(const union prov_msg*, struct relation_struct*);
  int (*in_edge)(struct relation_struct*, const union prov_msg*);
};

 extern struct policy_hook policy_hooks;

static inline int register_camflow_policy_hook( struct policy_hook *hook){
  if(!hook)
   return -ENOMEM;
  list_add_tail_rcu(&(hook->list), &(policy_hooks.list));
  return 0;
}

static inline int unregister_camflow_policy_hook( struct policy_hook *hook){
  list_del_rcu(&(hook->list));
  return 0;
}

static inline int call_camflow_out_edge(const union prov_msg* node,
                            struct relation_struct* out){
  int rc=0;
  struct list_head *pos, *q;
  struct policy_hook *fcn;

	list_for_each_safe(pos, q, &(policy_hooks.list)) {
		fcn = list_entry(pos, struct policy_hook, list);
		if(!fcn->out_edge)
      rc|=fcn->out_edge(node, out);
	}
  return rc;
}

static inline int call_camflow_in_edge(struct relation_struct* in,
                            const union prov_msg* node){
  int rc=0;
  struct list_head *pos, *q;
  struct policy_hook *fcn;

	list_for_each_safe(pos, q, &(policy_hooks.list)) {
		fcn = list_entry(pos, struct policy_hook, list);
		if(!fcn->in_edge)
      rc|=fcn->in_edge(in, node);
	}
  return rc;
}
 #endif
