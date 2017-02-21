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
 #ifndef _LINUX_CAMFLOW_POLICY_H
 #define _LINUX_CAMFLOW_POLICY_H

 #include <uapi/linux/provenance.h>

 struct policy_hook {
  struct list_head list;
  int (*camflow_policy_hook)(const union prov_msg*, const union prov_msg*, const union prov_msg*);
 };

 extern struct policy_hook policy_hooks;

int register_camflow_policy_hook( struct policy_hook *hook){
  if(!hook)
   return -ENOMEM;
  list_add_tail_rcu(&(hook->list), &(policy_hooks.list));
  return 0;
}

int unregister_camflow_policy_hook( struct policy_hook *hook){
  list_del_rcu(&(hook->list));
  return 0;
}

int call_camflow_policy_hook(const union prov_msg *from,
                            const union prov_msg *to,
                            const union prov_msg *edge){
  int rc=0;
  struct list_head *pos, *q;
  struct policy_hook *fcn;

	list_for_each_safe(pos, q, &(policy_hooks.list)) {
		fcn = list_entry(pos, struct policy_hook, list);
		if(!fcn->camflow_policy_hook)
      rc|=fcn->camflow_policy_hook(from, to, edge);
	}
  return rc;
}

 #endif
