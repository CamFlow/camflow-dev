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

 #define CAMFLOW_RAISE_WARNING  1
 #define CAMFLOW_PREVENT_FLOW   2

struct policy_hook {
  struct list_head list;
  int (*out_edge)(const union prov_msg*, struct relation_struct*);
  int (*in_edge)(struct relation_struct*, const union prov_msg*);
};

 extern struct list_head policy_hooks;

int register_camflow_policy_hook( struct policy_hook *hook);
int unregister_camflow_policy_hook( struct policy_hook *hook);
#endif
