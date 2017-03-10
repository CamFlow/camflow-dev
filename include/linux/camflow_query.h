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
 #ifndef __LINUX_CAMFLOW_QUERY_H
 #define __LINUX_CAMFLOW_QUERY_H

 #include <uapi/linux/provenance.h>

 #define CAMFLOW_RAISE_WARNING  1
 #define CAMFLOW_PREVENT_FLOW   2

struct provenance_query_hooks {
  struct list_head list;
  int (*out_edge)(union prov_msg*, union prov_msg*);
  int (*in_edge)(union prov_msg*, union prov_msg*);
};

 extern struct list_head provenance_query_hooks;

int register_camflow_query_hook( struct provenance_query_hooks *hook);
int unregister_camflow_query_hook( struct provenance_query_hooks *hook);
#endif
