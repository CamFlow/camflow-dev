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

#include "provenance.h"

int in_edge(struct relation_struct* edge, const union prov_msg* node){
  printk(KERN_INFO "Provenance propagate in.\n");
  return 0;
}

int out_edge(const union prov_msg* node, struct relation_struct* edge){
  printk(KERN_INFO "Provenance propagate out.\n");
  return 0;
}

struct policy_hook hooks = {
  .out_edge=out_edge,
  .in_edge=in_edge
};

static int __init init_prov_propagate(void)
{
  register_camflow_policy_hook(&hooks);
  printk(KERN_INFO "Provenance propagate ready.\n");
	return 0;
}
core_initcall(init_prov_propagate);
