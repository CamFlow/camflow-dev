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
#include <linux/rculist.h>

#include "provenance_query.h"

int register_provenance_query_hooks(struct provenance_query_hooks *hook)
{
	if (!hook)
		return -ENOMEM;
	pr_info("Provenance: registering policy hook...\n");
	list_add_tail_rcu(&(hook->list), &provenance_query_hooks);
	return 0;
}
EXPORT_SYMBOL_GPL(register_provenance_query_hooks);

int unregister_provenance_query_hooks(struct provenance_query_hooks *hook)
{
	list_del_rcu(&(hook->list));
	return 0;
}
EXPORT_SYMBOL_GPL(unregister_provenance_query_hooks);
