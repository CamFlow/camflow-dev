// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2016 University of Cambridge,
 * Copyright (C) 2016-2017 Harvard University,
 * Copyright (C) 2017-2018 University of Cambridge,
 * Copyright (C) 2018-2021 University of Bristol
 *
 * Author: Thomas Pasquier <thomas.pasquier@bristol.ac.uk>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 */
#include <linux/rculist.h>
#include <uapi/asm-generic/errno-base.h>

#include "provenance_query.h"

/*!
 * @brief Register provenance query hooks.
 *
 * @param hook The provenance_query_hooks pointer.
 * @return 0 if no error occurred; -ENOMEM if hook is NULL (does not exist yet).
 *
 */
int register_provenance_query_hooks(struct provenance_query_hooks *hook)
{
	if (!hook)
		return -ENOMEM;
	pr_info("Provenance: registering policy hook...\n");
	list_add_tail_rcu(&(hook->list), &provenance_query_hooks);
	return 0;
}
EXPORT_SYMBOL_GPL(register_provenance_query_hooks);

/*!
 * @brief Unregister provenance query hooks.
 *
 * @param hook The provenance_query_hooks pointer.
 * @return 0 if no error occurred.
 *
 */
int unregister_provenance_query_hooks(struct provenance_query_hooks *hook)
{
	list_del_rcu(&(hook->list));
	return 0;
}
EXPORT_SYMBOL_GPL(unregister_provenance_query_hooks);
