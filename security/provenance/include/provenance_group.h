/*
 *
 * Author: Thomas Pasquier <tfjmp@seas.harvard.edu>
 *
 * Copyright (C) 2017 Harvard University
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 */
#ifndef CONFIG_SECURITY_PROVENANCE_GROUP
#define CONFIG_SECURITY_PROVENANCE_GROUP

struct group_filters {
	struct list_head list;
	struct groupinfo filter;
};

extern struct list_head group_filters;

static inline uint8_t prov_gid_whichOP(uint32_t gid)
{
	struct list_head *listentry, *listtmp;
	struct group_filters *tmp;

	list_for_each_safe(listentry, listtmp, &group_filters) {
		tmp = list_entry(listentry, struct group_filters, list);
		if (tmp->filter.gid == gid)
			return tmp->filter.op;
	}
	return 0; // do nothing
}

static inline uint8_t prov_gid_delete(struct group_filters *f)
{
	struct list_head *listentry, *listtmp;
	struct group_filters *tmp;

	list_for_each_safe(listentry, listtmp, &group_filters) {
		tmp = list_entry(listentry, struct group_filters, list);
		if (tmp->filter.gid == f->filter.gid) {
			list_del(listentry);
			kfree(tmp);
			return 0; // you should only get one
		}
	}
	return 0; // do nothing
}

static inline uint8_t prov_gid_add_or_update(struct group_filters *f)
{
	struct list_head *listentry, *listtmp;
	struct group_filters *tmp;

	list_for_each_safe(listentry, listtmp, &group_filters) {
		tmp = list_entry(listentry, struct group_filters, list);
		if (tmp->filter.gid == f->filter.gid) {
			tmp->filter.op = f->filter.op;
			return 0; // you should only get one
		}
	}
	list_add_tail(&(f->list), &group_filters); // not already on the list, we add it
	return 0;
}
#endif
