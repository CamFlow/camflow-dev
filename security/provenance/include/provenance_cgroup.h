/*
 *
 * Author: Thomas Pasquier <tfjmp@seas.harvard.edu>
 *
 * Copyright (C) 2017 Harvard University
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 */
#ifndef CONFIG_SECURITY_PROVENANCE_CGROUP
#define CONFIG_SECURITY_PROVENANCE_CGROUP

struct cgroup_filters {
	struct list_head list;
	struct cgroupinfo filter;
};

extern struct cgroup_filters cgroup_filters;

static inline uint8_t prov_cgroup_whichOP(struct cgroup_filters *filters, uint32_t cid)
{
	struct cgroup_filters *tmp;

	list_for_each_entry(tmp, &(filters->list), list) {
		if (tmp->filter.cid == cid)
			return tmp->filter.op;
	}
	return 0; // do nothing
}

static inline uint8_t prov_cgroup_delete(struct cgroup_filters *filters, struct cgroup_filters *f)
{
	struct list_head *pos, *q;
	struct cgroup_filters *tmp;

	list_for_each_safe(pos, q, &(filters->list)) {
		tmp = list_entry(pos, struct cgroup_filters, list);
		if (tmp->filter.cid == f->filter.cid) {
			list_del(pos);
			kfree(tmp);
			return 0; // you should only get one
		}
	}
	return 0; // do nothing
}

static inline uint8_t prov_cgroup_add_or_update(struct cgroup_filters *filters, struct cgroup_filters *f)
{
	struct list_head *pos, *q;
	struct cgroup_filters *tmp;

	list_for_each_safe(pos, q, &(filters->list)) {
		tmp = list_entry(pos, struct cgroup_filters, list);
		if (tmp->filter.cid == f->filter.cid) {
			tmp->filter.op = f->filter.op;
			return 0; // you should only get one
		}
	}
	list_add_tail(&(f->list), &(filters->list)); // not already on the list, we add it
	return 0;
}

#endif
