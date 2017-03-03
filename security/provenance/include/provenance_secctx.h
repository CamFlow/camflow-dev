/*
 *
 * Author: Thomas Pasquier <tfjmp@seas.harvard.edu>
 *
 * Copyright (C) 2016 Harvard University
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 */
#ifndef CONFIG_SECURITY_PROVENANCE_SECCTX
#define CONFIG_SECURITY_PROVENANCE_SECCTX

struct secctx_filters {
	struct list_head list;
	struct secinfo filter;
};

extern struct list_head secctx_filters;

static inline uint8_t prov_secctx_whichOP(uint32_t secid)
{
	struct list_head *listentry, *listtmp;
	struct secctx_filters *tmp;

	list_for_each_safe(listentry, listtmp, &secctx_filters) {
		tmp = list_entry(listentry, struct secctx_filters, list);
		if (tmp->filter.secid == secid)
			return tmp->filter.op;
	}
	return 0; // do nothing
}

static inline uint8_t prov_secctx_delete(struct secctx_filters  *f)
{
	struct list_head *listentry, *listtmp;
	struct secctx_filters *tmp;

	list_for_each_safe(listentry, listtmp, &secctx_filters) {
		tmp = list_entry(listentry, struct secctx_filters, list);
		if (tmp->filter.secid == f->filter.secid) {
			list_del(listentry);
			kfree(tmp);
			return 0; // you should only get one
		}
	}
	return 0; // do nothing
}

static inline uint8_t prov_secctx_add_or_update( struct secctx_filters *f)
{
	struct list_head *listentry, *listtmp;
	struct secctx_filters *tmp;

	list_for_each_safe(listentry, listtmp, &secctx_filters) {
		tmp = list_entry(listentry, struct secctx_filters, list);
		if (tmp->filter.secid == f->filter.secid) {
			tmp->filter.op = f->filter.op;
			return 0; // you should only get one
		}
	}
	list_add_tail(&(f->list), &secctx_filters); // not already on the list, we add it
	return 0;
}

#endif
