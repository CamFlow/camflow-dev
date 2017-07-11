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
#ifndef CONFIG_SECURITY_PROVENANCE_USER
#define CONFIG_SECURITY_PROVENANCE_USER

struct user_filters {
	struct list_head list;
	struct userinfo filter;
};

extern struct list_head user_filters;

static inline uint8_t prov_uid_whichOP(uint32_t uid)
{
	struct list_head *listentry, *listtmp;
	struct user_filters *tmp;

	list_for_each_safe(listentry, listtmp, &user_filters) {
		tmp = list_entry(listentry, struct user_filters, list);
		if (tmp->filter.uid == uid)
			return tmp->filter.op;
	}
	return 0; // do nothing
}

static inline uint8_t prov_uid_delete(struct user_filters *f)
{
	struct list_head *listentry, *listtmp;
	struct user_filters *tmp;

	list_for_each_safe(listentry, listtmp, &user_filters) {
		tmp = list_entry(listentry, struct user_filters, list);
		if (tmp->filter.uid == f->filter.uid) {
			list_del(listentry);
			kfree(tmp);
			return 0; // you should only get one
		}
	}
	return 0; // do nothing
}

static inline uint8_t prov_uid_add_or_update(struct user_filters *f)
{
	struct list_head *listentry, *listtmp;
	struct user_filters *tmp;

	list_for_each_safe(listentry, listtmp, &user_filters) {
		tmp = list_entry(listentry, struct user_filters, list);
		if (tmp->filter.uid == f->filter.uid) {
			tmp->filter.op = f->filter.op;
			return 0; // you should only get one
		}
	}
	list_add_tail(&(f->list), &user_filters); // not already on the list, we add it
	return 0;
}
#endif
