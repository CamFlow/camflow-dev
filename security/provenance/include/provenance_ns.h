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
#ifndef _PROVENANCE_NS_H
#define _PROVENANCE_NS_H

struct ns_filters {
	struct list_head list;
	struct nsinfo filter;
};

extern struct list_head ns_filters;

static inline uint8_t prov_ns_whichOP(uint32_t utsns,
				      uint32_t ipcns,
				      uint32_t mntns,
				      uint32_t pidns,
				      uint32_t netns,
				      uint32_t cgroupns)
{
	struct list_head *listentry, *listtmp;
	struct ns_filters *tmp;

	list_for_each_safe(listentry, listtmp, &ns_filters) {
		tmp = list_entry(listentry, struct ns_filters, list);
		if ((tmp->filter.cgroupns == cgroupns || tmp->filter.cgroupns == IGNORE_NS)
		    && (tmp->filter.utsns == utsns || tmp->filter.utsns == IGNORE_NS)
		    && (tmp->filter.ipcns == ipcns || tmp->filter.ipcns == IGNORE_NS)
		    && (tmp->filter.mntns == mntns || tmp->filter.mntns == IGNORE_NS)
		    && (tmp->filter.pidns == pidns || tmp->filter.pidns == IGNORE_NS)
		    && (tmp->filter.netns == netns || tmp->filter.netns == IGNORE_NS))
			return tmp->filter.op;
	}
	return 0; // do nothing
}

static inline uint8_t prov_ns_delete(struct ns_filters *f)
{
	struct list_head *listentry, *listtmp;
	struct ns_filters *tmp;

	list_for_each_safe(listentry, listtmp, &ns_filters) {
		tmp = list_entry(listentry, struct ns_filters, list);
		if (tmp->filter.cgroupns == f->filter.cgroupns
		    && tmp->filter.utsns == f->filter.utsns
		    && tmp->filter.ipcns == f->filter.ipcns
		    && tmp->filter.mntns == f->filter.mntns
		    && tmp->filter.pidns == f->filter.pidns
		    && tmp->filter.netns == f->filter.netns
		    ) {
			list_del(listentry);
			kfree(tmp);
			return 0; // you should only get one
		}
	}
	return 0; // do nothing
}

static inline uint8_t prov_ns_add_or_update(struct ns_filters *f)
{
	struct list_head *listentry, *listtmp;
	struct ns_filters *tmp;

	list_for_each_safe(listentry, listtmp, &ns_filters) {
		tmp = list_entry(listentry, struct ns_filters, list);
		if (tmp->filter.cgroupns == f->filter.cgroupns
		    && tmp->filter.utsns == f->filter.utsns
		    && tmp->filter.ipcns == f->filter.ipcns
		    && tmp->filter.mntns == f->filter.mntns
		    && tmp->filter.pidns == f->filter.pidns
		    && tmp->filter.netns == f->filter.netns
		    ) {
			tmp->filter.op = f->filter.op;
			return 0; // you should only get one
		}
	}
	list_add_tail(&(f->list), &ns_filters); // not already on the list, we add it
	return 0;
}
#endif
