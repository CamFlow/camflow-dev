/*
 *
 * Author: Thomas Pasquier <thomas.pasquier@cl.cam.ac.uk>
 *
 * Copyright (C) 2015 University of Cambridge
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 */
#ifndef _PROVENANCE_CORE_H
#define _PROVENANCE_CORE_H

extern atomic64_t prov_relation_id;
extern atomic64_t prov_node_id;
extern uint32_t prov_machine_id;
extern uint32_t prov_boot_id;

#define prov_next_relation_id() ((uint64_t)atomic64_inc_return(&prov_relation_id))
#define prov_next_node_id() ((uint64_t)atomic64_inc_return(&prov_node_id))

enum {
	PROVENANCE_LOCK_TASK,
	PROVENANCE_LOCK_DIR,
	PROVENANCE_LOCK_INODE,
	PROVENANCE_LOCK_MSG,
	PROVENANCE_LOCK_SHM,
	PROVENANCE_LOCK_SOCKET,
	PROVENANCE_LOCK_SOCK
};

struct provenance {
	union prov_elt msg;
	spinlock_t lock;
	uint8_t has_mmap;
	bool has_outgoing;
	bool initialised;
	bool saved;
};

#define prov_elt(provenance) (&(provenance->msg))
#define prov_lock(provenance) (&(provenance->lock))
#define prov_entry(provenance) ((prov_entry_t*)prov_elt(provenance))

#define ASSIGN_NODE_ID 0
#endif
