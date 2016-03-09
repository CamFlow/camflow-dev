/*
*
* provenancelib.h
*
* Author: Thomas Pasquier <tfjmp2@cam.ac.uk>
*
* Copyright (C) 2015 University of Cambridge
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License version 2, as
* published by the Free Software Foundation.
*
*/
#ifndef __PROVENANCELIB_H
#define __PROVENANCELIB_H


#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <linux/provenance.h>

static char* edge_str[]={"data", "create", "pass", "change", "mmap", "unknown"};

struct provenance_ops{
  void (*init)(void);
  void (*log_edge)(struct edge_struct*);
  void (*log_task)(struct task_prov_struct*);
  void (*log_inode)(struct inode_prov_struct*);
  void (*log_str)(struct str_struct*);
  void (*log_link)(struct link_struct*);
  void (*log_unlink)(struct unlink_struct*);
  void (*log_disc)(struct disc_node_struct*);
  void (*log_msg)(struct msg_prov_struct*);
};

/* provenance usher functions */
int provenance_register(struct provenance_ops* ops);
void provenance_stop(void);

/* security file manipulation */
int provenance_set_enable(bool v);
int provenance_set_all(bool v);
int provenance_set_opaque(bool v);
int provenance_disclose_node(struct disc_node_struct* node);
int provenance_disclose_edge(struct edge_struct* edge);
int provenance_self(struct task_prov_struct* self);

#endif /* __PROVENANCELIB_H */
