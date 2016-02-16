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

static char* edge_str[]={"data", "create", "pass", "change", "unknown"};
static char* node_str[]={"task", "inode", "unknown"};

struct provenance_ops{
  void (*init)(void);
  void (*log_edge)(struct edge_struct*);
  void (*log_node)(struct node_struct*);
  void (*log_str)(struct str_struct*);
};

/* provenance usher functions */
int provenance_register(struct provenance_ops* ops);
void provenance_stop(void);

/* security file manipulation */
int provenance_set_enable(bool v);
int provenance_set_all(bool v);
int provenance_set_opaque(bool v);

#endif /* __PROVENANCELIB_H */
