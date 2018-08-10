/*
 *
 * Author: Thomas Pasquier <thomas.pasquier@bristol.ac.uk>
 *
 * Copyright (C) 2015-2018 University of Cambridge, Harvard University, University of Bristol
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 */
 #ifndef _LINUX_PROVENANCE_QUERY_H
 #define _LINUX_PROVENANCE_QUERY_H

 #include <uapi/linux/provenance.h>

 #define PROVENANCE_RAISE_WARNING  1
 #define PROVENANCE_PREVENT_FLOW   2

 #define QUERY_HOOK_INIT(HEAD, HOOK) .HEAD=&HOOK

struct provenance_query_hooks {
  struct list_head list;
  int (*flow)(prov_entry_t*, prov_entry_t*, prov_entry_t*);
  int (*alloc)(prov_entry_t*);
  int (*free)(prov_entry_t*);
};

 extern struct list_head provenance_query_hooks;

int register_provenance_query_hooks( struct provenance_query_hooks *hook);
int unregister_provenance_query_hooks( struct provenance_query_hooks *hook);
#endif
