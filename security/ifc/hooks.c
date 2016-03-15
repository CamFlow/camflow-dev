/*
*
* /linux/security/ifc/hooks.c
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

#include <linux/provenance.h>
#include <linux/slab.h>
#include <linux/lsm_hooks.h>
#include <linux/msg.h>
#include <net/sock.h>
#include <linux/binfmts.h>
#include <linux/random.h>
#include <linux/xattr.h>

static struct security_hook_list ifc_hooks[] = {
};

void __init ifc_add_hooks(void){
  security_add_hooks(ifc_hooks, ARRAY_SIZE(ifc_hooks));
  printk(KERN_INFO "IFC hooks ready.\n");
}
