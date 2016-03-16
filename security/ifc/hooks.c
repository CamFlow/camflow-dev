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
#include <linux/ifc.h>
#include <linux/slab.h>
#include <linux/lsm_hooks.h>
#include <linux/msg.h>
#include <net/sock.h>
#include <linux/binfmts.h>
#include <linux/random.h>
#include <linux/xattr.h>

struct crypto_cipher *ifc_tfm;
atomic64_t ifc_tag_count=ATOMIC64_INIT(0);

static const uint64_t key=0xAEF; // not safe
int tag_crypto_init(void){
  int rv;
  ifc_tfm = crypto_alloc_cipher("blowfish", 0, CRYPTO_ALG_ASYNC);
  if(IS_ERR((void *)ifc_tfm)){
    printk(KERN_INFO "IFC: cannot alloc crypto cipher. Error: %ld.\n", PTR_ERR((void *)ifc_tfm));
    return PTR_ERR((void *)ifc_tfm);
  }
  rv = crypto_cipher_setkey(ifc_tfm, (const u8*)&key, sizeof(uint64_t));
  return rv;
}

static struct security_hook_list ifc_hooks[] = {
};

void __init ifc_add_hooks(void){
  if(tag_crypto_init()){
    printk(KERN_ERR "IFC: tag_crypto_init failure\n");
  }

  security_add_hooks(ifc_hooks, ARRAY_SIZE(ifc_hooks));
  printk(KERN_INFO "IFC hooks ready.\n");
}
