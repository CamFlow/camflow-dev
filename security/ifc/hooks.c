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

struct kmem_cache *ifc_cache=NULL;

static inline struct ifc_struct* alloc_ifc(gfp_t gfp)
{
  struct ifc_struct* ifc =  kmem_cache_zalloc(ifc_cache, gfp);
  if(!ifc){
    return NULL;
  }
  return ifc;
}

static inline struct ifc_struct* inherit_ifc(struct ifc_struct* old, gfp_t gfp)
{
  struct ifc_struct* ifc =  kmem_cache_zalloc(ifc_cache, gfp);
  if(!ifc)
    return NULL;

  if(!old)
    return ifc;
  /* copy tags */
  memcpy(&ifc->context.secrecy, &old->context.secrecy, sizeof(struct ifc_label));
  memcpy(&ifc->context.integrity, &old->context.integrity, sizeof(struct ifc_label));
  return ifc;
}

static inline void free_ifc(struct ifc_struct* ifc){
  kmem_cache_free(ifc_cache, ifc);
}

/*
* @cred points to the credentials.
* @gfp indicates the atomicity of any memory allocations.
* Only allocate sufficient memory and attach to @cred such that
* cred_transfer() will not get ENOMEM.
*/
static int ifc_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{
  struct ifc_struct* ifc = alloc_ifc(gfp);
  if(!ifc){
    return -ENOMEM;
  }
  cred->ifc = ifc;
  return 0;
}

/*
* @cred points to the credentials.
* Deallocate and clear the cred->security field in a set of credentials.
*/
static void ifc_cred_free(struct cred *cred)
{
  free_ifc(cred->ifc);
  cred->ifc = NULL;
}

/*
* @new points to the new credentials.
* @old points to the original credentials.
* @gfp indicates the atomicity of any memory allocations.
* Prepare a new set of credentials by copying the data from the old set.
*/
static int ifc_cred_prepare(struct cred *new, const struct cred *old, gfp_t gfp)
{
  struct ifc_struct *old_ifc = old->ifc;
  struct ifc_struct *new_ifc;

  if(unlikely(old_ifc->bridge.spawner==true)){
    new_ifc = alloc_ifc(gfp);
    if(!new_ifc){
      return -ENOMEM;
    }
    new_ifc->bridge.remote_pid = old_ifc->bridge.remote_pid;
    new_ifc->bridge.bridge=true;
  }else{
    new_ifc = inherit_ifc(old_ifc, gfp);
  }

  new->ifc=new_ifc;
	return 0;
}

/*
* @new points to the new credentials.
* @old points to the original credentials.
* Transfer data from original creds to new creds
*/
static void ifc_cred_transfer(struct cred *new, const struct cred *old)
{
  struct ifc_struct *old_ifc = old->ifc;
	struct ifc_struct *ifc = new->ifc;

  *old_ifc=*ifc;
}

static struct security_hook_list ifc_hooks[] = {
  LSM_HOOK_INIT(cred_alloc_blank, ifc_cred_alloc_blank),
  LSM_HOOK_INIT(cred_free, ifc_cred_free),
  LSM_HOOK_INIT(cred_prepare, ifc_cred_prepare),
  LSM_HOOK_INIT(cred_transfer, ifc_cred_transfer)
};

#define CRYPTO_DRIVER_NAME "blowfish"
struct crypto_cipher *ifc_tfm = NULL;
static const uint64_t ifc_key=0xAEF; // not safe

int ifc_crypto_init(void){
  ifc_tfm = crypto_alloc_cipher(CRYPTO_DRIVER_NAME, 0, 0);
  if(IS_ERR((void *)ifc_tfm)){
    printk(KERN_ERR "IFC: Failed to load transform for %s: %ld\n", CRYPTO_DRIVER_NAME, PTR_ERR(ifc_tfm));
    ifc_tfm = NULL;
    return PTR_ERR((void *)ifc_tfm);
  }
  return crypto_cipher_setkey(ifc_tfm, (const u8*)&ifc_key, sizeof(uint64_t));
}

/* init security of the first process */
static void cred_init_security(void){
	struct cred *cred = (struct cred *)current->real_cred;
	struct ifc_struct *ifc;

  ifc = alloc_ifc(GFP_KERNEL);
	if(!ifc){
		panic("IFC: Failed to initialize initial task.\n");
	}
	cred->ifc = ifc;
}

atomic64_t ifc_tag_count=ATOMIC64_INIT(1);

void __init ifc_add_hooks(void){
  int rc;

  printk(KERN_INFO "IFC Camflow %s\n", CAMFLOW_VERSION_STR);
  rc = ifc_crypto_init();
  if(rc){
    printk(KERN_ERR "IFC: cannot alloc crypto cipher. Error: %d.\n", rc);
  }

  ifc_cache = kmem_cache_create("ifc_struct",
					    sizeof(struct ifc_struct),
					    0, SLAB_PANIC, NULL);
  cred_init_security();
  security_add_hooks(ifc_hooks, ARRAY_SIZE(ifc_hooks));
  printk(KERN_INFO "IFC hooks ready.\n");
}
