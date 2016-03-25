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
#include <linux/camflow.h>
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
  struct ifc_struct *new_ifc, *caller_ifc;
  pid_t cpid;
  struct task_struct* dest;
  const struct cred* caller;

  if(unlikely(old_ifc->bridge.spawner==true)){
    new_ifc = alloc_ifc(gfp);
    if(!new_ifc){
      return -ENOMEM;
    }
    new_ifc->bridge.remote_pid = old_ifc->bridge.remote_pid;
    new_ifc->bridge.bridge=true;
    cpid = task_pid_vnr(current);
    dest = find_task_by_vpid(new_ifc->bridge.remote_pid);
    if(dest==NULL){
      return -EFAULT;
    }
    caller = __task_cred(dest);
    caller_ifc = caller->ifc;
    caller_ifc->bridge.remote_pid = cpid;
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

/*
* Allocate and attach a security structure to @inode->i_security.  The
* i_security field is initialized to NULL when the inode structure is
* allocated.
* @inode contains the inode structure.
* Return 0 if operation was successful.
*/
static int ifc_inode_alloc_security(struct inode *inode)
{
  struct ifc_struct* cifc = current_ifc();
  struct ifc_struct* ifc = inherit_ifc(cifc, GFP_KERNEL);
  if(!ifc){
    return -ENOMEM;
  }
  alloc_camflow(inode, GFP_KERNEL);
  inode_set_ifc(inode, (void**)&ifc);
  return 0;
}

/*
* @inode contains the inode structure.
* Deallocate the inode security structure and set @inode->i_security to
* NULL.
*/
static void ifc_inode_free_security(struct inode *inode)
{
  struct ifc_struct* ifc = inode_get_ifc(inode);
  if(!ifc)
    free_ifc(ifc);
	inode_set_ifc(inode, NULL);
	free_camflow(inode);
}

/*
* Check permission before accessing an inode.  This hook is called by the
* existing Linux permission function, so a security module can use it to
* provide additional checking for existing Linux permission checks.
* Notice that this hook is called when a file is opened (as well as many
* other operations), whereas the file_security_ops permission hook is
* called when the actual read/write operations are performed.
* @inode contains the inode structure to check.
* @mask contains the permission mask.
* Return 0 if permission is granted.
*/
static int ifc_inode_permission(struct inode *inode, int mask)
{
  struct ifc_struct* cifc = current_ifc();
  struct ifc_struct* ifc=NULL;
#ifdef CONFIG_SECURITY_PROVENANCE
	prov_msg_t *i_prov=NULL;
  prov_msg_t *p_prov=NULL;
#endif

  mask &= (MAY_READ|MAY_WRITE|MAY_EXEC|MAY_APPEND);
  // no permission to check. Existence test
  if (!mask)
		return 0;

  if(unlikely(IS_PRIVATE(inode)))
		return 0;

  ifc = inode_get_ifc(inode);
  if(!ifc){
    ifc_inode_alloc_security(inode);
    ifc = inode_get_ifc(inode);
  }

#ifdef CONFIG_SECURITY_PROVENANCE
  i_prov=inode_get_provenance(inode);
  p_prov=current_provenance();
  if(ifc_is_labelled(&cifc->context))
    p_prov->node_info.tracked=NODE_TRACKED;

  if(ifc_is_labelled(&ifc->context))
    i_prov->node_info.tracked=NODE_TRACKED;
#endif

  if((mask & (MAY_WRITE|MAY_APPEND)) != 0){
    // process -> inode
    if(!ifc_can_flow(&cifc->context, &ifc->context)){
#ifdef CONFIG_SECURITY_PROVENANCE
      record_edge(ED_DATA, p_prov, i_prov, FLOW_DISALLOWED);
#endif
      return -EPERM;
    }
  }
  if((mask & (MAY_READ)) != 0){
    // inode -> process
    if(!ifc_can_flow(&ifc->context, &cifc->context)){
#ifdef CONFIG_SECURITY_PROVENANCE
      record_edge(ED_DATA, i_prov, p_prov, FLOW_DISALLOWED);
#endif
      return -EPERM;
    }
  }
  return 0;
}

/*
* Check file permissions before accessing an open file.  This hook is
* called by various operations that read or write files.  A security
* module can use this hook to perform additional checking on these
* operations, e.g.  to revalidate permissions on use to support privilege
* bracketing or policy changes.  Notice that this hook is used when the
* actual read/write operations are performed, whereas the
* inode_security_ops hook is called when a file is opened (as well as
* many other operations).
* Caveat:  Although this hook can be used to revalidate permissions for
* various system call operations that read or write files, it does not
* address the revalidation of permissions for memory-mapped files.
* Security modules must handle this separately if they need such
* revalidation.
* @file contains the file structure being accessed.
* @mask contains the requested permissions.
* Return 0 if permission is granted.
*/
static int ifc_file_permission(struct file *file, int mask)
{
  struct inode *inode = file_inode(file);
  return ifc_inode_permission(inode, mask);
}

static struct security_hook_list ifc_hooks[] = {
  LSM_HOOK_INIT(cred_alloc_blank, ifc_cred_alloc_blank),
  LSM_HOOK_INIT(cred_free, ifc_cred_free),
  LSM_HOOK_INIT(cred_prepare, ifc_cred_prepare),
  LSM_HOOK_INIT(cred_transfer, ifc_cred_transfer),
  LSM_HOOK_INIT(inode_alloc_security, ifc_inode_alloc_security),
  LSM_HOOK_INIT(inode_free_security, ifc_inode_free_security),
  LSM_HOOK_INIT(inode_permission, ifc_inode_permission),
  LSM_HOOK_INIT(file_permission, ifc_file_permission)
};

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

struct kmem_cache *camflow_cache=NULL;

void __init ifc_add_hooks(void){
  ifc_cache = kmem_cache_create("ifc_struct",
					    sizeof(struct ifc_struct),
					    0, SLAB_PANIC, NULL);

  camflow_cache = kmem_cache_create("camflow_i_ptr",
					    sizeof(struct camflow_i_ptr),
					    0, SLAB_PANIC, NULL);
  cred_init_security();
  security_add_hooks(ifc_hooks, ARRAY_SIZE(ifc_hooks));
  printk(KERN_INFO "IFC Camflow %s\n", CAMFLOW_VERSION_STR);
  printk(KERN_INFO "IFC hooks ready.\n");
}
