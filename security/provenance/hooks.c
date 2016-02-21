/*
*
* /linux/security/provenance/hooks.c
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

atomic64_t prov_node_id=ATOMIC64_INIT(0);
static struct kmem_cache *provenance_cache;

static inline void record_node(prov_msg_t* prov){
  if(!prov_enabled) // capture is not enabled, ignore
    return;

  prov->node_info.recorded=NODE_RECORDED;
  prov_write(prov);
}

static inline void record_edge(edge_type_t type, prov_msg_t* from, prov_msg_t* to){
  prov_msg_t edge;
  memset(&edge, 0, sizeof(prov_msg_t));

  if(from->node_info.opaque == NODE_OPAQUE || to->node_info.opaque == NODE_OPAQUE) // to or from are opaque
    return;

  if(!prov_enabled) // capture is not enabled, ignore
    return;

  if(!(from->node_info.recorded == NODE_RECORDED) )
    record_node(from);

  if(!(to->node_info.recorded == NODE_RECORDED) )
    record_node(to);

  edge.edge_info.message_type=MSG_EDGE;
  edge.edge_info.snd_id=from->node_info.node_id;
  edge.edge_info.rcv_id=to->node_info.node_id;
  edge.edge_info.allowed=FLOW_ALLOWED;
  edge.edge_info.type=type;
  prov_write(&edge);
}

static inline node_id_t prov_next_nodeid( void )
{
  return (node_id_t)atomic64_inc_return(&prov_node_id);
}

static inline prov_msg_t* alloc_provenance(node_id_t nid, message_type_t ntype, gfp_t gfp)
{
  prov_msg_t* prov =  kmem_cache_zalloc(provenance_cache, gfp);
  if(!prov){
    return NULL;
  }

  if(nid==0)
  {
    prov->node_info.node_id=prov_next_nodeid();
  }else{
    prov->node_info.node_id=nid;
  }
  prov->node_info.message_type=ntype;
  return prov;
}

static inline void free_provenance(prov_msg_t* prov){
  kmem_cache_free(provenance_cache, prov);
}

static inline prov_msg_t* provenance_clone(message_type_t ntype, prov_msg_t* old, gfp_t gfp)
{
  prov_msg_t* prov =   alloc_provenance(0, ntype, gfp);
  if(!prov)
  {
    return NULL;
  }
  return prov;
}


/*
 * initialise the security for the init task
 */
static void cred_init_provenance(void)
{
	struct cred *cred = (struct cred *) current->real_cred;
	prov_msg_t *prov;

	prov = alloc_provenance(0, MSG_TASK, GFP_KERNEL);
	if (!prov)
		panic("Provenance:  Failed to initialize initial task.\n");
  prov->node_info.uid=__kuid_val(cred->euid);
  prov->node_info.gid=__kgid_val(cred->egid);

	cred->provenance = prov;
}

/*
* @cred points to the credentials.
* @gfp indicates the atomicity of any memory allocations.
* Only allocate sufficient memory and attach to @cred such that
* cred_transfer() will not get ENOMEM.
*/
static int provenance_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{
  prov_msg_t* prov;

  prov = alloc_provenance(0, MSG_TASK, gfp);

  if(!prov)
    return -ENOMEM;
  prov->node_info.uid=__kuid_val(cred->euid);
  prov->node_info.gid=__kgid_val(cred->egid);

  cred->provenance = prov;
  return 0;
}

/*
* @cred points to the credentials.
* Deallocate and clear the cred->security field in a set of credentials.
*/
static void provenance_cred_free(struct cred *cred)
{
  free_provenance(cred->provenance);
  cred->provenance = NULL;
}

/*
* @new points to the new credentials.
* @old points to the original credentials.
* @gfp indicates the atomicity of any memory allocations.
* Prepare a new set of credentials by copying the data from the old set.
*/
static int provenance_cred_prepare(struct cred *new, const struct cred *old, gfp_t gfp)
{
  prov_msg_t* old_prov = old->provenance;
  prov_msg_t* prov = provenance_clone(MSG_TASK, old_prov, gfp);

  if(!prov)
    return -ENOMEM;
  prov->node_info.uid=__kuid_val(new->euid);
  prov->node_info.gid=__kgid_val(new->egid);

  if(old_prov->node_info.tracked == NODE_TRACKED || prov_all)
  {
    record_edge(ED_CREATE, old_prov, prov);
  }

  new->provenance = prov;
  return 0;
}

/*
* @new points to the new credentials.
* @old points to the original credentials.
* Transfer data from original creds to new creds
*/
static void provenance_cred_transfer(struct cred *new, const struct cred *old)
{
  const prov_msg_t *old_prov = old->provenance;
	prov_msg_t *prov = new->provenance;

  *prov=*old_prov;
}

/*
* Update the module's state after setting one or more of the user
* identity attributes of the current process.  The @flags parameter
* indicates which of the set*uid system calls invoked this hook.  If
* @new is the set of credentials that will be installed.  Modifications
* should be made to this rather than to @current->cred.
* @old is the set of credentials that are being replaces
* @flags contains one of the LSM_SETID_* values.
* Return 0 on success.
*/
static int provenance_task_fix_setuid(struct cred *new, const struct cred *old, int flags)
{
  prov_msg_t *old_prov = old->provenance;
	prov_msg_t *prov = new->provenance;

  if(old_prov->node_info.tracked == NODE_TRACKED || prov->node_info.tracked == NODE_TRACKED || prov_all) // record if entity tracked or if record everyting
  {
    record_edge(ED_CHANGE, old_prov, prov);
  }

  return 0;
}

/*
* Allocate and attach a security structure to @inode->i_security.  The
* i_security field is initialized to NULL when the inode structure is
* allocated.
* @inode contains the inode structure.
* Return 0 if operation was successful.
*/
static int provenance_inode_alloc_security(struct inode *inode)
{
  prov_msg_t* cprov = current_provenance();
  prov_msg_t* iprov;
  iprov = alloc_provenance(inode->i_ino, MSG_INODE, GFP_NOFS);
  if(unlikely(!iprov))
    return -ENOMEM;
  iprov->inode_info.uid=__kuid_val(inode->i_uid);
  iprov->inode_info.gid=__kgid_val(inode->i_gid);
  iprov->inode_info.mode=inode->i_mode;
  iprov->inode_info.rdev=inode->i_rdev;

  inode->i_provenance = iprov;

  if(cprov->node_info.tracked==NODE_TRACKED || iprov->node_info.tracked==NODE_TRACKED || prov_all){
    record_edge(ED_CREATE, cprov, iprov); /* creating inode != creating the file */
  }
  return 0;
}

/*
* @inode contains the inode structure.
* Deallocate the inode security structure and set @inode->i_security to
* NULL.
*/
static void provenance_inode_free_security(struct inode *inode)
{
  prov_msg_t* prov = inode->i_provenance;
  inode->i_provenance=NULL;
  if(!prov)
    free_provenance(prov);
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
static int provenance_inode_permission(struct inode *inode, int mask)
{
  prov_msg_t* cprov = current_provenance();
  prov_msg_t* iprov;

  if(!inode->i_provenance){ // alloc provenance if none there
    provenance_inode_alloc_security(inode);
  }

  iprov = inode->i_provenance;

  mask &= (MAY_READ|MAY_WRITE|MAY_EXEC|MAY_APPEND);

  if((mask & (MAY_WRITE|MAY_APPEND)) != 0){
    if(cprov->node_info.tracked==NODE_TRACKED || iprov->node_info.tracked==NODE_TRACKED || prov_all){
      record_edge(ED_DATA, cprov, iprov);
    }
  }
  if((mask & (MAY_READ|MAY_EXEC|MAY_WRITE|MAY_APPEND)) != 0){
    // conservatively assume write imply read
    if(cprov->node_info.tracked==NODE_TRACKED || iprov->node_info.tracked==NODE_TRACKED || prov_all){
      record_edge(ED_DATA, iprov, cprov);
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
static int provenance_file_permission(struct file *file, int mask)
{
  struct inode *inode = file_inode(file);
  if(!inode->i_provenance){ // alloc provenance if none there
    provenance_inode_alloc_security(inode);
  }
  provenance_inode_permission(inode, mask);
  return 0;
}

/*
* Check permissions for a mmap operation.  The @file may be NULL, e.g.
* if mapping anonymous memory.
* @file contains the file structure for file to map (may be NULL).
* @reqprot contains the protection requested by the application.
* @prot contains the protection that will be applied by the kernel.
* @flags contains the operational flags.
* Return 0 if permission is granted.
*/
static int provenance_mmap_file(struct file *file, unsigned long reqprot, unsigned long prot, unsigned long flags)
{
  prov_msg_t* cprov = current_provenance();
  prov_msg_t* iprov;
  struct inode *inode;
  if(file==NULL){ // what to do for NULL?
    return 0;
  }
  inode = file_inode(file);
  if(!inode->i_provenance){ // alloc provenance if none there
    provenance_inode_alloc_security(inode);
  }
  iprov = inode->i_provenance;
  prot &= (PROT_EXEC|PROT_READ|PROT_WRITE);

  if((prot & (PROT_WRITE|PROT_EXEC)) != 0){
    if(cprov->node_info.tracked==NODE_TRACKED || iprov->node_info.tracked==NODE_TRACKED || prov_all){
      record_edge(ED_MMAP, cprov, iprov);
    }
  }
  if((prot & (PROT_READ|PROT_EXEC|PROT_WRITE)) != 0){
    // conservatively assume write imply read
    if(cprov->node_info.tracked==NODE_TRACKED || iprov->node_info.tracked==NODE_TRACKED || prov_all){
      record_edge(ED_MMAP, iprov, cprov);
    }
  }
  return 0;
}

/*
* @file contains the file structure.
* @cmd contains the operation to perform.
* @arg contains the operational arguments.
* Check permission for an ioctl operation on @file.  Note that @arg
* sometimes represents a user space pointer; in other cases, it may be a
* simple integer value.  When @arg represents a user space pointer, it
* should never be used by the security module.
* Return 0 if permission is granted.
*/
static int provenance_file_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
  prov_msg_t* cprov = current_provenance();
  prov_msg_t* iprov;
  struct inode *inode = file_inode(file);

  if(!inode->i_provenance){ // alloc provenance if none there
    provenance_inode_alloc_security(inode);
  }
  iprov = inode->i_provenance;
  if(cprov->node_info.tracked==NODE_TRACKED || iprov->node_info.tracked==NODE_TRACKED || prov_all){
    record_edge(ED_DATA, iprov, cprov); // both way exchange
    record_edge(ED_DATA, cprov, iprov);
  }

  return 0;
}

static struct security_hook_list provenance_hooks[] = {
  LSM_HOOK_INIT(cred_alloc_blank, provenance_cred_alloc_blank),
  LSM_HOOK_INIT(cred_free, provenance_cred_free),
  LSM_HOOK_INIT(cred_prepare, provenance_cred_prepare),
  LSM_HOOK_INIT(cred_transfer, provenance_cred_transfer),
  LSM_HOOK_INIT(task_fix_setuid, provenance_task_fix_setuid),
  LSM_HOOK_INIT(inode_alloc_security, provenance_inode_alloc_security),
  LSM_HOOK_INIT(inode_free_security, provenance_inode_free_security),
  LSM_HOOK_INIT(inode_permission, provenance_inode_permission),
  LSM_HOOK_INIT(file_permission, provenance_file_permission),
  LSM_HOOK_INIT(mmap_file, provenance_mmap_file),
  LSM_HOOK_INIT(file_ioctl, provenance_file_ioctl),
};

void __init provenance_add_hooks(void){
  provenance_cache = kmem_cache_create("provenance_struct",
					    sizeof(prov_msg_t),
					    0, SLAB_PANIC, NULL);
  cred_init_provenance();
  /* register the provenance security hooks */
  security_add_hooks(provenance_hooks, ARRAY_SIZE(provenance_hooks));
}
