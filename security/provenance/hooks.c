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

struct cred_provenance_struct{
  node_id_t node_id;
  node_type_t node_type;
  bool tracked;
  bool recorded;
  struct mutex lock;
  uid_t uid;
  gid_t gid;
  dev_t dev;
};

static inline void record_node(struct cred_provenance_struct* prov){
  prov_msg_t msg;

  if(!prov_enabled) // capture is not enabled, ignore
    return;

  prov->recorded=true;
  msg.node_info.message_id=MSG_NODE;
  msg.node_info.node_id=prov->node_id;
  msg.node_info.type=prov->node_type;
  msg.node_info.uid=prov->uid;
  msg.node_info.gid=prov->gid;
  msg.node_info.dev=prov->dev;
  prov_write(&msg);
}

static inline void record_edge(edge_type_t type, struct cred_provenance_struct* from, struct cred_provenance_struct* to){
  prov_msg_t msg;

  if(!prov_enabled) // capture is not enabled, ignore
    return;

  if(!from->recorded)
    record_node(from);

  if(!to->recorded)
    record_node(to);

  msg.edge_info.message_id=MSG_EDGE;
  msg.edge_info.snd_id=from->node_id;
  msg.edge_info.snd_dev=from->dev;
  msg.edge_info.rcv_id=to->node_id;
  msg.edge_info.rcv_dev=to->dev;
  msg.edge_info.allowed=true;
  msg.edge_info.type=type;
  prov_write(&msg);
}

static inline node_id_t prov_next_nodeid( void )
{
  return (node_id_t)atomic64_inc_return(&prov_node_id);
}

static inline struct cred_provenance_struct* alloc_provenance(node_id_t nid, node_type_t ntype, gfp_t gfp)
{
  struct cred_provenance_struct* prov =  kmem_cache_zalloc(provenance_cache, gfp);
  if(!prov){
    return NULL;
  }

  mutex_init(&prov->lock);
  if(nid==0)
  {
    prov->node_id=prov_next_nodeid();
  }else{
    prov->node_id=nid;
  }
  prov->node_type=ntype;
  prov->tracked=false;
  prov->recorded=false;
  prov->uid=0;
  prov->gid=0;
  return prov;
}

static inline void free_provenance(struct cred_provenance_struct* prov){
  kmem_cache_free(provenance_cache, prov);
}

static inline struct cred_provenance_struct* provenance_clone(node_type_t ntype, struct cred_provenance_struct* old, gfp_t gfp)
{
  struct cred_provenance_struct* prov =   alloc_provenance(0, ntype, gfp);
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
	struct cred_provenance_struct *prov;

	prov = alloc_provenance(0, ND_TASK, GFP_KERNEL);
	if (!prov)
		panic("Provenance:  Failed to initialize initial task.\n");
  prov->uid=__kuid_val(cred->euid);
  prov->gid=__kgid_val(cred->egid);

	cred->provenance = prov;
}

static int provenance_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{
  struct cred_provenance_struct* prov;

  prov = alloc_provenance(0, ND_TASK, gfp);

  if(!prov)
    return -ENOMEM;
  prov->uid=__kuid_val(cred->euid);
  prov->gid=__kgid_val(cred->egid);

  cred->provenance = prov;
  return 0;
}

static void provenance_cred_free(struct cred *cred)
{
  free_provenance(cred->provenance);
  cred->provenance = NULL;
}



static int provenance_cred_prepare(struct cred *new, const struct cred *old, gfp_t gfp)
{
  struct cred_provenance_struct* old_prov = old->provenance;
  struct cred_provenance_struct* prov = provenance_clone(ND_TASK, old_prov, gfp);

  if(!prov)
    return -ENOMEM;
  prov->uid=__kuid_val(new->euid);
  prov->gid=__kgid_val(new->egid);

  if(old_prov->tracked || prov_all)
  {
    record_edge(ED_CREATE, old_prov, prov);
  }

  new->provenance = prov;
  return 0;
}

/* Indirectly called in keys/process_keys.c:
* Replace a process's session keyring on behalf of one of its children when
* the target  process is about to resume userspace execution.
*/
static void provenance_cred_transfer(struct cred *new, const struct cred *old)
{
  const struct cred_provenance_struct *old_prov = old->provenance;
	struct cred_provenance_struct *prov = new->provenance;

  *prov=*old_prov;
}

static int provenance_task_fix_setuid(struct cred *new, const struct cred *old, int flags)
{
  struct cred_provenance_struct *old_prov = old->provenance;
	struct cred_provenance_struct *prov = new->provenance;

  if(old_prov->tracked || prov->tracked || prov_all) // record if entity tracked or if record everyting
  {
    record_edge(ED_CHANGE, old_prov, prov);
  }

  return 0;
}

/* inode stuff */

static int provenance_inode_alloc_security(struct inode *inode)
{
  struct cred_provenance_struct* prov;
  prov = alloc_provenance(inode->i_ino, ND_INODE, GFP_NOFS);
  if(unlikely(!prov))
    return -ENOMEM;
  prov->uid=__kuid_val(inode->i_uid);
  prov->gid=__kgid_val(inode->i_gid);
  prov->dev=inode->i_rdev;

  inode->i_provenance = prov;
  return 0;
}

static void provenance_inode_free_security(struct inode *inode)
{
  struct cred_provenance_struct* prov = inode->i_provenance;
  inode->i_provenance=NULL;
  if(!prov)
    free_provenance(prov);
}

/* called on open */
static int provenance_inode_permission(struct inode *inode, int mask)
{
  struct cred_provenance_struct* cprov = current_provenance();
  struct cred_provenance_struct* iprov;

  if(!inode->i_provenance){ // alloc provenance if none there
    provenance_inode_alloc_security(inode);
  }

  iprov = inode->i_provenance;

   mask &= (MAY_READ|MAY_WRITE|MAY_EXEC|MAY_APPEND);

  if((mask & (MAY_WRITE|MAY_APPEND)) != 0){
    if(cprov->tracked || iprov->tracked || prov_all){

      record_edge(ED_DATA, cprov, iprov);
    }
  }
  if((mask & (MAY_READ|MAY_EXEC|MAY_WRITE|MAY_APPEND)) != 0){
    // conservatively assume write imply read
    if(cprov->tracked || iprov->tracked || prov_all){
      record_edge(ED_DATA, iprov, cprov);
    }
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
};

void __init provenance_add_hooks(void){
  provenance_cache = kmem_cache_create("cred_provenance_struct",
					    sizeof(struct cred_provenance_struct),
					    0, SLAB_PANIC, NULL);
  cred_init_provenance();
  /* register the provenance security hooks */
  security_add_hooks(provenance_hooks, ARRAY_SIZE(provenance_hooks));
}
