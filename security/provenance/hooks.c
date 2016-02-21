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
  edge.edge_info.snd_dev=from->node_info.dev;
  edge.edge_info.rcv_id=to->node_info.node_id;
  edge.edge_info.rcv_dev=to->node_info.dev;
  edge.edge_info.allowed=FLOW_ALLOWED;
  edge.edge_info.type=type;
  prov_write(&edge);
}

static inline node_id_t prov_next_nodeid( void )
{
  return (node_id_t)atomic64_inc_return(&prov_node_id);
}

static inline prov_msg_t* alloc_provenance(node_id_t nid, node_type_t ntype, gfp_t gfp)
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
  prov->node_info.type=ntype;
  prov->node_info.message_type=MSG_NODE;
  return prov;
}

static inline void free_provenance(prov_msg_t* prov){
  kmem_cache_free(provenance_cache, prov);
}

static inline prov_msg_t* provenance_clone(node_type_t ntype, prov_msg_t* old, gfp_t gfp)
{
  prov_msg_t* prov =   alloc_provenance(0, ntype, gfp);
  if(!prov)
  {
    return NULL;
  }
  /* if parent was tracked, track it */
  prov->node_info.tracked = old->node_info.tracked;
  return prov;
}


/*
 * initialise the security for the init task
 */
static void cred_init_provenance(void)
{
	struct cred *cred = (struct cred *) current->real_cred;
	prov_msg_t *prov;

	prov = alloc_provenance(0, ND_TASK, GFP_KERNEL);
	if (!prov)
		panic("Provenance:  Failed to initialize initial task.\n");
  prov->node_info.uid=__kuid_val(cred->euid);
  prov->node_info.gid=__kgid_val(cred->egid);

	cred->provenance = prov;
}

static int provenance_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{
  prov_msg_t* prov;

  prov = alloc_provenance(0, ND_TASK, gfp);

  if(!prov)
    return -ENOMEM;
  prov->node_info.uid=__kuid_val(cred->euid);
  prov->node_info.gid=__kgid_val(cred->egid);

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
  prov_msg_t* old_prov = old->provenance;
  prov_msg_t* prov = provenance_clone(ND_TASK, old_prov, gfp);

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

/* Indirectly called in keys/process_keys.c:
* Replace a process's session keyring on behalf of one of its children when
* the target  process is about to resume userspace execution.
*/
static void provenance_cred_transfer(struct cred *new, const struct cred *old)
{
  const prov_msg_t *old_prov = old->provenance;
	prov_msg_t *prov = new->provenance;

  *prov=*old_prov;
}

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

/* inode stuff */

static int provenance_inode_alloc_security(struct inode *inode)
{
  prov_msg_t* prov;
  prov = alloc_provenance(inode->i_ino, ND_INODE, GFP_NOFS);
  if(unlikely(!prov))
    return -ENOMEM;
  prov->node_info.uid=__kuid_val(inode->i_uid);
  prov->node_info.gid=__kgid_val(inode->i_gid);
  prov->node_info.dev=inode->i_rdev;

  inode->i_provenance = prov;
  return 0;
}

static void provenance_inode_free_security(struct inode *inode)
{
  prov_msg_t* prov = inode->i_provenance;
  inode->i_provenance=NULL;
  if(!prov)
    free_provenance(prov);
}

/* called on open */
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
  provenance_cache = kmem_cache_create("provenance_struct",
					    sizeof(prov_msg_t),
					    0, SLAB_PANIC, NULL);
  cred_init_provenance();
  /* register the provenance security hooks */
  security_add_hooks(provenance_hooks, ARRAY_SIZE(provenance_hooks));
}
