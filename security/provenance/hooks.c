/*
*
* Author: Thomas Pasquier <thomas.pasquier@cl.cam.ac.uk>
*
* Copyright (C) 2015 University of Cambridge
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License version 2, as
* published by the Free Software Foundation; either version 2 of the License, or
*	(at your option) any later version.
*
*/
#include <linux/slab.h>
#include <linux/lsm_hooks.h>
#include <linux/msg.h>
#include <net/sock.h>
#include <linux/binfmts.h>
#include <linux/random.h>
#include <linux/xattr.h>
#include <linux/file.h>

#include "av_utils.h"
#include "provenance.h"
#include "provenance_net.h"
#include "provenance_inode.h"
#include "provenance_task.h"
#include "provenance_long.h"

/*
 * initialise the security for the init task
 */
static void cred_init_provenance(void)
{
	struct cred *cred = (struct cred *) current->real_cred;
	prov_msg_t *prov = alloc_provenance(ACT_TASK, GFP_KERNEL);
	if (!prov)
		panic("Provenance:  Failed to initialize initial task.\n");
  set_node_id(prov, ASSIGN_NODE_ID);
  prov->task_info.uid=__kuid_val(cred->euid);
  prov->task_info.gid=__kgid_val(cred->egid);
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
  prov_msg_t* prov  = alloc_provenance(ACT_TASK, gfp);

  if(!prov)
    return -ENOMEM;
  set_node_id(prov, ASSIGN_NODE_ID);

  prov->task_info.uid=__kuid_val(cred->euid);
  prov->task_info.gid=__kgid_val(cred->egid);

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
  prov_msg_t* prov = alloc_provenance(ACT_TASK, gfp);

  if(!prov){
    return -ENOMEM;
  }
  set_node_id(prov, ASSIGN_NODE_ID);
	task_config_from_file(current);
  prov->task_info.uid=__kuid_val(new->euid);
  prov->task_info.gid=__kgid_val(new->egid);

	record_relation(RL_CLONE, old_prov, prov, FLOW_ALLOWED, NULL);
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

  record_relation(RL_CHANGE, old_prov, prov, FLOW_ALLOWED, NULL);
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
  prov_msg_t* iprov = alloc_provenance(ENT_INODE_UNKNOWN, GFP_KERNEL);
  prov_msg_t* sprov;

  if(unlikely(!iprov))
    return -ENOMEM;
  set_node_id(iprov, inode->i_ino);

  iprov->inode_info.uid=__kuid_val(inode->i_uid);
  iprov->inode_info.gid=__kgid_val(inode->i_gid);
  prov_read_inode_type(iprov, inode);
	iprov->inode_info.mode=inode->i_mode;
  sprov = inode->i_sb->s_provenance;
  memcpy(iprov->inode_info.sb_uuid, sprov->sb_info.uuid, 16*sizeof(uint8_t));

	inode->i_provenance = iprov;
  return 0;
}

/*
* @inode contains the inode structure.
* Deallocate the inode security structure and set @inode->i_security to
* NULL.
*/
static void provenance_inode_free_security(struct inode *inode)
{
  free_provenance(inode->i_provenance);
	inode->i_provenance = NULL;
}

/*
* Check permission to create a regular file.
* @dir contains inode structure of the parent of the new file.
* @dentry contains the dentry structure for the file to be created.
* @mode contains the file mode of the file to be created.
* Return 0 if permission is granted.
*/
static int provenance_inode_create(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	prov_msg_t* cprov = current_provenance();
	prov_msg_t* iprov = inode_provenance(dir);
	int rtn=0;

	if(!iprov){
    rtn = -ENOMEM;
		goto out;
  }

	record_relation(RL_WRITE, cprov, iprov, FLOW_ALLOWED, NULL);
out:
	return rtn;
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
  prov_msg_t* iprov = NULL;
	uint32_t perms;
	int rtn=0;

	if(!mask){
		goto out;
	}

	if(unlikely(IS_PRIVATE(inode))){
		goto out;
	}

	iprov = inode->i_provenance;
  if(iprov==NULL){ // alloc provenance if none there
    rtn = -ENOMEM;
		goto out;
  }

	perms = file_mask_to_perms(inode->i_mode, mask);
	if(is_inode_dir(inode)){
		if((perms & (DIR__WRITE)) != 0){
	    record_relation(RL_PERM_WRITE, cprov, iprov, FLOW_ALLOWED, NULL);
	  }
	  if((perms & (DIR__READ)) != 0){
	    record_relation(RL_PERM_READ, iprov, cprov, FLOW_ALLOWED, NULL);
	  }
		if((perms & (DIR__SEARCH)) != 0){
	    record_relation(RL_PERM_EXEC, iprov, cprov, FLOW_ALLOWED, NULL);
	  }
	}else if(is_inode_socket(inode)){
		if((perms & (FILE__WRITE|FILE__APPEND)) != 0){
	    record_relation(RL_PERM_WRITE, cprov, iprov, FLOW_ALLOWED, NULL);
	  }
	  if((perms & (FILE__READ)) != 0){
	    record_relation(RL_PERM_READ, iprov, cprov, FLOW_ALLOWED, NULL);
	  }
	}else{
		if((perms & (FILE__WRITE|FILE__APPEND)) != 0){
	    record_relation(RL_PERM_WRITE, cprov, iprov, FLOW_ALLOWED, NULL);
	  }
	  if((perms & (FILE__READ)) != 0){
	    record_relation(RL_PERM_READ, iprov, cprov, FLOW_ALLOWED, NULL);
	  }
		if((perms & (FILE__EXECUTE)) != 0){
	    record_relation(RL_PERM_EXEC, iprov, cprov, FLOW_ALLOWED, NULL);
	  }
	}

out:
  return 0;
}

/*
* Check permission before creating a new hard link to a file.
* @old_dentry contains the dentry structure for an existing
* link to the file.
* @dir contains the inode structure of the parent directory
* of the new link.
* @new_dentry contains the dentry structure for the new link.
* Return 0 if permission is granted.
*/

static int provenance_inode_link(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry)
{
	prov_msg_t* cprov = current_provenance();
  prov_msg_t* dprov = NULL;
  prov_msg_t* iprov;
	int rtn=0;

	iprov = inode_provenance(d_backing_inode(old_dentry)); // inode pointed by dentry
  if(!iprov){ // alloc provenance if none there
    rtn = -ENOMEM;
		goto out;
  }

	dprov = inode_provenance(dir);
  if(!dprov){ // alloc provenance if none there
    rtn = -ENOMEM;
		goto out;
  }
	// record edges
  record_relation(RL_LINK, cprov, dprov, FLOW_ALLOWED, NULL);
  record_relation(RL_LINK, cprov, iprov, FLOW_ALLOWED, NULL);
  record_relation(RL_LINK, dprov, iprov, FLOW_ALLOWED, NULL);
	record_inode_name_from_dentry(new_dentry, iprov);
out:
  return rtn;
}

/*
* Check for permission to rename a file or directory.
* @old_dir contains the inode structure for parent of the old link.
* @old_dentry contains the dentry structure of the old link.
* @new_dir contains the inode structure for parent of the new link.
* @new_dentry contains the dentry structure of the new link.
* Return 0 if permission is granted.
*/
static int provenance_inode_rename(struct inode *old_dir, struct dentry *old_dentry,
				struct inode *new_dir, struct dentry *new_dentry)
{
	return provenance_inode_link(old_dentry, new_dir, new_dentry);
}

/*
* Check permission before setting file attributes.  Note that the kernel
* call to notify_change is performed from several locations, whenever
* file attributes change (such as when a file is truncated, chown/chmod
* operations, transferring disk quotas, etc).
* @dentry contains the dentry structure for the file.
* @attr is the iattr structure containing the new file attributes.
* Return 0 if permission is granted.
*/
static int provenance_inode_setattr(struct dentry *dentry, struct iattr *iattr)
{
	prov_msg_t* cprov = current_provenance();
  prov_msg_t* iprov;
	prov_msg_t* iattrprov;
	int rtn=0;

	iprov = inode_provenance(d_backing_inode(dentry)); // inode pointed by dentry
  if(!iprov){ // alloc provenance if none there
    rtn = -ENOMEM;
		goto out;
  }
	// alloc and assign id to attribute
	iattrprov = alloc_provenance(ENT_IATTR, GFP_KERNEL);
	set_node_id(iattrprov, ASSIGN_NODE_ID);

	iattrprov->iattr_info.valid = iattr->ia_valid;
	iattrprov->iattr_info.mode = iattr->ia_mode;
	iattrprov->iattr_info.uid = __kuid_val(iattr->ia_uid);
	iattrprov->iattr_info.gid = __kgid_val(iattr->ia_gid);
	iattrprov->iattr_info.size = iattr->ia_size;
	iattrprov->iattr_info.atime = iattr->ia_atime.tv_sec;
	iattrprov->iattr_info.mtime = iattr->ia_mtime.tv_sec;
	iattrprov->iattr_info.ctime = iattr->ia_ctime.tv_sec;

	record_relation(RL_SETATTR, cprov, iattrprov, FLOW_ALLOWED, NULL);
	record_relation(RL_SETATTR, iattrprov, iprov, FLOW_ALLOWED, NULL);
	free_provenance(iattrprov);
out:
  return rtn;
}

/*
* Check permission before obtaining file attributes.
* @path contains the path structure for the file.
* Return 0 if permission is granted.
*/
int provenance_inode_getattr(const struct path *path){
	struct inode *inode = d_backing_inode(path->dentry);
	prov_msg_t* cprov = current_provenance();
  prov_msg_t* iprov;
	int rtn=0;

	iprov = inode_provenance(inode); // inode pointed by dentry
  if(!iprov){ // alloc provenance if none there
    rtn = -ENOMEM;
		goto out;
  }

	record_relation(RL_GETATTR, iprov, cprov, FLOW_ALLOWED, NULL);
out:
  return rtn;
}

/*
* Check the permission to read the symbolic link.
* @dentry contains the dentry structure for the file link.
* Return 0 if permission is granted.
*/
static int provenance_inode_readlink(struct dentry *dentry)
{
	struct inode *inode = d_backing_inode(dentry);
	prov_msg_t* cprov = current_provenance();
	prov_msg_t* iprov;
	int rtn = 0;

	iprov = inode_provenance(inode); // inode pointed by dentry
  if(!iprov){ // alloc provenance if none there
    rtn = -ENOMEM;
		goto out;
  }

	record_relation(RL_READLINK, iprov, cprov, FLOW_ALLOWED, NULL);
out:
  return rtn;
}

/*
* Update inode security field after successful setxattr operation.
* @value identified by @name for @dentry.
*/
static void provenance_inode_post_setxattr(struct dentry *dentry, const char *name,
					const void *value, size_t size, int flags)
{
	struct inode *inode = d_backing_inode(dentry);
	prov_msg_t* cprov = current_provenance();
	prov_msg_t* iprov = inode_provenance(inode); // inode pointed by dentry
  if(!iprov){ // alloc provenance if none there
		goto out;
  }

	// one of the node is opaque
	if(provenance_is_opaque(cprov) || provenance_is_opaque(iprov)){
		goto out;
	}

	// none of the node is tracked
	if(!provenance_is_tracked(cprov) && !provenance_is_tracked(iprov)){
		goto out;
	}

	record_write_xattr(RL_SETXATTR, iprov, cprov, name, value, size, flags, FLOW_ALLOWED);
out:
	return;
}

/*
* Check permission before obtaining the extended attributes
* identified by @name for @dentry.
* Return 0 if permission is granted.
*/
static int provenance_inode_getxattr(struct dentry *dentry, const char *name)
{
	struct inode *inode = d_backing_inode(dentry);
	prov_msg_t* cprov = current_provenance();
	prov_msg_t* iprov;
	int rtn = 0;

	iprov = inode_provenance(inode); // inode pointed by dentry
  if(!iprov){ // alloc provenance if none there
    rtn = -ENOMEM;
		goto out;
  }

	// one of the node is opaque
	if(provenance_is_opaque(cprov) || provenance_is_opaque(iprov)){
		goto out;
	}

	// none of the node is tracked
	if(!provenance_is_tracked(cprov) && !provenance_is_tracked(iprov)){
		goto out;
	}

	record_read_xattr(RL_GETXATTR, cprov, iprov, name, FLOW_ALLOWED);
out:
	return rtn;
}

/*
* Check permission before obtaining the list of extended attribute
* names for @dentry.
* Return 0 if permission is granted.
*/
static int provenance_inode_listxattr(struct dentry *dentry)
{
	struct inode *inode = d_backing_inode(dentry);
	prov_msg_t* cprov = current_provenance();
	prov_msg_t* iprov;
	int rtn = 0;

	iprov = inode_provenance(inode); // inode pointed by dentry
  if(!iprov){ // alloc provenance if none there
    rtn = -ENOMEM;
		goto out;
  }

	record_relation(RL_LSTXATTR, iprov, cprov, FLOW_ALLOWED, NULL);
out:
	return rtn;
}

/*
* Check permission before removing the extended attribute
* identified by @name for @dentry.
* Return 0 if permission is granted.
*/
static int provenance_inode_removexattr(struct dentry *dentry, const char *name)
{
	struct inode *inode = d_backing_inode(dentry);
	prov_msg_t* cprov = current_provenance();
	prov_msg_t* iprov;
	int rtn=0;

	iprov = inode_provenance(inode); // inode pointed by dentry
  if(!iprov){ // alloc provenance if none there
    rtn = -ENOMEM;
		goto out;
  }

	// one of the node is opaque
	if(provenance_is_opaque(cprov) || provenance_is_opaque(iprov)){
		goto out;
	}

	// none of the node is tracked
	if(!provenance_is_tracked(cprov) && !provenance_is_tracked(iprov)){
		goto out;
	}

	record_write_xattr(RL_RMVXATTR, iprov, cprov, name, NULL, 0, 0, FLOW_ALLOWED);
out:
	return rtn;
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
	prov_msg_t* cprov = current_provenance();
  prov_msg_t* iprov;
  struct inode *inode = file_inode(file);
	uint32_t perms;
	int rtn=0;

	iprov = inode_provenance(inode);
	if(iprov==NULL){ // alloc provenance if none there
		rtn = -ENOMEM;
		goto out;
	}

	perms = file_mask_to_perms(inode->i_mode, mask);
	if(is_inode_dir(inode)){
		if((perms & (DIR__WRITE)) != 0){
			record_relation(RL_WRITE, cprov, iprov, FLOW_ALLOWED, file);
		}
		if((perms & (DIR__READ)) != 0){
			record_relation(RL_READ, iprov, cprov, FLOW_ALLOWED, file);
		}
		if((perms & (DIR__SEARCH)) != 0){
			record_relation(RL_SEARCH, iprov, cprov, FLOW_ALLOWED, file);
		}
	}else if(is_inode_socket(inode)){
		if((perms & (FILE__WRITE|FILE__APPEND)) != 0){
			record_relation(RL_SND, cprov, iprov, FLOW_ALLOWED, file);
		}
		if((perms & (FILE__READ)) != 0){
			record_relation(RL_RCV, iprov, cprov, FLOW_ALLOWED, file);
		}
	}else{
		if((perms & (FILE__WRITE|FILE__APPEND)) != 0){
			record_relation(RL_WRITE, cprov, iprov, FLOW_ALLOWED, file);
		}
		if((perms & (FILE__READ)) != 0){
			record_relation(RL_READ, iprov, cprov, FLOW_ALLOWED, file);
		}
		if((perms & (FILE__EXECUTE)) != 0){
	    record_relation(RL_EXEC, iprov, cprov, FLOW_ALLOWED, file);
	  }
	}

out:
  return rtn;
}

/*
* Save open-time permission checking state for later use upon
* file_permission, and recheck access if anything has changed
* since inode_permission.
*/
static int provenance_file_open(struct file *file, const struct cred *cred)
{
	prov_msg_t* cprov = current_provenance();
	struct inode *inode = file_inode(file);
	prov_msg_t* iprov = inode_provenance(inode);
	int rtn=0;

	if(!iprov){ // alloc provenance if none there
    rtn = -ENOMEM;
		goto out;
  }
	record_relation(RL_OPEN, iprov, cprov, FLOW_ALLOWED, file);

out:
	return rtn;
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
  prov_msg_t* iprov = NULL;
	prov_msg_t* bprov = NULL;
  struct inode *inode;
	int rtn=0;

  if(unlikely(file==NULL)){
    goto out;
  }
	//provenance_record_file_name(file);

  inode = file_inode(file);
  iprov = inode_provenance(inode);
	if( (flags & (MAP_SHARED) ) !=  0){
	  if((prot & (PROT_WRITE)) != 0){
	    record_relation(RL_MMAP_WRITE, cprov, iprov, FLOW_ALLOWED, file);
	  }
	  if((prot & (PROT_READ)) != 0){
	    record_relation(RL_MMAP_READ, iprov, cprov, FLOW_ALLOWED, file);
	  }

		if((prot & (PROT_EXEC)) != 0){
	    record_relation(RL_MMAP_EXEC, iprov, cprov, FLOW_ALLOWED, file);
	  }
	}else{
		bprov = branch_mmap(iprov, cprov);
		if(bprov==NULL){
			goto out;
		}
		if((prot & (PROT_WRITE)) != 0){
	    record_relation(RL_MMAP_WRITE, cprov, bprov, FLOW_ALLOWED, file);
	  }
	  if((prot & (PROT_READ)) != 0){
	    record_relation(RL_MMAP_READ, bprov, cprov, FLOW_ALLOWED, file);
	  }

		if((prot & (PROT_EXEC)) != 0){
	    record_relation(RL_MMAP_EXEC, bprov, cprov, FLOW_ALLOWED, file);
	  }
		free_provenance(bprov);
	}

out:
  return rtn;
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
	int rtn=0;

	iprov = inode_provenance(inode);
  if(!iprov){
    rtn = -ENOMEM;
		goto out;
  }

	// both way exchange
  record_relation(RL_WRITE, cprov, iprov, FLOW_ALLOWED, NULL);
  record_relation(RL_READ, iprov, cprov, FLOW_ALLOWED, NULL);

out:
  return rtn;
}

/* msg */

/*
* Allocate and attach a security structure to the msg->security field.
* The security field is initialized to NULL when the structure is first
* created.
* @msg contains the message structure to be modified.
* Return 0 if operation was successful and permission is granted.
*/
static int provenance_msg_msg_alloc_security(struct msg_msg *msg)
{
  prov_msg_t* cprov = current_provenance();
  prov_msg_t* mprov;
	int rtn=0;

  /* alloc new prov struct with generated id */
  mprov = alloc_provenance(ENT_MSG, GFP_KERNEL);

  if(!mprov){
    rtn = -ENOMEM;
		goto out;
	}

  set_node_id(mprov, ASSIGN_NODE_ID);
  mprov->msg_msg_info.type=msg->m_type;
  msg->provenance = mprov;
  record_relation(RL_CREATE, cprov, mprov, FLOW_ALLOWED, NULL);
out:
  return rtn;
}

/*
* Deallocate the security structure for this message.
* @msg contains the message structure to be modified.
*/
static void provenance_msg_msg_free_security(struct msg_msg *msg)
{
	prov_msg_t *prov = msg->provenance;
  msg->provenance=NULL;
  free_provenance(prov);
}

/*
* Check permission before a message, @msg, is enqueued on the message
* queue, @msq.
* @msq contains the message queue to send message to.
* @msg contains the message to be enqueued.
* @msqflg contains operational flags.
* Return 0 if permission is granted.
*/
static int provenance_msg_queue_msgsnd(struct msg_queue *msq, struct msg_msg *msg, int msqflg)
{
  prov_msg_t* cprov = current_provenance();
  prov_msg_t* mprov = msg->provenance;

  record_relation(RL_CREATE, cprov, mprov, FLOW_ALLOWED, NULL);
  return 0;
}

/*
* Check permission before a message, @msg, is removed from the message
* queue, @msq.  The @target task structure contains a pointer to the
* process that will be receiving the message (not equal to the current
* process when inline receives are being performed).
* @msq contains the message queue to retrieve message from.
* @msg contains the message destination.
* @target contains the task structure for recipient process.
* @type contains the type of message requested.
* @mode contains the operational flags.
* Return 0 if permission is granted.
*/
static int provenance_msg_queue_msgrcv(struct msg_queue *msq, struct msg_msg *msg,
				    struct task_struct *target,
				    long type, int mode)
{
  prov_msg_t* cprov = target->cred->provenance;
  prov_msg_t* mprov = msg->provenance;

  record_relation(RL_READ, mprov, cprov, FLOW_ALLOWED, NULL);
  return 0;
}

/*
* Allocate and attach a security structure to the shp->shm_perm.security
* field.  The security field is initialized to NULL when the structure is
* first created.
* @shp contains the shared memory structure to be modified.
* Return 0 if operation was successful and permission is granted.
*/
static int provenance_shm_alloc_security(struct shmid_kernel *shp)
{
	prov_msg_t* cprov = current_provenance();
  prov_msg_t* sprov = alloc_provenance(ENT_SHM, GFP_KERNEL);
	int rtn=0;

  if(!sprov){
    rtn = -ENOMEM;
		goto out;
	}

  set_node_id(sprov, ASSIGN_NODE_ID);
  sprov->shm_info.mode=shp->shm_perm.mode;
  shp->shm_perm.provenance=sprov;
  record_relation(RL_WRITE, sprov, cprov, FLOW_ALLOWED, NULL);
  record_relation(RL_READ, cprov, sprov, FLOW_ALLOWED, NULL);
out:
	return rtn;
}

/*
* Deallocate the security struct for this memory segment.
* @shp contains the shared memory structure to be modified.
*/
static void provenance_shm_free_security(struct shmid_kernel *shp)
{
  free_provenance(shp->shm_perm.provenance);
  shp->shm_perm.provenance=NULL;
}

/*
* Check permissions prior to allowing the shmat system call to attach the
* shared memory segment @shp to the data segment of the calling process.
* The attaching address is specified by @shmaddr.
* @shp contains the shared memory structure to be modified.
* @shmaddr contains the address to attach memory region to.
* @shmflg contains the operational flags.
* Return 0 if permission is granted.
*/
static int provenance_shm_shmat(struct shmid_kernel *shp,
			     char __user *shmaddr, int shmflg)
{
  prov_msg_t* cprov = current_provenance();
	prov_msg_t* sprov = shp->shm_perm.provenance;
	int rtn=0;

  if(!sprov){
    rtn = -ENOMEM;
		goto out;
	}

  if(shmflg & SHM_RDONLY){
    record_relation(RL_READ, sprov, cprov, FLOW_ALLOWED, NULL);
  }else{
    record_relation(RL_READ, sprov, cprov, FLOW_ALLOWED, NULL);
    record_relation(RL_WRITE, cprov, sprov, FLOW_ALLOWED, NULL);
  }

out:
	return rtn;
}

/*
* Allocate and attach a security structure to the sk->sk_security field,
* which is used to copy security attributes between local stream sockets.
*/
static int provenance_sk_alloc_security(struct sock *sk, int family, gfp_t priority)
{
  prov_msg_t* skprov = current_provenance();
	int rtn=0;

  if(!skprov){
    rtn = -ENOMEM;
		goto out;
	}

  sk->sk_provenance=skprov;

out:
  return 0;
}

/*
* This hook allows a module to update or allocate a per-socket security
* structure. Note that the security field was not added directly to the
* socket structure, but rather, the socket security information is stored
* in the associated inode.  Typically, the inode alloc_security hook will
* allocate and and attach security information to
* sock->inode->i_security.  This hook may be used to update the
* sock->inode->i_security field with additional information that wasn't
* available when the inode was allocated.
* @sock contains the newly created socket structure.
* @family contains the requested protocol family.
* @type contains the requested communications type.
* @protocol contains the requested protocol.
* @kern set to 1 if a kernel socket.
*/
static int provenance_socket_post_create(struct socket *sock, int family,
				      int type, int protocol, int kern)
{
  prov_msg_t* cprov  = current_provenance();
  prov_msg_t* iprov = socket_inode_provenance(sock);

  if(kern){
    goto out;
  }
  record_relation(RL_CREATE, cprov, iprov, FLOW_ALLOWED, NULL);

out:
  return 0;
}

/*
* Check permission before socket protocol layer bind operation is
* performed and the socket @sock is bound to the address specified in the
* @address parameter.
* @sock contains the socket structure.
* @address contains the address to bind to.
* @addrlen contains the length of address.
* Return 0 if permission is granted.
*/
static int provenance_socket_bind(struct socket *sock, struct sockaddr *address, int addrlen)
{
  prov_msg_t* cprov  = current_provenance();
  prov_msg_t* iprov = socket_inode_provenance(sock);
	struct sockaddr_in* ipv4_addr;
	uint8_t op;
	int rtn = 0;

  if(!iprov){
    rtn = -ENOMEM;
		goto out;
	}

  if(provenance_is_opaque(cprov)){
    goto out;
	}

	/* should we start tracking this socket */
	if(address->sa_family==AF_INET){
		ipv4_addr = (struct sockaddr_in*)address;
		op = prov_ipv4_ingressOP(ipv4_addr->sin_addr.s_addr, ipv4_addr->sin_port);
		if( (op & PROV_NET_TRACKED)!=0 ){
			set_tracked(iprov);
			set_tracked(cprov);
		}
		if( (op & PROV_NET_PROPAGATE)!=0 ){
			set_propagate(iprov);
			set_propagate(cprov);
		}
	}

	provenance_record_address(iprov, address, addrlen);
	record_relation(RL_BIND, cprov, iprov, FLOW_ALLOWED, NULL);
out:
  return rtn;
}

/*
* Check permission before socket protocol layer connect operation
* attempts to connect socket @sock to a remote address, @address.
* @sock contains the socket structure.
* @address contains the address of remote endpoint.
* @addrlen contains the length of address.
* Return 0 if permission is granted.
*/
static int provenance_socket_connect(struct socket *sock, struct sockaddr *address, int addrlen)
{
  prov_msg_t* cprov  = current_provenance();
  prov_msg_t* iprov = socket_inode_provenance(sock);
	struct sockaddr_in* ipv4_addr;
	uint8_t op;
	int rtn=0;

	if(!iprov){
    rtn = -ENOMEM;
		goto out;
	}

  if(provenance_is_opaque(cprov)){
    goto out;
	}

	/* should we start tracking this socket */
	if(address->sa_family==AF_INET){
		ipv4_addr = (struct sockaddr_in*)address;
		op = prov_ipv4_egressOP(ipv4_addr->sin_addr.s_addr, ipv4_addr->sin_port);
		if( (op & PROV_NET_TRACKED)!=0 ){
			set_tracked(iprov);
			set_tracked(cprov);
		}
		if( (op & PROV_NET_PROPAGATE)!=0 ){
			set_propagate(iprov);
			set_propagate(cprov);
		}
	}


	provenance_record_address(iprov, address, addrlen);
	record_relation(RL_CONNECT, cprov, iprov, FLOW_ALLOWED, NULL);
out:
  return 0;
}

/*
* Check permission before socket protocol layer listen operation.
* @sock contains the socket structure.
* @backlog contains the maximum length for the pending connection queue.
* Return 0 if permission is granted.
*/
static int provenance_socket_listen(struct socket *sock, int backlog)
{
  prov_msg_t* cprov  = current_provenance();
  prov_msg_t* iprov = socket_inode_provenance(sock);
	int rtn=0;

	if(!iprov){
    rtn = -ENOMEM;
		goto out;
	}

  record_relation(RL_LISTEN, cprov, iprov, FLOW_ALLOWED, NULL);
out:
  return 0;
}

/*
* Check permission before accepting a new connection.  Note that the new
* socket, @newsock, has been created and some information copied to it,
* but the accept operation has not actually been performed.
* @sock contains the listening socket structure.
* @newsock contains the newly created server socket for connection.
* Return 0 if permission is granted.
*/
static int provenance_socket_accept(struct socket *sock, struct socket *newsock)
{
  prov_msg_t* cprov  = current_provenance();
  prov_msg_t* iprov = socket_inode_provenance(sock);
  prov_msg_t* niprov = socket_inode_provenance(newsock);

  record_relation(RL_CREATE, iprov, niprov, FLOW_ALLOWED, NULL);
  record_relation(RL_ACCEPT, niprov, cprov, FLOW_ALLOWED, NULL);

  return 0;
}

/*
* Check permission before transmitting a message to another socket.
* @sock contains the socket structure.
* @msg contains the message to be transmitted.
* @size contains the size of message.
* Return 0 if permission is granted.
*/
static int provenance_socket_sendmsg(struct socket *sock, struct msghdr *msg,
				  int size)
{
	prov_msg_t* cprov = current_provenance();
	prov_msg_t* iprov = socket_inode_provenance(sock);
	int rtn=0;

	if(iprov==NULL){
		rtn = -ENOMEM;
		goto out;
	}

	record_relation(RL_SND, cprov, iprov, FLOW_ALLOWED, NULL);
out:
	return rtn;
}

/*
* Check permission before receiving a message from a socket.
* @sock contains the socket structure.
* @msg contains the message structure.
* @size contains the size of message structure.
* @flags contains the operational flags.
* Return 0 if permission is granted.
*/
static int provenance_socket_recvmsg(struct socket *sock, struct msghdr *msg,
				  int size, int flags)
{
	prov_msg_t* cprov = current_provenance();
	prov_msg_t* iprov = socket_inode_provenance(sock);
	int rtn=0;

	if(iprov==NULL){
		rtn = -ENOMEM;
		goto out;
	}

	record_relation(RL_RCV, iprov, cprov, FLOW_ALLOWED, NULL);
out:
	return rtn;
}

/*
* Check permissions on incoming network packets.  This hook is distinct
* from Netfilter's IP input hooks since it is the first time that the
* incoming sk_buff @skb has been associated with a particular socket, @sk.
* Must not sleep inside this hook because some callers hold spinlocks.
* @sk contains the sock (not socket) associated with the incoming sk_buff.
* @skb contains the incoming network data.
*/
static int provenance_socket_sock_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
	prov_msg_t* cprov = sk_provenance(sk);
	prov_msg_t* iprov;
  prov_msg_t pckprov;
	uint16_t family = sk->sk_family;
	int rtn=0;

	if(cprov==NULL){
		goto out;
	}

	if(family!=PF_INET){ // we only handle IPv4 for now
		goto out;
	}

	iprov = sk_inode_provenance(sk);
	if(iprov==NULL){ // we could not get the provenance, we give up
		goto out;
	}
	if(provenance_is_tracked(iprov)){
    provenance_parse_skb_ipv4(skb, &pckprov);
    record_pck_to_inode(&pckprov, iprov);
		if(provenance_is_tracked(cprov)){
			record_relation(RL_RCV, iprov, cprov, FLOW_ALLOWED, NULL);
		}
  }
out:
	return rtn;
}

/*
* Check permissions before establishing a Unix domain stream connection
* between @sock and @other.
* @sock contains the sock structure.
* @other contains the peer sock structure.
* @newsk contains the new sock structure.
* Return 0 if permission is granted.
*/
static int provenance_unix_stream_connect(struct sock *sock,
					      struct sock *other,
					      struct sock *newsk)
{
  /*prov_msg_t* cprov  = current_provenance();
  prov_msg_t* skprov = sk_provenance(sock);
  prov_msg_t* nskprov = sk_provenance(newsk);
  prov_msg_t* okprov = sk_provenance(other);

  record_relation(RL_CONNECT, cprov, skprov, FLOW_ALLOWED);
  record_relation(RL_ASSOCIATE, skprov, nskprov, FLOW_ALLOWED);
  record_relation(RL_ASSOCIATE, skprov, okprov, FLOW_ALLOWED);*/
  return 0;
}

/*
* Check permissions before connecting or sending datagrams from @sock to
* @other.
* @sock contains the socket structure.
* @other contains the peer socket structure.
* Return 0 if permission is granted.
*/
static int provenance_unix_may_send(struct socket *sock,
					struct socket *other)
{
  /*prov_msg_t* skprov = socket_inode_provenance(sock);
  prov_msg_t* okprov = socket_inode_provenance(other);

  record_relation(RL_UNKNOWN, skprov, okprov, FLOW_ALLOWED);*/
  return 0;
}

/* outdated description */
/*
* Save security information in the bprm->security field, typically based
* on information about the bprm->file, for later use by the apply_creds
* hook.  This hook may also optionally check permissions (e.g. for
* transitions between security domains).
* This hook may be called multiple times during a single execve, e.g. for
* interpreters.  The hook can tell whether it has already been called by
* checking to see if @bprm->security is non-NULL.  If so, then the hook
* may decide either to retain the security information saved earlier or
* to replace it.
* @bprm contains the linux_binprm structure.
* Return 0 if the hook is successful and permission is granted.
*/
static int provenance_bprm_set_creds(struct linux_binprm *bprm){
	prov_msg_t* nprov = bprm_provenance(bprm);
	struct inode *inode = file_inode(bprm->file);
	prov_msg_t* iprov = inode_provenance(inode);
	int rtn=0;

  if(!nprov){
		rtn = -ENOMEM;
		goto out;
  }

	if(provenance_is_opaque(iprov)){
		set_opaque(nprov);
		goto out;
	}

	record_relation(RL_EXEC, iprov, nprov, FLOW_ALLOWED, NULL);

out:
  return rtn;
}

/*
* Prepare to install the new security attributes of a process being
* transformed by an execve operation, based on the old credentials
* pointed to by @current->cred and the information set in @bprm->cred by
* the bprm_set_creds hook.  @bprm points to the linux_binprm structure.
* This hook is a good place to perform state changes on the process such
* as closing open file descriptors to which access will no longer be
* granted when the attributes are changed.  This is called immediately
* before commit_creds().
*/
 static void provenance_bprm_committing_creds(struct linux_binprm *bprm){
	prov_msg_t* cprov  = current_provenance();
	prov_msg_t* nprov = bprm_provenance(bprm);
	struct inode *inode = file_inode(bprm->file);
	prov_msg_t* iprov = inode_provenance(inode);

	if(provenance_is_opaque(iprov)){
		set_opaque(nprov);
		goto out;
	}

	record_relation(RL_EXEC_PROCESS, cprov, nprov, FLOW_ALLOWED, NULL);
	record_relation(RL_EXEC, iprov, nprov, FLOW_ALLOWED, NULL);

out:
	return;
 }

/*
* Allocate and attach a security structure to the sb->s_security field.
* The s_security field is initialized to NULL when the structure is
* allocated.
* @sb contains the super_block structure to be modified.
* Return 0 if operation was successful.
*/
static int provenance_sb_alloc_security(struct super_block *sb)
{
  prov_msg_t* sbprov  = alloc_provenance(ENT_SBLCK, GFP_KERNEL);
  if(!sbprov)
    return -ENOMEM;
  sb->s_provenance = sbprov;
  return 0;
}

/*
* Deallocate and clear the sb->s_security field.
* @sb contains the super_block structure to be modified.
*/
static void provenance_sb_free_security(struct super_block *sb)
{
  free_provenance(sb->s_provenance);
  sb->s_provenance=NULL;
}

static int provenance_sb_kern_mount(struct super_block *sb, int flags, void *data)
{
  int i;
  uint8_t c=0;
  prov_msg_t* sbprov = sb->s_provenance;
  for(i=0; i<16; i++){
    sbprov->sb_info.uuid[i]=sb->s_uuid[i];
    c|=sb->s_uuid[i];
  }
  if(c==0){ // no uuid defined, generate random one
    get_random_bytes(sbprov->sb_info.uuid, 16*sizeof(uint8_t));
  }
  return 0;
}

static struct security_hook_list provenance_hooks[] = {
	/* task related hooks */
  LSM_HOOK_INIT(cred_alloc_blank, provenance_cred_alloc_blank),
  LSM_HOOK_INIT(cred_free, provenance_cred_free),
  LSM_HOOK_INIT(cred_prepare, provenance_cred_prepare),
  LSM_HOOK_INIT(cred_transfer, provenance_cred_transfer),
  LSM_HOOK_INIT(task_fix_setuid, provenance_task_fix_setuid),

	/* inode related hooks */
  LSM_HOOK_INIT(inode_alloc_security, provenance_inode_alloc_security),
  LSM_HOOK_INIT(inode_create, provenance_inode_create),
  LSM_HOOK_INIT(inode_free_security, provenance_inode_free_security),
  LSM_HOOK_INIT(inode_permission, provenance_inode_permission),
  LSM_HOOK_INIT(inode_link, provenance_inode_link),
  LSM_HOOK_INIT(inode_rename, provenance_inode_rename),
  LSM_HOOK_INIT(inode_setattr, provenance_inode_setattr),
  LSM_HOOK_INIT(inode_getattr, provenance_inode_getattr),
  LSM_HOOK_INIT(inode_readlink, provenance_inode_readlink),
	LSM_HOOK_INIT(inode_post_setxattr, provenance_inode_post_setxattr),
	LSM_HOOK_INIT(inode_getxattr, provenance_inode_getxattr),
	LSM_HOOK_INIT(inode_listxattr, provenance_inode_listxattr),
	LSM_HOOK_INIT(inode_removexattr, provenance_inode_removexattr),

	/* file related hooks */
  LSM_HOOK_INIT(file_permission, provenance_file_permission),
  LSM_HOOK_INIT(mmap_file, provenance_mmap_file),
  LSM_HOOK_INIT(file_ioctl, provenance_file_ioctl),
	LSM_HOOK_INIT(file_open, provenance_file_open),

	/* msg related hooks */
	LSM_HOOK_INIT(msg_msg_alloc_security, provenance_msg_msg_alloc_security),
	LSM_HOOK_INIT(msg_msg_free_security, provenance_msg_msg_free_security),
  LSM_HOOK_INIT(msg_queue_msgsnd, provenance_msg_queue_msgsnd),
  LSM_HOOK_INIT(msg_queue_msgrcv, provenance_msg_queue_msgrcv),

	/* shared memory related hooks */
  LSM_HOOK_INIT(shm_alloc_security, provenance_shm_alloc_security),
  LSM_HOOK_INIT(shm_free_security, provenance_shm_free_security),
  LSM_HOOK_INIT(shm_shmat, provenance_shm_shmat),

	/* socket related hooks */
  LSM_HOOK_INIT(sk_alloc_security, provenance_sk_alloc_security),
  LSM_HOOK_INIT(socket_post_create, provenance_socket_post_create),
  LSM_HOOK_INIT(socket_bind, provenance_socket_bind),
  LSM_HOOK_INIT(socket_connect, provenance_socket_connect),
  LSM_HOOK_INIT(socket_listen, provenance_socket_listen),
  LSM_HOOK_INIT(socket_accept, provenance_socket_accept),
  LSM_HOOK_INIT(socket_sendmsg, provenance_socket_sendmsg),
  LSM_HOOK_INIT(socket_recvmsg, provenance_socket_recvmsg),
  LSM_HOOK_INIT(socket_sock_rcv_skb, provenance_socket_sock_rcv_skb),
  LSM_HOOK_INIT(unix_stream_connect, provenance_unix_stream_connect),
  LSM_HOOK_INIT(unix_may_send, provenance_unix_may_send),

	/* exec related hooks */
  LSM_HOOK_INIT(bprm_set_creds, provenance_bprm_set_creds),
  LSM_HOOK_INIT(bprm_committing_creds, provenance_bprm_committing_creds),

	/* file system related hooks */
  LSM_HOOK_INIT(sb_alloc_security, provenance_sb_alloc_security),
  LSM_HOOK_INIT(sb_free_security, provenance_sb_free_security),
  LSM_HOOK_INIT(sb_kern_mount, provenance_sb_kern_mount)
};

struct kmem_cache *provenance_cache=NULL;

uint32_t prov_machine_id=1; /* TODO get a proper id somehow, for now set from userspace */
uint32_t prov_boot_id=0;

struct prov_boot_buffer*       boot_buffer=NULL;
struct prov_long_boot_buffer*  long_boot_buffer=NULL;

struct ipv4_filters ingress_ipv4filters;
struct ipv4_filters egress_ipv4filters;

void __init provenance_add_hooks(void){
	INIT_LIST_HEAD(&ingress_ipv4filters.list);
	INIT_LIST_HEAD(&egress_ipv4filters.list);

	get_random_bytes(&prov_boot_id, sizeof(uint32_t)); // proper counter instead of random id?
  provenance_cache = kmem_cache_create("provenance_struct",
					    sizeof(prov_msg_t),
					    0, SLAB_PANIC, NULL);
  cred_init_provenance();

	/* init relay buffers, to deal with provenance before FS is ready */
	boot_buffer = (struct prov_boot_buffer*)kzalloc(sizeof(struct prov_boot_buffer), GFP_KERNEL);
	if(unlikely(boot_buffer==NULL)){
		printk(KERN_ERR "Provenance: could not allocate boot_buffer\n");
	}
	long_boot_buffer = (struct prov_long_boot_buffer*)kzalloc(sizeof(struct prov_long_boot_buffer), GFP_KERNEL);
	if(unlikely(long_boot_buffer==NULL)){
		printk(KERN_ERR "Provenance: could not allocate long_boot_buffer\n");
	}

  /* register the provenance security hooks */
  security_add_hooks(provenance_hooks, ARRAY_SIZE(provenance_hooks));

	printk(KERN_INFO "Provenance Camflow %s\n", CAMFLOW_VERSION_STR);
	printk(KERN_INFO "Provenance hooks ready.\n");
}
