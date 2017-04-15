/*
 *
 * Author: Thomas Pasquier <thomas.pasquier@cl.cam.ac.uk>
 *
 * Copyright (C) 2015 University of Cambridge
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 */
#include <linux/security.h>

#include "provenance.h"
#include "provenance_inode.h"
#include "provenance_net.h"
#include "provenance_task.h"

#define TMPBUFLEN       12

#define declare_file_operations(ops_name, write_op, read_op) static const struct file_operations ops_name = { \
		.write		= write_op, \
		.read		= read_op, \
		.llseek		= generic_file_llseek, \
}

static ssize_t no_read(struct file *filp, char __user *buf, size_t count, loff_t *ppos)
{
	return -EPERM; // write only
}

static ssize_t no_write(struct file *file, const char __user *buf,
			size_t count, loff_t *ppos)
{
	return -EPERM; // read only
}

static inline void __init_opaque(void)
{
	provenance_mark_as_opaque(PROV_ENABLE_FILE);
	provenance_mark_as_opaque(PROV_ALL_FILE);
	provenance_mark_as_opaque(PROV_NODE_FILE);
	provenance_mark_as_opaque(PROV_RELATION_FILE);
	provenance_mark_as_opaque(PROV_SELF_FILE);
	provenance_mark_as_opaque(PROV_MACHINE_ID_FILE);
	provenance_mark_as_opaque(PROV_BOOT_ID_FILE);
	provenance_mark_as_opaque(PROV_NODE_FILTER_FILE);
	provenance_mark_as_opaque(PROV_RELATION_FILTER_FILE);
	provenance_mark_as_opaque(PROV_PROPAGATE_NODE_FILTER_FILE);
	provenance_mark_as_opaque(PROV_PROPAGATE_RELATION_FILTER_FILE);
	provenance_mark_as_opaque(PROV_FLUSH_FILE);
	provenance_mark_as_opaque(PROV_PROCESS_FILE);
	provenance_mark_as_opaque(PROV_IPV4_INGRESS_FILE);
	provenance_mark_as_opaque(PROV_IPV4_EGRESS_FILE);
	provenance_mark_as_opaque(PROV_SECCTX);
	provenance_mark_as_opaque(PROV_SECCTX_FILTER);
	provenance_mark_as_opaque(PROV_CGROUP_FILTER);
	provenance_mark_as_opaque(PROV_LOG_FILE);
	provenance_mark_as_opaque(PROV_LOGP_FILE);
}

static inline ssize_t __write_flag(struct file *file, const char __user *buf,
				   size_t count, loff_t *ppos, bool *flag)

{
	char *page = NULL;
	ssize_t length;
	bool new_value;
	uint32_t tmp;

	/* no partial write */
	if (*ppos > 0)
		return -EINVAL;

	if (!capable(CAP_AUDIT_CONTROL))
		return -EPERM;

	page = (char *)get_zeroed_page(GFP_KERNEL);
	if (!page)
		return -ENOMEM;

	length =  -EFAULT;
	if (copy_from_user(page, buf, count))
		goto out;

	length = kstrtouint(page, 2, &tmp);
	if (length)
		goto out;

	new_value = tmp;
	(*flag) = new_value;
	length = count;
out:
	free_page((unsigned long)page);
	return length;
}

static ssize_t __read_flag(struct file *filp, char __user *buf,
			   size_t count, loff_t *ppos, bool flag)
{
	char tmpbuf[TMPBUFLEN];
	ssize_t length;
	int tmp = flag;

	length = scnprintf(tmpbuf, TMPBUFLEN, "%d", tmp);
	return simple_read_from_buffer(buf, count, ppos, tmpbuf, length);
}

#define declare_write_flag_fcn(fcn_name, flag) static ssize_t fcn_name(struct file *file, const char __user *buf, size_t count, loff_t *ppos) \
	{ \
		return __write_flag(file, buf, count, ppos, &flag); \
	}
#define declare_read_flag_fcn(fcn_name, flag) static ssize_t fcn_name(struct file *filp, char __user *buf, size_t count, loff_t *ppos) \
	{ \
		return __read_flag(filp, buf, count, ppos, flag); \
	}

declare_write_flag_fcn(prov_write_enable, prov_enabled);
declare_read_flag_fcn(prov_read_enable, prov_enabled);
declare_file_operations(prov_enable_ops, prov_write_enable, prov_read_enable);

declare_write_flag_fcn(prov_write_all, prov_all);
declare_read_flag_fcn(prov_read_all, prov_all);
declare_file_operations(prov_all_ops, prov_write_all, prov_read_all);

static ssize_t prov_write_machine_id(struct file *file, const char __user *buf,
				     size_t count, loff_t *ppos)
{
	uint32_t *tmp = (uint32_t *)buf;

	// ideally should be decoupled from set machine id
	__init_opaque();

	if (!capable(CAP_AUDIT_CONTROL))
		return -EPERM;

	if (count < sizeof(uint32_t))
		return -ENOMEM;

	if (copy_from_user(&prov_machine_id, tmp, sizeof(uint32_t)))
		return -EAGAIN;

	return count; // read only
}

static ssize_t prov_read_machine_id(struct file *filp, char __user *buf,
				    size_t count, loff_t *ppos)
{
	if (count < sizeof(uint32_t))
		return -ENOMEM;

	if (copy_to_user(buf, &prov_machine_id, sizeof(uint32_t)))
		return -EAGAIN;

	return count;
}
declare_file_operations(prov_machine_id_ops, prov_write_machine_id, prov_read_machine_id);

static ssize_t prov_write_boot_id(struct file *file, const char __user *buf,
				     size_t count, loff_t *ppos)
{
	uint32_t *tmp = (uint32_t *)buf;

	// ideally should be decoupled from set machine id
	__init_opaque();

	if (!capable(CAP_AUDIT_CONTROL))
		return -EPERM;

	if (count < sizeof(uint32_t))
		return -ENOMEM;

	if (copy_from_user(&prov_boot_id, tmp, sizeof(uint32_t)))
		return -EAGAIN;

	return count; // read only
}

static ssize_t prov_read_boot_id(struct file *filp, char __user *buf,
				    size_t count, loff_t *ppos)
{
	if (count < sizeof(uint32_t))
		return -ENOMEM;

	if (copy_to_user(buf, &prov_boot_id, sizeof(uint32_t)))
		return -EAGAIN;

	return count;
}
declare_file_operations(prov_boot_id_ops, prov_write_boot_id, prov_read_boot_id);


static ssize_t prov_write_node(struct file *file, const char __user *buf,
			       size_t count, loff_t *ppos)

{
	struct provenance *cprov = current_provenance();
	union long_prov_elt *node = NULL;

	if (!capable(CAP_AUDIT_WRITE))
		return -EPERM;

	if (count < sizeof(struct disc_node_struct))
		return -ENOMEM;

	node = kzalloc(sizeof(union long_prov_elt), GFP_KERNEL);
	if (!node)
		return -ENOMEM;

	if (copy_from_user(node, buf, sizeof(struct disc_node_struct))) {
		count = -ENOMEM;
		goto out;
	}
	if (prov_type(node) == ENT_DISC || prov_type(node) == ACT_DISC || prov_type(node) == AGT_DISC) {
		spin_lock_nested(prov_lock(cprov), PROVENANCE_LOCK_TASK);
		write_node(prov_elt(cprov));
		copy_identifier(&node->disc_node_info.parent, &prov_elt(cprov)->node_info.identifier);
		spin_unlock(prov_lock(cprov));
		node_identifier(node).id = prov_next_node_id();
		node_identifier(node).boot_id = prov_boot_id;
		node_identifier(node).machine_id = prov_machine_id;
		long_prov_write(node);
	} else{ // the node is not of disclosed type
		count = -EINVAL;
		goto out;
	}

	if (copy_to_user((void *)buf, &node, count)) {
		count = -ENOMEM;
		goto out;
	}

out:
	if (node)
		kfree(node);
	return count;
}
declare_file_operations(prov_node_ops, prov_write_node, no_read);

static ssize_t prov_write_relation(struct file *file, const char __user *buf,
				   size_t count, loff_t *ppos)
{
	union prov_elt relation;

	if (!capable(CAP_AUDIT_WRITE))
		return -EPERM;

	if (count < sizeof(struct relation_struct))
		return -ENOMEM;

	if (copy_from_user(&relation, buf, sizeof(struct relation_struct)))
		return -ENOMEM;

	prov_write(&relation);
	return count;
}
declare_file_operations(prov_relation_ops, prov_write_relation, no_read);

static inline void update_prov_config(union prov_elt *setting, uint8_t op, struct provenance *prov)
{
	spin_lock_nested(prov_lock(prov), PROVENANCE_LOCK_TASK);
	if ((op & PROV_SET_TRACKED) != 0) {
		if (provenance_is_tracked(setting))
			set_tracked(prov_elt(prov));
		else
			clear_tracked(prov_elt(prov));
	}

	if ((op & PROV_SET_OPAQUE) != 0) {
		if (provenance_is_opaque(setting))
			set_opaque(prov_elt(prov));
		else
			clear_opaque(prov_elt(prov));
	}

	if ((op & PROV_SET_PROPAGATE) != 0) {
		if (provenance_does_propagate(setting))
			set_propagate(prov_elt(prov));
		else
			clear_propagate(prov_elt(prov));
	}

	if ((op & PROV_SET_TAINT) != 0)
		prov_bloom_merge(prov_taint(prov_elt(prov)), prov_taint(setting));
	spin_unlock(prov_lock(prov));
}

static ssize_t prov_write_self(struct file *file, const char __user *buf,
			       size_t count, loff_t *ppos)
{
	struct prov_process_config msg;
	struct provenance *prov = current_provenance();

	if (count < sizeof(struct prov_process_config))
		return -EINVAL;

	if (copy_from_user(&msg, buf, sizeof(struct prov_process_config)))
		return -ENOMEM;

	update_prov_config(&(msg.prov), msg.op, prov);
	return sizeof(struct prov_process_config);
}

static ssize_t prov_read_self(struct file *filp, char __user *buf,
			      size_t count, loff_t *ppos)
{
	struct provenance *cprov = current_provenance();
	union prov_elt *tmp = (union prov_elt *)buf;

	if (count < sizeof(struct task_prov_struct))
		return -ENOMEM;

	spin_lock_nested(prov_lock(cprov), PROVENANCE_LOCK_TASK);
	if (copy_to_user(tmp, prov_elt(cprov), sizeof(union prov_elt)))
		count = -EAGAIN;
	spin_unlock(prov_lock(cprov));
	return count; // write only
}
declare_file_operations(prov_self_ops, prov_write_self, prov_read_self);

static inline ssize_t __write_filter(struct file *file, const char __user *buf,
				     size_t count, uint64_t *filter)
{
	struct prov_filter *setting;

	if (!capable(CAP_AUDIT_CONTROL))
		return -EPERM;

	if (count < sizeof(struct prov_filter))
		return -ENOMEM;

	setting = (struct prov_filter *)buf;

	if (setting->add != 0)
		(*filter) |= setting->filter & setting->mask;
	else
		(*filter) &=  ~(setting->filter & setting->mask);

	return count;
}

static inline ssize_t __read_filter(struct file *filp, char __user *buf,
				    size_t count, uint64_t filter)
{
	if (count < sizeof(uint64_t))
		return -ENOMEM;

	if (copy_to_user(buf, &filter, sizeof(uint64_t)))
		return -EAGAIN;

	return count;
}

#define declare_write_filter_fcn(fcn_name, filter) static ssize_t fcn_name(struct file *file, const char __user *buf, size_t count, loff_t *ppos) \
	{ \
		return __write_filter(file, buf, count, &filter); \
	}
#define declare_reader_filter_fcn(fcn_name, filter) static ssize_t fcn_name(struct file *filp, char __user *buf, size_t count, loff_t *ppos) \
	{ \
		return __read_filter(filp, buf, count, filter); \
	}

uint64_t prov_node_filter;
declare_write_filter_fcn(prov_write_node_filter, prov_node_filter);
declare_reader_filter_fcn(prov_read_node_filter, prov_node_filter);
declare_file_operations(prov_node_filter_ops, prov_write_node_filter, prov_read_node_filter);

uint64_t prov_relation_filter;
declare_write_filter_fcn(prov_write_relation_filter, prov_relation_filter);
declare_reader_filter_fcn(prov_read_relation_filter, prov_relation_filter);
declare_file_operations(prov_relation_filter_ops, prov_write_relation_filter, prov_read_relation_filter);

uint64_t prov_propagate_node_filter;
declare_write_filter_fcn(prov_write_propagate_node_filter, prov_propagate_node_filter);
declare_reader_filter_fcn(prov_read_propagate_node_filter, prov_propagate_node_filter);
declare_file_operations(prov_propagate_node_filter_ops, prov_write_propagate_node_filter, prov_read_propagate_node_filter);

uint64_t prov_propagate_relation_filter;
declare_write_filter_fcn(prov_write_propagate_relation_filter, prov_propagate_relation_filter);
declare_reader_filter_fcn(prov_read_propagate_relation_filter, prov_propagate_relation_filter);
declare_file_operations(prov_propagate_relation_filter_ops, prov_write_propagate_relation_filter, prov_read_propagate_relation_filter);

static ssize_t prov_write_flush(struct file *file, const char __user *buf,
				size_t count, loff_t *ppos)

{
	if (!capable(CAP_AUDIT_CONTROL))
		return -EPERM;

	prov_flush();
	return 0;
}
declare_file_operations(prov_flush_ops, prov_write_flush, no_read);

static ssize_t prov_write_process(struct file *file, const char __user *buf,
				  size_t count, loff_t *ppos)
{
	struct prov_process_config msg;
	struct provenance *prov;

	if (!capable(CAP_AUDIT_CONTROL))
		return -EPERM;

	if (count < sizeof(struct prov_process_config))
		return -EINVAL;

	if (copy_from_user(&msg, buf, sizeof(struct prov_process_config)))
		return -ENOMEM;

	prov = prov_from_vpid(msg.vpid);
	if (!prov)
		return -EINVAL;

	update_prov_config(&(msg.prov), msg.op, prov);
	return sizeof(struct prov_process_config);
}

static ssize_t prov_read_process(struct file *filp, char __user *buf,
				 size_t count, loff_t *ppos)
{
	struct prov_process_config *msg;
	struct provenance *prov;
	int rtn = sizeof(struct prov_process_config);

	if (count < sizeof(struct prov_process_config))
		return -EINVAL;

	msg = (struct prov_process_config *)buf;

	prov = prov_from_vpid(msg->vpid);
	if (!prov)
		return -EINVAL;

	spin_lock_nested(prov_lock(prov), PROVENANCE_LOCK_TASK);
	if (copy_to_user(&msg->prov, prov_elt(prov), sizeof(union prov_elt)))
		rtn = -ENOMEM;
	spin_unlock(prov_lock(prov));
	return rtn;
}
declare_file_operations(prov_process_ops, prov_write_process, prov_read_process);

static inline ssize_t __write_ipv4_filter(struct file *file, const char __user *buf,
					  size_t count, struct list_head *filters)
{
	struct ipv4_filters     *f;

	if (!capable(CAP_AUDIT_CONTROL))
		return -EPERM;

	if (count < sizeof(struct prov_ipv4_filter))
		return -ENOMEM;

	f = kzalloc(sizeof(struct ipv4_filters), GFP_KERNEL);
	if (!f)
		return -ENOMEM;

	if (copy_from_user(&f->filter, buf, sizeof(struct prov_ipv4_filter)))
		return -EAGAIN;
	f->filter.ip = f->filter.ip & f->filter.mask;

	// we are not trying to delete something
	if ((f->filter.op & PROV_NET_DELETE) != PROV_NET_DELETE)
		prov_ipv4_add_or_update(filters, f);
	else
		prov_ipv4_delete(filters, f);
	return sizeof(struct prov_ipv4_filter);
}

static inline ssize_t __read_ipv4_filter(struct file *filp, char __user *buf,
					 size_t count, struct list_head *filters)
{
	struct list_head *listentry, *listtmp;
	struct ipv4_filters *tmp;
	size_t pos = 0;

	if (count < sizeof(struct prov_ipv4_filter))
		return -ENOMEM;

	list_for_each_safe(listentry, listtmp, filters) {
		tmp = list_entry(listentry, struct ipv4_filters, list);
		if (count < pos + sizeof(struct prov_ipv4_filter))
			return -ENOMEM;

		if (copy_to_user(buf + pos, &(tmp->filter), sizeof(struct prov_ipv4_filter)))
			return -EAGAIN;

		pos += sizeof(struct prov_ipv4_filter);
	}
	return pos;
}

#define declare_write_ipv4_filter_fcn(fcn_name, filter) static ssize_t fcn_name(struct file *file, const char __user *buf, size_t count, loff_t *ppos) \
	{ \
		return __write_ipv4_filter(file, buf, count, &filter); \
	}
#define declare_reader_ipv4_filter_fcn(fcn_name, filter) static ssize_t fcn_name(struct file *filp, char __user *buf, size_t count, loff_t *ppos) \
	{ \
		return __read_ipv4_filter(filp, buf, count, &filter); \
	}

declare_write_ipv4_filter_fcn(prov_write_ipv4_ingress_filter, ingress_ipv4filters);
declare_reader_ipv4_filter_fcn(prov_read_ipv4_ingress_filter, ingress_ipv4filters);
declare_file_operations(prov_ipv4_ingress_filter_ops, prov_write_ipv4_ingress_filter, prov_read_ipv4_ingress_filter);

declare_write_ipv4_filter_fcn(prov_write_ipv4_egress_filter, egress_ipv4filters);
declare_reader_ipv4_filter_fcn(prov_read_ipv4_egress_filter, egress_ipv4filters);
declare_file_operations(prov_ipv4_egress_filter_ops, prov_write_ipv4_egress_filter, prov_read_ipv4_egress_filter);

static ssize_t prov_read_secctx(struct file *filp, char __user *buf,
				size_t count, loff_t *ppos)
{
	char *ctx = NULL;
	uint32_t len;
	struct secinfo *data;
	int rtn = 0;

	if (count < sizeof(struct secinfo))
		return -ENOMEM;
	data = (struct secinfo *)buf;

	rtn = security_secid_to_secctx(data->secid, &ctx, &len); // read secctx
	if (rtn < 0)
		goto out;
	if (len < PATH_MAX) {
		if (copy_to_user(data->secctx, ctx, len)) {
			rtn = -ENOMEM;
			goto out;
		}
		data->secctx[len] = '\0'; // maybe unecessary
		data->len = len;
	} else
		rtn = -ENOMEM;
out:
	security_release_secctx(ctx, len); // security module dealloc
	return rtn;
}
declare_file_operations(prov_secctx_ops, no_write, prov_read_secctx);

static ssize_t prov_write_secctx_filter(struct file *file, const char __user *buf,
					size_t count, loff_t *ppos)
{
	struct secctx_filters *s;

	if (count < sizeof(struct secinfo))
		return -ENOMEM;

	s = kzalloc(sizeof(struct secctx_filters), GFP_KERNEL);
	if (!s)
		return -ENOMEM;

	if (copy_from_user(&s->filter, buf, sizeof(struct secinfo)))
		return -EAGAIN;

	security_secctx_to_secid(s->filter.secctx, s->filter.len, &s->filter.secid);
	if ((s->filter.op & PROV_SEC_DELETE) != PROV_SEC_DELETE)
		prov_secctx_add_or_update(s);
	else
		prov_secctx_delete(s);
	return 0;
}

static ssize_t prov_read_secctx_filter(struct file *filp, char __user *buf,
				       size_t count, loff_t *ppos)
{
	struct list_head *listentry, *listtmp;
	struct secctx_filters *tmp;
	size_t pos = 0;

	if (count < sizeof(struct secinfo))
		return -ENOMEM;

	list_for_each_safe(listentry, listtmp, &secctx_filters) {
		tmp = list_entry(listentry, struct secctx_filters, list);
		if (count < pos + sizeof(struct secinfo))
			return -ENOMEM;

		if (copy_to_user(buf + pos, &(tmp->filter), sizeof(struct secinfo)))
			return -EAGAIN;
		pos += sizeof(struct secinfo);
	}
	return pos;
}
declare_file_operations(prov_secctx_filter_ops, prov_write_secctx_filter, prov_read_secctx_filter);

static ssize_t prov_write_cgroup_filter(struct file *file, const char __user *buf,
					size_t count, loff_t *ppos)
{
	struct cgroup_filters *s;

	if (count < sizeof(struct cgroupinfo))
		return -ENOMEM;

	s = kzalloc(sizeof(struct cgroup_filters), GFP_KERNEL);
	if (!s)
		return -ENOMEM;

	if (copy_from_user(&s->filter, buf, sizeof(struct cgroupinfo)))
		return -EAGAIN;
	if ((s->filter.op & PROV_CGROUP_DELETE) != PROV_CGROUP_DELETE)
		prov_cgroup_add_or_update(s);
	else
		prov_cgroup_delete(s);
	return 0;
}

static ssize_t prov_read_cgroup_filter(struct file *filp, char __user *buf,
				       size_t count, loff_t *ppos)
{
	struct list_head *listentry, *listtmp;
	struct cgroup_filters *tmp;
	size_t pos = 0;

	if (count < sizeof(struct cgroupinfo))
		return -ENOMEM;

	list_for_each_safe(listentry, listtmp, &cgroup_filters) {
		tmp = list_entry(listentry, struct cgroup_filters, list);
		if (count < pos + sizeof(struct cgroupinfo))
			return -ENOMEM;
		if (copy_to_user(buf + pos, &(tmp->filter), sizeof(struct cgroupinfo)))
			return -EAGAIN;
		pos += sizeof(struct cgroupinfo);
	}
	return pos;
}
declare_file_operations(prov_cgroup_filter_ops, prov_write_cgroup_filter, prov_read_cgroup_filter);

static ssize_t prov_write_log(struct file *file, const char __user *buf,
			      size_t count, loff_t *ppos)
{
	struct provenance *cprov = current_provenance();

	if (count <= 0 || count >= PATH_MAX)
		return 0;
	set_tracked(prov_elt(cprov));
	return record_log(prov_elt(cprov), buf, count);
}
declare_file_operations(prov_log_ops, prov_write_log, no_read);

static ssize_t prov_write_logp(struct file *file, const char __user *buf,
			       size_t count, loff_t *ppos)
{
	struct provenance *cprov = current_provenance();

	if (count <= 0 || count >= PATH_MAX)
		return 0;
	set_tracked(prov_elt(cprov));
	set_propagate(prov_elt(cprov));
	return record_log(prov_elt(cprov), buf, count);
}
declare_file_operations(prov_logp_ops, prov_write_logp, no_read);

static int __init init_prov_fs(void)
{
	struct dentry *prov_dir;

	prov_dir = securityfs_create_dir("provenance", NULL);
	securityfs_create_file("enable", 0644, prov_dir, NULL, &prov_enable_ops);
	securityfs_create_file("all", 0644, prov_dir, NULL, &prov_all_ops);
	securityfs_create_file("node", 0666, prov_dir, NULL, &prov_node_ops);
	securityfs_create_file("relation", 0666, prov_dir, NULL, &prov_relation_ops);
	securityfs_create_file("self", 0666, prov_dir, NULL, &prov_self_ops);
	securityfs_create_file("machine_id", 0444, prov_dir, NULL, &prov_machine_id_ops);
	securityfs_create_file("boot_id", 0444, prov_dir, NULL, &prov_boot_id_ops);
	securityfs_create_file("node_filter", 0644, prov_dir, NULL, &prov_node_filter_ops);
	securityfs_create_file("relation_filter", 0644, prov_dir, NULL, &prov_relation_filter_ops);
	securityfs_create_file("propagate_node_filter", 0644, prov_dir, NULL, &prov_propagate_node_filter_ops);
	securityfs_create_file("propagate_relation_filter", 0644, prov_dir, NULL, &prov_propagate_relation_filter_ops);
	securityfs_create_file("flush", 0600, prov_dir, NULL, &prov_flush_ops);
	securityfs_create_file("process", 0644, prov_dir, NULL, &prov_process_ops);
	securityfs_create_file("ipv4_ingress", 0644, prov_dir, NULL, &prov_ipv4_ingress_filter_ops);
	securityfs_create_file("ipv4_egress", 0644, prov_dir, NULL, &prov_ipv4_egress_filter_ops);
	securityfs_create_file("secctx", 0644, prov_dir, NULL, &prov_secctx_ops);
	securityfs_create_file("secctx_filter", 0644, prov_dir, NULL, &prov_secctx_filter_ops);
	securityfs_create_file("cgroup", 0644, prov_dir, NULL, &prov_cgroup_filter_ops);
	securityfs_create_file("log", 0666, prov_dir, NULL, &prov_log_ops);
	securityfs_create_file("logp", 0666, prov_dir, NULL, &prov_logp_ops);
	pr_info("Provenance: fs ready.\n");
	return 0;
}
core_initcall(init_prov_fs);
