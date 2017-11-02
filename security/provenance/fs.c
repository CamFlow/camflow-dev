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
#include <crypto/hash.h>

#include "provenance.h"
#include "provenance_inode.h"
#include "provenance_net.h"
#include "provenance_task.h"
#include "provenance_types.h"

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
	provenance_mark_as_opaque(PROV_COMPRESS_FILE);
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
	provenance_mark_as_opaque(PROV_NS_FILTER);
	provenance_mark_as_opaque(PROV_LOG_FILE);
	provenance_mark_as_opaque(PROV_LOGP_FILE);
	provenance_mark_as_opaque(PROV_POLICY_HASH_FILE);
	provenance_mark_as_opaque(PROV_UID_FILTER);
	provenance_mark_as_opaque(PROV_GID_FILTER);
	provenance_mark_as_opaque(PROV_TYPE);
	provenance_mark_as_opaque(PROV_VERSION);
	provenance_mark_as_opaque(PROV_CHANNEL);
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

	page = (char*)get_zeroed_page(GFP_KERNEL);
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

declare_write_flag_fcn(prov_write_enable, prov_policy.prov_enabled);
declare_read_flag_fcn(prov_read_enable, prov_policy.prov_enabled);
declare_file_operations(prov_enable_ops, prov_write_enable, prov_read_enable);

declare_write_flag_fcn(prov_write_all, prov_policy.prov_all);
declare_read_flag_fcn(prov_read_all, prov_policy.prov_all);
declare_file_operations(prov_all_ops, prov_write_all, prov_read_all);

declare_write_flag_fcn(prov_write_compress, prov_policy.should_compress);
declare_read_flag_fcn(prov_read_compress, prov_policy.should_compress);
declare_file_operations(prov_compress_ops, prov_write_compress, prov_read_compress);

static ssize_t prov_write_machine_id(struct file *file, const char __user *buf,
				     size_t count, loff_t *ppos)
{
	uint32_t *tmp = (uint32_t*)buf;

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
	uint32_t *tmp = (uint32_t*)buf;

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
	struct provenance *cprov = get_current_provenance();
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
		__write_node(prov_entry(cprov));
		copy_identifier(&node->disc_node_info.parent, &prov_elt(cprov)->node_info.identifier);
		spin_unlock(prov_lock(cprov));
		node_identifier(node).id = prov_next_node_id();
		node_identifier(node).boot_id = prov_boot_id;
		node_identifier(node).machine_id = prov_machine_id;
		__write_node(node);
	} else{ // the node is not of disclosed type
		count = -EINVAL;
		goto out;
	}

	if (copy_to_user((void*)buf, &node, count)) {
		count = -ENOMEM;
		goto out;
	}

out:
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
	struct provenance *prov = get_current_provenance();

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
	struct provenance *cprov = get_current_provenance();
	union prov_elt *tmp = (union prov_elt*)buf;

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

	setting = (struct prov_filter*)buf;

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
		return __read_filter(filp, buf, count, filter);	\
	}

declare_write_filter_fcn(prov_write_node_filter, prov_policy.prov_node_filter);
declare_reader_filter_fcn(prov_read_node_filter, prov_policy.prov_node_filter);
declare_file_operations(prov_node_filter_ops, prov_write_node_filter, prov_read_node_filter);

declare_write_filter_fcn(prov_write_relation_filter, prov_policy.prov_relation_filter);
declare_reader_filter_fcn(prov_read_relation_filter, prov_policy.prov_relation_filter);
declare_file_operations(prov_relation_filter_ops, prov_write_relation_filter, prov_read_relation_filter);

declare_write_filter_fcn(prov_write_propagate_node_filter, prov_policy.prov_propagate_node_filter);
declare_reader_filter_fcn(prov_read_propagate_node_filter, prov_policy.prov_propagate_node_filter);
declare_file_operations(prov_propagate_node_filter_ops, prov_write_propagate_node_filter, prov_read_propagate_node_filter);

declare_write_filter_fcn(prov_write_propagate_relation_filter, prov_policy.prov_propagate_relation_filter);
declare_reader_filter_fcn(prov_read_propagate_relation_filter, prov_policy.prov_propagate_relation_filter);
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

	msg = (struct prov_process_config*)buf;

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
	if ((f->filter.op & PROV_SET_DELETE) != PROV_SET_DELETE)
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
	data = (struct secinfo*)buf;

	rtn = security_secid_to_secctx(data->secid, &ctx, &len); // read secctx
	if (rtn < 0)
		return rtn;
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

#define declare_generic_filter_write(function_name, filters, info, add_function, delete_function) \
	static ssize_t function_name(struct file *file, const char __user *buf, size_t count, loff_t *ppos) \
	{ \
		struct filters *s; \
		if (count < sizeof(struct info)) \
			return -ENOMEM;	\
		s = kzalloc(sizeof(struct filters), GFP_KERNEL); \
		if (!s)	\
			return -ENOMEM;	\
		if (copy_from_user(&s->filter, buf, sizeof(struct info))) \
			return -EAGAIN;	\
		if ((s->filter.op & PROV_SET_DELETE) != PROV_SET_DELETE) \
			add_function(s); \
		else \
			delete_function(s); \
		return 0; \
	}

#define declare_generic_filter_read(function_name, filters, info) \
	static ssize_t function_name(struct file *filp, char __user *buf, size_t count, loff_t *ppos) \
	{ \
		struct list_head *listentry, *listtmp; \
		struct filters *tmp; \
		size_t pos = 0;	\
		if (count < sizeof(struct info)) \
			return -ENOMEM;	\
		list_for_each_safe(listentry, listtmp, &filters) { \
			tmp = list_entry(listentry, struct filters, list); \
			if (count < pos + sizeof(struct info)) \
				return -ENOMEM;	\
			if (copy_to_user(buf + pos, &(tmp->filter), sizeof(struct info))) \
				return -EAGAIN;	\
			pos += sizeof(struct info); \
		} \
		return pos; \
	}

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
	if ((s->filter.op & PROV_SET_DELETE) != PROV_SET_DELETE)
		prov_secctx_add_or_update(s);
	else
		prov_secctx_delete(s);
	return 0;
}

declare_generic_filter_read(prov_read_secctx_filter, secctx_filters, secinfo);
declare_file_operations(prov_secctx_filter_ops, prov_write_secctx_filter, prov_read_secctx_filter);

declare_generic_filter_write(prov_write_uid_filter, user_filters, userinfo, prov_uid_add_or_update, prov_uid_delete);
declare_generic_filter_read(prov_read_uid_filter, user_filters, userinfo);
declare_file_operations(prov_uid_filter_ops, prov_write_uid_filter, prov_read_uid_filter);

declare_generic_filter_write(prov_write_gid_filter, group_filters, groupinfo, prov_gid_add_or_update, prov_gid_delete);
declare_generic_filter_read(prov_read_gid_filter, group_filters, groupinfo);
declare_file_operations(prov_gid_filter_ops, prov_write_gid_filter, prov_read_gid_filter);

static ssize_t prov_write_ns_filter(struct file *file, const char __user *buf,
				    size_t count, loff_t *ppos)
{
	struct ns_filters *s;

	if (count < sizeof(struct nsinfo))
		return -ENOMEM;

	s = kzalloc(sizeof(struct ns_filters), GFP_KERNEL);
	if (!s)
		return -ENOMEM;

	if (copy_from_user(&s->filter, buf, sizeof(struct nsinfo)))
		return -EAGAIN;
	if ((s->filter.op & PROV_SET_DELETE) != PROV_SET_DELETE)
		prov_ns_add_or_update(s);
	else
		prov_ns_delete(s);
	return 0;
}

static ssize_t prov_read_ns_filter(struct file *filp, char __user *buf,
				   size_t count, loff_t *ppos)
{
	struct list_head *listentry, *listtmp;
	struct ns_filters *tmp;
	size_t pos = 0;

	if (count < sizeof(struct nsinfo))
		return -ENOMEM;

	list_for_each_safe(listentry, listtmp, &ns_filters) {
		tmp = list_entry(listentry, struct ns_filters, list);
		if (count < pos + sizeof(struct nsinfo))
			return -ENOMEM;
		if (copy_to_user(buf + pos, &(tmp->filter), sizeof(struct nsinfo)))
			return -EAGAIN;
		pos += sizeof(struct nsinfo);
	}
	return pos;
}
declare_file_operations(prov_ns_filter_ops, prov_write_ns_filter, prov_read_ns_filter);

static ssize_t prov_write_log(struct file *file, const char __user *buf,
			      size_t count, loff_t *ppos)
{
	struct provenance *cprov = get_current_provenance();

	if (count <= 0 || count >= PATH_MAX)
		return -ENOMEM;
	set_tracked(prov_elt(cprov));
	return record_log(prov_elt(cprov), buf, count);
}
declare_file_operations(prov_log_ops, prov_write_log, no_read);

static ssize_t prov_write_logp(struct file *file, const char __user *buf,
			       size_t count, loff_t *ppos)
{
	struct provenance *cprov = get_current_provenance();

	if (count <= 0 || count >= PATH_MAX)
		return -ENOMEM;
	set_tracked(prov_elt(cprov));
	set_propagate(prov_elt(cprov));
	return record_log(prov_elt(cprov), buf, count);
}
declare_file_operations(prov_logp_ops, prov_write_logp, no_read);

#define hash_filters(filters, filters_type, tmp, tmp_type) \
	list_for_each_safe(listentry, listtmp, &filters) { \
		tmp = list_entry(listentry, struct filters_type, list);	\
		rc = crypto_shash_update(hashdesc, (u8*)&tmp->filter, sizeof(struct tmp_type));	\
		if (rc) { \
			pr_err("Provenance: error updating hash."); \
			pos = -EAGAIN; \
			goto out; \
		} \
	}

static ssize_t prov_read_policy_hash(struct file *filp, char __user *buf,
				     size_t count, loff_t *ppos)
{
	size_t pos = 0;
	size_t size;
	int rc;
	struct crypto_shash *policy_shash_tfm;
	struct shash_desc *hashdesc = NULL;
	uint8_t *buff = NULL;
	struct list_head *listentry, *listtmp;
	struct ipv4_filters *ipv4_tmp;
	struct ns_filters *ns_tmp;
	struct secctx_filters *secctx_tmp;
	struct user_filters *user_tmp;
	struct group_filters *group_tmp;

	policy_shash_tfm = crypto_alloc_shash(PROVENANCE_HASH, 0, 0);
	if (IS_ERR(policy_shash_tfm))
		return -ENOMEM;
	pos = crypto_shash_digestsize(policy_shash_tfm);
	if (count < pos)
		return -ENOMEM;
	buff = kzalloc(pos, GFP_KERNEL);
	if (!buff) {
		pr_err("Provenance: error allocating hash buffer.");
		pos = -ENOMEM;
		goto out;
	}
	size = sizeof(struct shash_desc) + crypto_shash_descsize(policy_shash_tfm);
	hashdesc = kzalloc(size, GFP_KERNEL);
	if (!hashdesc) {
		pr_err("Provenance: error allocating hash desc.");
		pos = -ENOMEM;
		goto out;
	}
	hashdesc->tfm = policy_shash_tfm;
	hashdesc->flags = 0x0;
	rc = crypto_shash_init(hashdesc);
	if (rc) {
		pr_err("Provenance: error initialising hash.");
		pos = -EAGAIN;
		goto out;
	}
	/* LSM version */
	rc = crypto_shash_update(hashdesc, (u8*)CAMFLOW_VERSION_STR, strlen(CAMFLOW_VERSION_STR));
	if (rc) {
		pr_err("Provenance: error updating hash.");
		pos = -EAGAIN;
		goto out;
	}
	/* general policy */
	rc = crypto_shash_update(hashdesc, (u8*)&prov_policy, sizeof(struct capture_policy));
	if (rc) {
		pr_err("Provenance: error updating hash.");
		pos = -EAGAIN;
		goto out;
	}
	/* ingress network policy */
	hash_filters(ingress_ipv4filters, ipv4_filters, ipv4_tmp, prov_ipv4_filter);
	/* egress network policy */
	hash_filters(egress_ipv4filters, ipv4_filters, ipv4_tmp, prov_ipv4_filter);
	/* namespace policy */
	hash_filters(ns_filters, ns_filters, ns_tmp, ns_filters);
	/* secctx policy */
	hash_filters(secctx_filters, secctx_filters, secctx_tmp, secinfo);
	/* userid policy */
	hash_filters(user_filters, user_filters, user_tmp, userinfo);
	/* groupid policy */
	hash_filters(group_filters, group_filters, group_tmp, groupinfo);

	rc = crypto_shash_final(hashdesc, buff);
	if (rc) {
		pr_err("Provenance: error finialising hash.");
		pos = -EAGAIN;
		goto out;
	}
	if (copy_to_user(buf, buff, pos)) {
		pr_err("Provenance: error copying hash to user.");
		pos = -EAGAIN;
		goto out;
	}
out:
	if (!buff)
		kfree(buff);
	if (!hashdesc)
		kfree(hashdesc);
	crypto_free_shash(policy_shash_tfm);
	return pos;
}
declare_file_operations(prov_policy_hash_ops, no_write, prov_read_policy_hash);

static ssize_t prov_read_prov_type(struct file *filp, char __user *buf,
				   size_t count, loff_t *ppos)
{
	struct prov_type type_info;

	if ( count < sizeof(struct prov_type) )
		return -ENOMEM;
	if ( copy_from_user(&type_info, buf, sizeof(struct prov_type)) )
		return -EAGAIN;
	if (type_info.is_relation) {
		if (type_info.id)
			strncpy(type_info.str, relation_str(type_info.id), 256);
		else
			type_info.id = relation_id(type_info.str);
	}else{
		if (type_info.id)
			strncpy(type_info.str, node_str(type_info.id), 256);
		else
			type_info.id = node_id(type_info.str);
	}
	if ( copy_to_user(buf, &type_info, sizeof(struct prov_type)) )
		return -EAGAIN;
	return sizeof(struct prov_type);
}
declare_file_operations(prov_type_ops, no_write, prov_read_prov_type);

static ssize_t prov_read_version(struct file *filp, char __user *buf,
				 size_t count, loff_t *ppos)
{
	size_t len = strlen(CAMFLOW_VERSION_STR);

	if ( count < len )
		return -ENOMEM;
	memset(buf, 0, count);
	if ( copy_to_user(buf, CAMFLOW_VERSION_STR, len) )
		return -EAGAIN;
	return sizeof(struct prov_type);
}
declare_file_operations(prov_version, no_write, prov_read_version);

static ssize_t prov_write_channel(struct file *file, const char __user *buf,
				  size_t count, loff_t *ppos)
{
	char *buffer = kzalloc(count, GFP_KERNEL);

	if (count <= 0 || count > PATH_MAX)
		return -ENOMEM;
	if (strlen(buf) > count) // null terminated?
		return -ENOMEM;
	if (copy_from_user(buffer, buf, count))
		return -ENOMEM;
	return prov_create_channel(buffer, strlen(buffer));
}
declare_file_operations(prov_channel_ops, prov_write_channel, no_read);

#define prov_create_file(name, perm, fun_ptr) \
	securityfs_create_file(name, perm, prov_dir, NULL, fun_ptr)

static int __init init_prov_fs(void)
{
	struct dentry *prov_dir;

	prov_dir = securityfs_create_dir("provenance", NULL);
	prov_create_file("enable", 0644, &prov_enable_ops);
	prov_create_file("all", 0644, &prov_all_ops);
	prov_create_file("compress", 0644, &prov_compress_ops);
	prov_create_file("node", 0666, &prov_node_ops);
	prov_create_file("relation", 0666, &prov_relation_ops);
	prov_create_file("self", 0666, &prov_self_ops);
	prov_create_file("machine_id", 0444, &prov_machine_id_ops);
	prov_create_file("boot_id", 0444, &prov_boot_id_ops);
	prov_create_file("node_filter", 0644, &prov_node_filter_ops);
	prov_create_file("relation_filter", 0644, &prov_relation_filter_ops);
	prov_create_file("propagate_node_filter", 0644,
			 &prov_propagate_node_filter_ops);
	prov_create_file("propagate_relation_filter", 0644,
			 &prov_propagate_relation_filter_ops);
	prov_create_file("flush", 0600, &prov_flush_ops);
	prov_create_file("process", 0644, &prov_process_ops);
	prov_create_file("ipv4_ingress", 0644, &prov_ipv4_ingress_filter_ops);
	prov_create_file("ipv4_egress", 0644, &prov_ipv4_egress_filter_ops);
	prov_create_file("secctx", 0644, &prov_secctx_ops);
	prov_create_file("secctx_filter", 0644, &prov_secctx_filter_ops);
	prov_create_file("ns", 0644, &prov_ns_filter_ops);
	prov_create_file("log", 0666, &prov_log_ops);
	prov_create_file("logp", 0666, &prov_logp_ops);
	prov_create_file("policy_hash", 0444, &prov_policy_hash_ops);
	prov_create_file("uid", 0644, &prov_uid_filter_ops);
	prov_create_file("gid", 0644, &prov_gid_filter_ops);
	prov_create_file("type", 0444, &prov_type_ops);
	prov_create_file("version", 0444, &prov_version);
	prov_create_file("channel", 0644, &prov_channel_ops);
	pr_info("Provenance: fs ready.\n");
	return 0;
}
core_initcall(init_prov_fs);
