/*
 * Copyright (C) 2015-2019 University of Cambridge, Harvard University, University of Bristol
 *
 * Author: Thomas Pasquier <thomas.pasquier@bristol.ac.uk>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 */

/*!
 * This file creates securityfs for provenance capture.
 * @todo We will document this file if needed in the future.
 *
 */
#include <linux/security.h>
#include <linux/provenance_types.h>
#include <crypto/hash.h>

#include "provenance.h"
#include "provenance_record.h"
#include "provenance_inode.h"
#include "provenance_net.h"
#include "provenance_task.h"
#include "provenance_machine.h"

#define TMPBUFLEN    12

#define declare_file_operations(ops_name, write_op, read_op)    static const struct file_operations ops_name = { \
		.write = write_op,										 \
		.read = read_op,										 \
		.llseek = generic_file_llseek,									 \
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

#define declare_write_flag_fcn(fcn_name, flag)          static ssize_t fcn_name(struct file *file, const char __user *buf, size_t count, loff_t *ppos) \
	{																	       \
		return __write_flag(file, buf, count, ppos, &flag);										       \
	}
#define declare_read_flag_fcn(fcn_name, flag)           static ssize_t fcn_name(struct file *filp, char __user *buf, size_t count, loff_t *ppos) \
	{																	 \
		return __read_flag(filp, buf, count, ppos, flag);										 \
	}

declare_write_flag_fcn(prov_write_enable, prov_policy.prov_enabled);
declare_read_flag_fcn(prov_read_enable, prov_policy.prov_enabled);
declare_file_operations(prov_enable_ops, prov_write_enable, prov_read_enable);

declare_write_flag_fcn(prov_write_all, prov_policy.prov_all);
declare_read_flag_fcn(prov_read_all, prov_policy.prov_all);
declare_file_operations(prov_all_ops, prov_write_all, prov_read_all);

declare_read_flag_fcn(prov_read_written, prov_policy.prov_written);
declare_file_operations(prov_written_ops, no_write, prov_read_written);

declare_write_flag_fcn(prov_write_compress_node, prov_policy.should_compress_node);
declare_read_flag_fcn(prov_read_compress_node, prov_policy.should_compress_node);
declare_file_operations(prov_compress_node_ops, prov_write_compress_node, prov_read_compress_node);

declare_write_flag_fcn(prov_write_compress_edge, prov_policy.should_compress_edge);
declare_read_flag_fcn(prov_read_compress_edge, prov_policy.should_compress_edge);
declare_file_operations(prov_compress_edge_ops, prov_write_compress_edge, prov_read_compress_edge);

declare_write_flag_fcn(prov_write_duplicate, prov_policy.should_duplicate);
declare_read_flag_fcn(prov_read_duplicate, prov_policy.should_duplicate);
declare_file_operations(prov_duplicate_ops, prov_write_duplicate, prov_read_duplicate);

static ssize_t prov_write_machine_id(struct file *file, const char __user *buf,
				     size_t count, loff_t *ppos)
{
	if (prov_machine_id != 0)   // it has already been set
		return -EPERM;

	if (!capable(CAP_AUDIT_CONTROL))
		return -EPERM;

	if (count < sizeof(uint32_t))
		return -ENOMEM;

	if (copy_from_user(&prov_machine_id, buf, sizeof(uint32_t)))
		return -EAGAIN;

	if (prov_machine_id == 0)
		return -EINVAL;

	pr_info("Provenance: machine ID %d\n", prov_machine_id);
	write_boot_buffer();
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
	if (prov_boot_id != 0)   // it has already been set
		return -EPERM;

	if (!capable(CAP_AUDIT_CONTROL))
		return -EPERM;

	if (count < sizeof(uint32_t))
		return -ENOMEM;

	if (copy_from_user(&prov_boot_id, buf, sizeof(uint32_t)))
		return -EAGAIN;

	if (prov_boot_id == 0)
		return -EINVAL;

	pr_info("Provenance: boot ID %d\n", prov_boot_id);
	write_boot_buffer();
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
	union long_prov_elt *node;

	if (!capable(CAP_AUDIT_WRITE))
		return -EPERM;

	if (count < sizeof(struct disc_node_struct))
		return -ENOMEM;

	node = memdup_user(buf, sizeof(struct disc_node_struct));
	if (IS_ERR(node))
		return PTR_ERR(node);

	if (prov_type(node) == ENT_DISC || prov_type(node) == ACT_DISC || prov_type(node) == AGT_DISC) {
		spin_lock(prov_lock(cprov));
		// TODO redo
		__write_node(prov_entry(cprov));
		memcpy(&node->disc_node_info.parent, &prov_elt(cprov)->node_info.identifier, sizeof(union prov_identifier));
		spin_unlock(prov_lock(cprov));
		node_identifier(node).id = prov_next_node_id();
		node_identifier(node).boot_id = prov_boot_id;
		node_identifier(node).machine_id = prov_machine_id;
		__write_node(node);
	} else { // the node is not of disclosed type
		count = -EINVAL;
		goto out;
	}
	if (copy_to_user((void *)buf, &node, count))
		count = -ENOMEM;
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

	prov_write(&relation, sizeof(union prov_elt));
	return count;
}
declare_file_operations(prov_relation_ops, prov_write_relation, no_read);

static inline void update_prov_config(union prov_elt *setting, uint8_t op, struct provenance *prov)
{
	spin_lock(prov_lock(prov));
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

	if (count < sizeof(struct task_prov_struct))
		return -ENOMEM;

	spin_lock(prov_lock(cprov));
	if (copy_to_user(buf, prov_elt(cprov), sizeof(union prov_elt)))
		count = -EAGAIN;
	spin_unlock(prov_lock(cprov));
	return count; // write only
}
declare_file_operations(prov_self_ops, prov_write_self, prov_read_self);

static inline ssize_t __write_filter(struct file *file, const char __user *buf,
				     size_t count, uint64_t *filter)
{
	struct prov_filter setting;

	if (!capable(CAP_AUDIT_CONTROL)) {
		pr_err("Provenance: failing setting filter, !CAP_AUDIT_CONTROL.");
		return -EPERM;
	}

	if (count < sizeof(struct prov_filter)) {
		pr_err("Provenance: failing setting filter, wrong length.");
		return -ENOMEM;
	}

	if (copy_from_user(&setting, buf, sizeof(struct prov_filter))) {
		pr_err("Provenance: failed copying from user.");
		return -ENOMEM;
	}

	if (setting.add != 0)
		(*filter) |= setting.filter & setting.mask;
	else
		(*filter) &=  ~(setting.filter & setting.mask);

	return count;
}

static inline ssize_t __read_filter(struct file *filp, char __user *buf,
				    size_t count, uint64_t filter)
{
	if (count < sizeof(uint64_t)) {
		pr_err("Provenance: failing setting filter, wrong length.");
		return -ENOMEM;
	}

	if (copy_to_user(buf, &filter, sizeof(uint64_t))) {
		pr_err("Provenance: failed copying to user.");
		return -EAGAIN;
	}

	return count;
}

#define declare_write_filter_fcn(fcn_name, filter)      static ssize_t fcn_name(struct file *file, const char __user *buf, size_t count, loff_t *ppos) \
	{																	       \
		return __write_filter(file, buf, count, &filter);										       \
	}
#define declare_reader_filter_fcn(fcn_name, filter)     static ssize_t fcn_name(struct file *filp, char __user *buf, size_t count, loff_t *ppos) \
	{																	 \
		return __read_filter(filp, buf, count, filter);											 \
	}

declare_write_filter_fcn(prov_write_node_filter, prov_policy.prov_node_filter);
declare_reader_filter_fcn(prov_read_node_filter, prov_policy.prov_node_filter);
declare_file_operations(prov_node_filter_ops, prov_write_node_filter, prov_read_node_filter);

declare_write_filter_fcn(prov_write_derived_filter, prov_policy.prov_derived_filter);
declare_reader_filter_fcn(prov_read_derived_filter, prov_policy.prov_derived_filter);
declare_file_operations(prov_derived_filter_ops, prov_write_derived_filter, prov_read_derived_filter);

declare_write_filter_fcn(prov_write_generated_filter, prov_policy.prov_generated_filter);
declare_reader_filter_fcn(prov_read_generated_filter, prov_policy.prov_generated_filter);
declare_file_operations(prov_generated_filter_ops, prov_write_generated_filter, prov_read_generated_filter);

declare_write_filter_fcn(prov_write_used_filter, prov_policy.prov_used_filter);
declare_reader_filter_fcn(prov_read_used_filter, prov_policy.prov_used_filter);
declare_file_operations(prov_used_filter_ops, prov_write_used_filter, prov_read_used_filter);

declare_write_filter_fcn(prov_write_informed_filter, prov_policy.prov_informed_filter);
declare_reader_filter_fcn(prov_read_informed_filter, prov_policy.prov_informed_filter);
declare_file_operations(prov_informed_filter_ops, prov_write_informed_filter, prov_read_informed_filter);

declare_write_filter_fcn(prov_write_propagate_node_filter, prov_policy.prov_propagate_node_filter);
declare_reader_filter_fcn(prov_read_propagate_node_filter, prov_policy.prov_propagate_node_filter);
declare_file_operations(prov_propagate_node_filter_ops, prov_write_propagate_node_filter, prov_read_propagate_node_filter);

declare_write_filter_fcn(prov_write_propagate_derived_filter, prov_policy.prov_propagate_derived_filter);
declare_reader_filter_fcn(prov_read_propagate_derived_filter, prov_policy.prov_propagate_derived_filter);
declare_file_operations(prov_propagate_derived_filter_ops, prov_write_propagate_derived_filter, prov_read_propagate_derived_filter);

declare_write_filter_fcn(prov_write_propagate_generated_filter, prov_policy.prov_propagate_generated_filter);
declare_reader_filter_fcn(prov_read_propagate_generated_filter, prov_policy.prov_propagate_generated_filter);
declare_file_operations(prov_propagate_generated_filter_ops, prov_write_propagate_generated_filter, prov_read_propagate_generated_filter);

declare_write_filter_fcn(prov_write_propagate_used_filter, prov_policy.prov_propagate_used_filter);
declare_reader_filter_fcn(prov_read_propagate_used_filter, prov_policy.prov_propagate_used_filter);
declare_file_operations(prov_propagate_used_filter_ops, prov_write_propagate_used_filter, prov_read_propagate_used_filter);

declare_write_filter_fcn(prov_write_propagate_informed_filter, prov_policy.prov_propagate_informed_filter);
declare_reader_filter_fcn(prov_read_propagate_informed_filter, prov_policy.prov_propagate_informed_filter);
declare_file_operations(prov_propagate_informed_filter_ops, prov_write_propagate_informed_filter, prov_read_propagate_informed_filter);

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

	msg = memdup_user(buf, sizeof(struct prov_process_config));
	if (IS_ERR(msg))
		return PTR_ERR(msg);

	prov = prov_from_vpid(msg->vpid);
	if (!prov) {
		rtn = -EINVAL;
		goto out;
	}

	spin_lock(prov_lock(prov));
	memcpy(&msg->prov, prov_elt(prov), sizeof(union prov_elt));
	spin_unlock(prov_lock(prov));

	if (copy_to_user(buf, msg, sizeof(struct prov_process_config)))
		rtn = -ENOMEM;
out:
	kfree(msg);
	return rtn;
}
declare_file_operations(prov_process_ops, prov_write_process, prov_read_process);

static ssize_t __write_ipv4_filter(struct file *file, const char __user *buf,
				   size_t count, struct list_head *filters)
{
	struct ipv4_filters *f;

	if (!capable(CAP_AUDIT_CONTROL))
		return -EPERM;
	if (count < sizeof(struct prov_ipv4_filter))
		return -ENOMEM;
	f = kzalloc(sizeof(struct ipv4_filters), GFP_KERNEL);
	if (!f)
		return -ENOMEM;
	if (copy_from_user(&(f->filter), buf, sizeof(struct prov_ipv4_filter))) {
		kfree(f);
		return -EAGAIN;
	}
	f->filter.ip = f->filter.ip & f->filter.mask;
	// we are not trying to delete something
	if ((f->filter.op & PROV_SET_DELETE) != PROV_SET_DELETE)
		prov_ipv4_add_or_update(filters, f);
	else
		prov_ipv4_delete(filters, f);
	return sizeof(struct prov_ipv4_filter);
}

static ssize_t __read_ipv4_filter(struct file *filp, char __user *buf,
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

#define declare_write_ipv4_filter_fcn(fcn_name, filter)         static ssize_t fcn_name(struct file *file, const char __user *buf, size_t count, loff_t *ppos) \
	{																		       \
		return __write_ipv4_filter(file, buf, count, &filter);											       \
	}
#define declare_reader_ipv4_filter_fcn(fcn_name, filter)        static ssize_t fcn_name(struct file *filp, char __user *buf, size_t count, loff_t *ppos) \
	{																		 \
		return __read_ipv4_filter(filp, buf, count, &filter);											 \
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

	data = memdup_user(buf, sizeof(struct secinfo));
	if (IS_ERR(data))
		return PTR_ERR(data);
	// in case US does not check returned value
	data->secctx[0] = '\0';
	data->len = 0;

	rtn = security_secid_to_secctx(data->secid, &ctx, &len); // read secctx
	if (rtn < 0)
		goto out;
	if (len >= PATH_MAX) {
		rtn = -ENOMEM;
		goto out;
	}
	memcpy(data->secctx, ctx, len);
	data->len = len;
out:
	security_release_secctx(ctx, len); // security module dealloc
	if (copy_to_user(buf, data, sizeof(struct secinfo)))
		rtn = -EAGAIN;
	kfree(data);
	return rtn;
}
declare_file_operations(prov_secctx_ops, no_write, prov_read_secctx);

#define declare_generic_filter_write(function_name, filters, info, add_function, delete_function)	    \
	static ssize_t function_name(struct file *file, const char __user *buf, size_t count, loff_t *ppos) \
	{												    \
		struct filters *s;									    \
		if (count < sizeof(struct info)) {							    \
			return -ENOMEM; }								    \
		s = kzalloc(sizeof(struct filters), GFP_KERNEL);					    \
		if (!s) {										    \
			return -ENOMEM; }								    \
		if (copy_from_user(&s->filter, buf, sizeof(struct info))) {				    \
			kfree(s);									    \
			return -EAGAIN;									    \
		}											    \
		if ((s->filter.op & PROV_SET_DELETE) != PROV_SET_DELETE) {				    \
			add_function(s); }								    \
		else {											    \
			delete_function(s); }								    \
		return sizeof(struct filters);								    \
	}

#define declare_generic_filter_read(function_name, filters, info)				      \
	static ssize_t function_name(struct file *filp, char __user *buf, size_t count, loff_t *ppos) \
	{											      \
		struct list_head *listentry, *listtmp;						      \
		struct filters *tmp;								      \
		size_t pos = 0;									      \
		if (count < sizeof(struct info)) {						      \
			return -ENOMEM; }							      \
		list_for_each_safe(listentry, listtmp, &filters) {				      \
			tmp = list_entry(listentry, struct filters, list);			      \
			if (count < pos + sizeof(struct info)) {				      \
				return -ENOMEM; }						      \
			if (copy_to_user(buf + pos, &(tmp->filter), sizeof(struct info))) {	      \
				return -EAGAIN; }						      \
			pos += sizeof(struct info);						      \
		}										      \
		return pos;									      \
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

	if (copy_from_user(&s->filter, buf, sizeof(struct secinfo))) {
		kfree(s);
		return -EAGAIN;
	}

	security_secctx_to_secid(s->filter.secctx, s->filter.len, &s->filter.secid);
	if ((s->filter.op & PROV_SET_DELETE) != PROV_SET_DELETE)
		prov_secctx_add_or_update(s);
	else
		prov_secctx_delete(s);
	return sizeof(struct secinfo);
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

	if (copy_from_user(&s->filter, buf, sizeof(struct nsinfo))) {
		kfree(s);
		return -EAGAIN;
	}

	if ((s->filter.op & PROV_SET_DELETE) != PROV_SET_DELETE)
		prov_ns_add_or_update(s);
	else
		prov_ns_delete(s);
	return sizeof(struct nsinfo);
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

/*!
 * @brief This function records a relation between a provenance node and a user supplied data, which is a transient node.
 *
 * This function allows the user to attach an annotation node to a provenance node.
 * The relation between the two nodes is RL_LOG and the node of the user-supplied log is of type ENT_STR.
 * ENT_STR node is transient and should not have further use.
 * Therefore, once we have recorded the node, we will free the memory allocated for it.
 * @param cprov Provenance node to be annotated by the user.
 * @param buf Userspace buffer where user annotation locates.
 * @param count Number of bytes copied from the user buffer.
 * @return Number of bytes copied. -ENOMEM if no memory can be allocated for the transient long provenance node. -EAGAIN if copying from userspace failed. Other error codes unknown.
 *
 */
static inline int record_log(union prov_elt *tprov, const char __user *buf, size_t count)
{
	union long_prov_elt *str;
	int rc = 0;

	str = alloc_long_provenance(ENT_STR);
	if (!str)
		return -ENOMEM;
	if (copy_from_user(str->str_info.str, buf, count)) {
		rc = -EAGAIN;
		goto out;
	}
	str->str_info.str[count] = '\0';        // Make sure the string is null terminated.
	str->str_info.length = count;

	rc = __write_relation(RL_LOG, str, tprov, NULL, 0);
out:
	free_long_provenance(str);
	if (rc < 0)
		return rc;
	return count;
}

static ssize_t prov_write_log(struct file *file, const char __user *buf,
			      size_t count, loff_t *ppos)
{
	struct provenance *tprov = get_task_provenance(false);

	if (count <= 0 || count >= PATH_MAX)
		return -ENOMEM;
	set_tracked(prov_elt(tprov));
	return record_log(prov_elt(tprov), buf, count);
}
declare_file_operations(prov_log_ops, prov_write_log, no_read);

static ssize_t prov_write_logp(struct file *file, const char __user *buf,
			       size_t count, loff_t *ppos)
{
	struct provenance *tprov = get_task_provenance(false);

	if (count <= 0 || count >= PATH_MAX)
		return -ENOMEM;
	set_tracked(prov_elt(tprov));
	set_propagate(prov_elt(tprov));
	return record_log(prov_elt(tprov), buf, count);
}
declare_file_operations(prov_logp_ops, prov_write_logp, no_read);

#define hash_filters(filters, filters_type, tmp, tmp_type)						 \
	do {												 \
		list_for_each_safe(listentry, listtmp, &filters) {					 \
			tmp = list_entry(listentry, struct filters_type, list);				 \
			rc = crypto_shash_update(hashdesc, (u8 *)&tmp->filter, sizeof(struct tmp_type)); \
			if (rc) {									 \
				pr_err("Provenance: error updating hash.");				 \
				pos = -EAGAIN;								 \
				goto out;								 \
			}										 \
		}											 \
	} while (0)

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
		pos = -ENOMEM;
		goto out;
	}
	size = sizeof(struct shash_desc) + crypto_shash_descsize(policy_shash_tfm);
	hashdesc = kzalloc(size, GFP_KERNEL);
	if (!hashdesc) {
		pos = -ENOMEM;
		goto out;
	}
	hashdesc->tfm = policy_shash_tfm;
	hashdesc->flags = 0x0;
	rc = crypto_shash_init(hashdesc);
	if (rc) {
		pos = -EAGAIN;
		goto out;
	}
	/* LSM version */
	rc = crypto_shash_update(hashdesc, (u8 *)CAMFLOW_VERSION_STR, strlen(CAMFLOW_VERSION_STR));
	if (rc) {
		pos = -EAGAIN;
		goto out;
	}
	/* commit */
	rc = crypto_shash_update(hashdesc, (u8 *)CAMFLOW_COMMIT, strlen(CAMFLOW_COMMIT));
	if (rc) {
		pos = -EAGAIN;
		goto out;
	}
	/* general policy */
	rc = crypto_shash_update(hashdesc, (u8 *)&prov_policy, sizeof(struct capture_policy));
	if (rc) {
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
		pos = -EAGAIN;
		goto out;
	}
	if (copy_to_user(buf, buff, pos)) {
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
	struct prov_type *type_info;
	ssize_t rc = sizeof(struct prov_type);

	if (count < sizeof(struct prov_type)) {
		pr_err("Provenance: failed retrieving object id, wrong string length.");
		return -ENOMEM;
	}
	type_info = memdup_user(buf, sizeof(struct prov_type));
	if (IS_ERR(type_info))
		return PTR_ERR(type_info);

	if (type_info->is_relation) {
		if (type_info->id)
			strlcpy(type_info->str, relation_str(type_info->id), PROV_TYPE_STR_MAX_LEN);
		else
			type_info->id = relation_id(type_info->str);
	} else {
		if (type_info->id)
			strlcpy(type_info->str, node_str(type_info->id), PROV_TYPE_STR_MAX_LEN);
		else
			type_info->id = node_id(type_info->str);
	}
	if (copy_to_user(buf, type_info, sizeof(struct prov_type)))
		rc = -EAGAIN;
	kfree(type_info);
	return rc;
}
declare_file_operations(prov_type_ops, no_write, prov_read_prov_type);

static ssize_t prov_read_version(struct file *filp, char __user *buf,
				 size_t count, loff_t *ppos)
{
	size_t len = strnlen(CAMFLOW_VERSION_STR, 32);

	if (count < len)
		return -ENOMEM;
	if (copy_to_user(buf, CAMFLOW_VERSION_STR, len))
		return -EAGAIN;
	return len;
}
declare_file_operations(prov_version, no_write, prov_read_version);

static ssize_t prov_read_commit(struct file *filp, char __user *buf,
				size_t count, loff_t *ppos)
{
	size_t len = strnlen(CAMFLOW_COMMIT, PROV_COMMIT_MAX_LENGTH);

	if (count < len)
		return -ENOMEM;
	if (copy_to_user(buf, CAMFLOW_COMMIT, len))
		return -EAGAIN;
	return len;
}
declare_file_operations(prov_commit, no_write, prov_read_commit);

static ssize_t prov_write_channel(struct file *file, const char __user *buf,
				  size_t count, loff_t *ppos)
{
	char *buffer;
	int rtn = 0;

	if (count <= 0 || count > PATH_MAX)
		return -ENOMEM;

	buffer = memdup_user(buf, count);
	if (IS_ERR(buffer))
		return PTR_ERR(buffer);

	rtn = prov_create_channel(buffer, count);
out:
	kfree(buffer);
	return rtn;
}
declare_file_operations(prov_channel_ops, prov_write_channel, no_read);

static ssize_t prov_write_epoch(struct file *file, const char __user *buf,
				size_t count, loff_t *ppos)
{
	epoch++;
	pr_info("Provenance: epoch changed to %d.", epoch);
	return count;
}
declare_file_operations(prov_epoch_ops, prov_write_epoch, no_read);

#define prov_create_file(name, perm, fun_ptr)					      \
	do {									      \
		dentry = securityfs_create_file(name, perm, prov_dir, NULL, fun_ptr); \
		provenance_mark_as_opaque_dentry(dentry);			      \
	} while (0)

static int __init init_prov_fs(void)
{
	struct dentry *prov_dir;
	struct dentry *dentry;

	prov_dir = securityfs_create_dir("provenance", NULL);
	prov_create_file("enable", 0644, &prov_enable_ops);
	prov_create_file("all", 0644, &prov_all_ops);
	prov_create_file("written", 0444, &prov_written_ops);
	prov_create_file("compress_node", 0644, &prov_compress_node_ops);
	prov_create_file("compress_edge", 0644, &prov_compress_edge_ops);
	prov_create_file("node", 0666, &prov_node_ops);
	prov_create_file("relation", 0666, &prov_relation_ops);
	prov_create_file("self", 0666, &prov_self_ops);
	prov_create_file("machine_id", 0444, &prov_machine_id_ops);
	prov_create_file("boot_id", 0444, &prov_boot_id_ops);
	prov_create_file("node_filter", 0644, &prov_node_filter_ops);
	prov_create_file("derived_filter", 0644, &prov_derived_filter_ops);
	prov_create_file("generated_filter", 0644, &prov_generated_filter_ops);
	prov_create_file("used_filter", 0644, &prov_used_filter_ops);
	prov_create_file("informed_filter", 0644, &prov_informed_filter_ops);
	prov_create_file("propagate_node_filter", 0644,
			 &prov_propagate_node_filter_ops);
	prov_create_file("propagate_derived_filter", 0644, &prov_propagate_derived_filter_ops);
	prov_create_file("propagate_generated_filter", 0644, &prov_propagate_generated_filter_ops);
	prov_create_file("propagate_used_filter", 0644, &prov_propagate_used_filter_ops);
	prov_create_file("propagate_informed_filter", 0644, &prov_propagate_informed_filter_ops);
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
	prov_create_file("commit", 0444, &prov_commit);
	prov_create_file("channel", 0644, &prov_channel_ops);
	prov_create_file("duplicate", 0644, &prov_duplicate_ops);
	prov_create_file("epoch", 0644, &prov_epoch_ops);
	pr_info("Provenance: fs ready.\n");
	return 0;
}
core_initcall(init_prov_fs);
