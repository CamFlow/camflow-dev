/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2015-2016 University of Cambridge,
 * Copyright (C) 2016-2017 Harvard University,
 * Copyright (C) 2017-2018 University of Cambridge,
 * Copyright (C) 2018-2020 University of Bristol
 *
 * Author: Thomas Pasquier <thomas.pasquier@bristol.ac.uk>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 */
#ifndef _PROVENANCE_RECORD_H
#define _PROVENANCE_RECORD_H

#include "provenance.h"
#include "provenance_relay.h"
#include "memcpy_ss.h"

/*!
 * @brief This function updates the version of a provenance node.
 *
 * Versioning is used to avoid cycles in a provenance graph.
 * Given a provenance node, unless a certain criteria are met, the node should
 * be versioned to avoid cycles.
 * "old_prov" holds the older version of the node while "prov" is updated to
 * the newer version.
 * "prov" and "old_prov" have the same information except the version number.
 * Once the node with a new version is created, a relation between the old and
 * the new version should be estabilished.
 * The relation is either "RL_VERSION_TASK" or "RL_VERSION" depending on the
 * type of the nodes (note that they should be of the same type).
 * If the nodes are of type AC_TASK, then the relation should be
 * "RL_VERSION_TASK"; otherwise it is "RL_VERSION".
 * The new node is not recorded (therefore "recorded" flag is unset) until we
 * record it in the "__write_relation" function.
 * The new node is not saved for persistance in this function. So we clear the
 * saved bit inherited from the older version node.
 * The criteria that should be met to not to update the version are:
 * 1. If nodes are set to be compressed and do not have outgoing edges, or
 * 2. If the argument "type" is a relation whose destination node's version
 * should not be updated becasue the "type" itself either is a VERSION type or
 * a NAMED type.
 * @param type The type of the relation.
 * @param prov The pointer to the provenance node whose version may need to be
 * updated.
 * @return 0 if no error occurred. Other error codes unknown.
 *
 */
static __always_inline int __update_version(const uint64_t type,
					    prov_entry_t *prov)
{
	union prov_elt old_prov;
	int rc = 0;

	if (!provenance_has_outgoing(prov) && prov_policy.should_compress_node)
		return 0;

	if (filter_update_node(type))
		return 0;

	// Copy the current provenance prov to old_prov.
	__memcpy_ss(&old_prov, sizeof(union prov_elt), prov, sizeof(union prov_elt));

	// Update the version of prov to the newer version.
	node_identifier(prov).version++;
	clear_recorded(prov);

	// Record the version relation between two versions of the same identity.
	if (node_identifier(prov).type == ACT_TASK)
		rc = __write_relation(RL_VERSION_TASK, &old_prov, prov, NULL, 0);
	else
		rc = __write_relation(RL_VERSION, &old_prov, prov, NULL, 0);
	clear_has_outgoing(prov);       // Newer version now has no outgoing edge.
	clear_saved(prov);              // For inode provenance persistance
	return rc;
}

/*!
 * @brief This function records a provenance relation (i.e., edge) between two
 * provenance nodes unless certain criteria are met.
 *
 * Unless edges are to be compressed and certain criteria are met,
 * this function would attempt to update the version of the destination node,
 * and create a relation between the source node and the newer version (if
 * version is updated) of the destination node.
 * Version should be updated every time an information flow occurs,
 * Unless:
 * 1. The relation to be recorded here is to explicitly update a version, or
 * 2. Compression of nodes is used.
 * The criteria to be met so as not to record the relation are:
 * 1. Compression of edges are set. (Multiple edges should be compressed to 1
 * edge.), and
 * 2. The type of the edges being recorded are the same as before (we only
 * compress same edges that occurs consecutively on the two nodes).
 * The relation is recorded by calling the "__write_relation" function.
 * @param type The type of the relation
 * @param from The pointer to the source provenance node
 * @param to The pointer to the destination provenance node
 * @param file Information related to LSM hooks.
 * @param flags Information related to LSM hooks.
 * @return 0 if no error occurred. Other error codes unknown.
 *
 */
static __always_inline int record_relation(const uint64_t type,
					   prov_entry_t *from,
					   prov_entry_t *to,
					   const struct file *file,
					   const uint64_t flags)
{
	int rc = 0;

	BUILD_BUG_ON(!prov_type_is_relation(type));

	if (prov_policy.should_compress_edge) {
		if (node_previous_id(to) == node_identifier(from).id
		    && node_previous_type(to) == type)
			return 0;
		else {
			node_previous_id(to) = node_identifier(from).id;
			node_previous_type(to) = type;
		}
	}

	rc = __update_version(type, to);
	if (rc < 0)
		return rc;
	set_has_outgoing(from); // The source node now has an outgoing edge.
	rc = __write_relation(type, from, to, file, flags);
	return rc;
}

/*!
 * @brief This function record a provenance relation that signifies termination
 * of an activity.
 *
 * Unless certain criteria are met, a termination relation is recorded of an
 * activity.
 * Because of this special relation, we will only update the version of the
 * provenance node that is about to be terminated (i.e., an activity).
 * The criteria that need to be met not to record this relation are:
 * 1. The provenance node itself is not recorded and capture all provenance is
 * not set, or
 * 2. The provenance node should be filtered out (i.e., not recorded).
 * @param type The type of termination relation to be recorded.
 * @param prov The provenance node in question (i.e., about to be terminated).
 * @return 0 if no errors occurred. Other error codes unknown.
 *
 */
static __always_inline int record_terminate(uint64_t type,
					    struct provenance *prov)
{
	union prov_elt old_prov;
	int rc;

	BUILD_BUG_ON(!prov_is_close(type));

	if (!provenance_is_recorded(prov_elt(prov)) && !prov_policy.prov_all)
		return 0;
	if (filter_node(prov_entry(prov)))
		return 0;
	__memcpy_ss(&old_prov, sizeof(union prov_elt),
		    prov_elt(prov), sizeof(union prov_elt));
	node_identifier(prov_elt(prov)).version++;
	clear_recorded(prov_elt(prov));

	rc = __write_relation(type, &old_prov, prov_elt(prov), NULL, 0);
	// Newer version now has no outgoing edge.
	clear_has_outgoing(prov_elt(prov));
	return rc;
}

/*!
 * @brief This function records the name of a provenance node. The name itself
 * is a provenance node so there exists a new relation between the name and the
 * node.
 *
 * Unless the node has already have a name or is not recorded, calling this
 * function will generate a new naming relation between the node and its name.
 * The name node is transient and should not have any further use.
 * Therefore, once we record the name node, we will free the memory allocated
 * for the name provenance node.
 * The name node has type "ENT_PATH", and the name has max length PATH_MAX.
 * Depending on the type of the node in question, the relation between the node
 * and the name node can be:
 * 1. RL_NAMED_PROCESS, if the node in question is ACT_TASK node, or
 * 2. RL_NAMED otherwise.
 * Recording the relation is located in a critical section.
 * No other thread can update the node in question, when its named is being
 * attached.
 * @param node The provenance node to which we create a new name node and a
 * naming relation between them.
 * @param name The name of the provenance node.
 * @return 0 if no error occurred. -ENOMEM if no memory can be allocated for
 * long provenance name node.
 *
 */
static __always_inline int record_node_name(struct provenance *node,
					    const char *name,
					    bool force)
{
	union long_prov_elt *fname_prov;
	int rc;

	if (provenance_is_opaque(prov_elt(node)))
		return 0;

	if ((provenance_is_name_recorded(prov_elt(node)) && !force)
	    || !provenance_is_recorded(prov_elt(node)))
		return 0;
	else {
		fname_prov = alloc_long_provenance(ENT_PATH, djb2_hash(name));
		if (!fname_prov)
			return -ENOMEM;

		strlcpy(fname_prov->file_name_info.name, name, PATH_MAX);
		fname_prov->file_name_info.length =
			strnlen(fname_prov->file_name_info.name, PATH_MAX);

		// Here we record the relation.
		spin_lock(prov_lock(node));
		rc = record_relation(RL_NAMED, fname_prov, prov_entry(node), NULL, 0);
		set_name_recorded(prov_elt(node));
		spin_unlock(prov_lock(node));
		free_long_provenance(fname_prov);
		return rc;
	}
}

static __always_inline int record_kernel_link(prov_entry_t *node)
{
	int rc;

	if (provenance_is_kernel_recorded(node) ||
	    !provenance_is_recorded(node))
		return 0;
	else {
		rc = record_relation(RL_RAN_ON, prov_machine, node, NULL, 0);
		set_kernel_recorded(node);
		return rc;
	}
}

static __always_inline int current_update_shst(struct provenance *cprov,
					       bool read);

/*!
 * @brief Record "used" relation from entity provenance node to activity
 * provenance node, including its memory state.
 *
 * This function applies to only "used" relation between two provenance nodes.
 * Unless all nodes involved (entity, activity, activity_mem) are set not to be
 * tracked and prov_all is also turned off,
 * or unless the relation type is set not to be tracked,
 * relation will be captured.
 * At least two relations will possibly be captured:
 * 1. Whatever relation between entity and activity given by the argument
 * "type", and
 * 2. RL_PROC_WRITE relation between activity and activity_mem
 * If activity_mem has memory mapped files, a SH_WRITE relation may be captured
 * (see function definition of "current_update_shst").
 * @param type The type of relation (in the category of "used") between entity
 * and activity.
 * @param entity The entity provenance node.
 * @param activity The activity provenance node.
 * @param activity_mem The memory provenance node of the activity.
 * @param file Information related to LSM hooks.
 * @param flags Information related to LSM hooks.
 * @return 0 if no error occurred. Other error codes unknown.
 *
 */
static __always_inline int uses(const uint64_t type,
				struct provenance *entity,
				struct provenance *activity,
				struct provenance *activity_mem,
				const struct file *file,
				const uint64_t flags)
{
	int rc;

	BUILD_BUG_ON(!prov_is_used(type));

	// Check if the nodes match some capture options.
	apply_target(prov_elt(entity));
	apply_target(prov_elt(activity));
	apply_target(prov_elt(activity_mem));

	if (provenance_is_opaque(prov_elt(entity))
	    || provenance_is_opaque(prov_elt(activity))
	    || provenance_is_opaque(prov_elt(activity_mem)))
		return 0;

	if (!provenance_is_tracked(prov_elt(entity))
	    && !provenance_is_tracked(prov_elt(activity))
	    && !provenance_is_tracked(prov_elt(activity_mem))
	    && !prov_policy.prov_all)
		return 0;
	if (!should_record_relation(type, prov_entry(entity), prov_entry(activity)))
		return 0;

	rc = record_relation(type, prov_entry(entity),
			     prov_entry(activity), file, flags);
	if (rc < 0)
		return rc;
	rc = record_kernel_link(prov_entry(activity));
	if (rc < 0)
		return rc;
	rc = record_relation(RL_PROC_WRITE, prov_entry(activity),
			     prov_entry(activity_mem), NULL, 0);
	if (rc < 0)
		return rc;
	return current_update_shst(activity_mem, false);
}

/*!
 * @brief Record "used" relation from entity provenance node to activity
 * provenance node. This function is a stripped-down version of "uses"
 * function above.
 *
 * This function applies to only "used" relation between two provenance nodes
 * and does almost the same as the above "uses" function.
 * Except that it does not deal with "activity_mem" provenance node.
 * @param type The type of relation (in the category of "used") between entity
 * and activity.
 * @param entity The entity provenance node.
 * @param activity The activity provenance node.
 * @param file Information related to LSM hooks.
 * @param flags Information related to LSM hooks.
 * @return 0 if no error occurred. Other error codes unknown.
 *
 */
static __always_inline int uses_two(const uint64_t type,
				    struct provenance *entity,
				    struct provenance *activity,
				    const struct file *file,
				    const uint64_t flags)
{
	int rc;

	BUILD_BUG_ON(!prov_is_used(type));

	apply_target(prov_elt(entity));
	apply_target(prov_elt(activity));

	if (provenance_is_opaque(prov_elt(entity))
	    || provenance_is_opaque(prov_elt(activity)))
		return 0;

	if (!provenance_is_tracked(prov_elt(entity))
	    && !provenance_is_tracked(prov_elt(activity))
	    && !prov_policy.prov_all)
		return 0;
	if (!should_record_relation(type, prov_entry(entity), prov_entry(activity)))
		return 0;
	rc = record_relation(type, prov_entry(entity),
			     prov_entry(activity), file, flags);
	if (rc < 0)
		return rc;
	return record_kernel_link(prov_entry(activity));
}

/*!
 * @brief Record "generated" relation from activity provenance node (including
 * its memory state) to entity provenance node.
 *
 * This function applies to only "generated" relation between two provenance
 * nodes.
 * Unless all nodes involved (entity, activity, activity_mem) are set not to be
 * tracked and prov_all is also turned off,
 * or unless the relation type is set not to be tracked,
 * relation will be captured.
 * At least two relations will possibly be captured:
 * 1. RL_PROC_READ relation between activity_mem and activity
 * 1. Whatever relation between activity and entity given by the argument
 * "type", and
 * If activity_mem has memory mapped files, a SH_READ relation may be captured
 * (see function definition of "current_update_shst").
 * @param type The type of relation (in the category of "generated") between
 * activity and entity.
 * @param activity_mem The memory provenance node of the activity.
 * @param activity The activity provenance node.
 * @param entity The entity provenance node.
 * @param file Information related to LSM hooks.
 * @param flags Information related to LSM hooks.
 * @return 0 if no error occurred. Other error codes unknown.
 *
 */
static __always_inline int generates(const uint64_t type,
				     struct provenance *activity_mem,
				     struct provenance *activity,
				     struct provenance *entity,
				     const struct file *file,
				     const uint64_t flags)
{
	int rc;

	BUILD_BUG_ON(!prov_is_generated(type));

	apply_target(prov_elt(activity_mem));
	apply_target(prov_elt(activity));
	apply_target(prov_elt(entity));

	if (provenance_is_tracked(prov_elt(activity_mem)))
		set_tracked(prov_elt(activity));

	if (provenance_is_opaque(prov_elt(activity_mem)))
		set_opaque(prov_elt(activity));

	if (provenance_is_opaque(prov_elt(entity))
	    || provenance_is_opaque(prov_elt(activity))
	    || provenance_is_opaque(prov_elt(activity_mem)))
		return 0;

	if (!provenance_is_tracked(prov_elt(activity_mem))
	    && !provenance_is_tracked(prov_elt(activity))
	    && !provenance_is_tracked(prov_elt(entity))
	    && !prov_policy.prov_all)
		return 0;

	if (!should_record_relation(type, prov_entry(activity), prov_entry(entity)))
		return 0;

	rc = current_update_shst(activity_mem, true);
	if (rc < 0)
		return rc;
	rc = record_relation(RL_PROC_READ, prov_entry(activity_mem),
			     prov_entry(activity), NULL, 0);
	if (rc < 0)
		return rc;
	rc = record_kernel_link(prov_entry(activity));
	if (rc < 0)
		return rc;
	rc = record_relation(type, prov_entry(activity),
			     prov_entry(entity), file, flags);
	return rc;
}

/*!
 * @brief Record "derived" relation from one entity provenance node to another
 * entity provenance node.
 *
 * This function applies to only "derived" relation between two entity
 * provenance nodes.
 * Unless both nodes involved (from, to) are set not to be tracked and prov_all
 * is also turned off,
 * or unless the relation type is set not to be tracked,
 * relation will be captured.
 * The relation is whatever relation between one entity to another given by the
 * argument "type".
 * @param type The type of relation (in the category of "derived") between
 * two entities.
 * @param from The entity provenance node.
 * @param to The other entity provenance node.
 * @param file Information related to LSM hooks.
 * @param flags Information related to LSM hooks.
 * @return 0 if no error occurred. Other error codes unknown.
 *
 */
static __always_inline int derives(const uint64_t type,
				   struct provenance *from,
				   struct provenance *to,
				   const struct file *file,
				   const uint64_t flags)
{
	BUILD_BUG_ON(!prov_is_derived(type));

	apply_target(prov_elt(from));
	apply_target(prov_elt(to));

	if (provenance_is_opaque(prov_elt(from))
	    || provenance_is_opaque(prov_elt(to)))
		return 0;

	if (!provenance_is_tracked(prov_elt(from))
	    && !provenance_is_tracked(prov_elt(to))
	    && !prov_policy.prov_all)
		return 0;
	if (!should_record_relation(type, prov_entry(from), prov_entry(to)))
		return 0;

	return record_relation(type, prov_entry(from), prov_entry(to), file, flags);
}

/*!
 * @brief Record "informed" relation from one activity provenance node to
 * another activity provenance node.
 *
 * This function applies to only "informed" relation between two activity
 * provenance nodes.
 * Unless both nodes involved (from, to) are set not to be tracked and prov_all
 * is also turned off,
 * or unless the relation type is set not to be tracked,
 * relation will be captured.
 * The relation is whatever relation between one activity node to another given
 * by the argument "type".
 * @param type The type of relation (in the category of "informed") between
 * two activities.
 * @param from The activity provenance node.
 * @param to The other activity provenance node.
 * @param file Information related to LSM hooks.
 * @param flags Information related to LSM hooks.
 * @return 0 if no error occurred. Other error codes unknown.
 *
 */
static __always_inline int informs(const uint64_t type,
				   struct provenance *from,
				   struct provenance *to,
				   const struct file *file,
				   const uint64_t flags)
{
	int rc;

	BUILD_BUG_ON(!prov_is_informed(type));

	apply_target(prov_elt(from));
	apply_target(prov_elt(to));

	if (provenance_is_opaque(prov_elt(from))
	    || provenance_is_opaque(prov_elt(to)))
		return 0;

	if (!provenance_is_tracked(prov_elt(from))
	    && !provenance_is_tracked(prov_elt(to))
	    && !prov_policy.prov_all)
		return 0;
	if (!should_record_relation(type, prov_entry(from), prov_entry(to)))
		return 0;
	rc = record_kernel_link(prov_entry(from));
	if (rc < 0)
		return rc;
	rc = record_kernel_link(prov_entry(to));
	if (rc < 0)
		return rc;
	return record_relation(type, prov_entry(from), prov_entry(to), file, flags);
}

static __always_inline int record_influences_kernel(const uint64_t type,
						    struct provenance *entity,
						    struct provenance *activity,
						    const struct file *file)
{
	int rc;

	BUILD_BUG_ON(!prov_is_influenced(type));

	apply_target(prov_elt(entity));
	apply_target(prov_elt(activity));

	if (provenance_is_opaque(prov_elt(entity))
	    || provenance_is_opaque(prov_elt(activity)))
		return 0;
	if (!provenance_is_tracked(prov_elt(entity))
	    && !provenance_is_tracked(prov_elt(activity))
	    && !prov_policy.prov_all)
		return 0;
	rc = record_relation(RL_LOAD_FILE, prov_entry(entity),
			     prov_entry(activity), file, 0);
	if (rc < 0)
		goto out;
	rc = record_relation(type, prov_entry(activity), prov_machine, NULL, 0);
out:
	return rc;
}

static __always_inline void record_machine(void)
{
	pr_info("Provenance: recording machine node...");
	__write_node(prov_machine);
}
#endif
