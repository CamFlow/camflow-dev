/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
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

#ifndef _UAPI_LINUX_PROVENANCE_H
#define _UAPI_LINUX_PROVENANCE_H

#ifdef __KERNEL__
#include <linux/socket.h>
#include <linux/mutex.h>
#endif
#ifndef __KERNEL__
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#endif
#include <linux/limits.h>
#include <linux/utsname.h>
#include <linux/provenance_utils.h>
#include <linux/in6.h>

#define xstr(s)         str(s)
#define str(s)          # s

#define CAMFLOW_VERSION_MAJOR           0
#define CAMFLOW_VERSION_MINOR           6
#define CAMFLOW_VERSION_PATCH           5
#define CAMFLOW_VERSION_STR             "v"xstr (CAMFLOW_VERSION_MAJOR)	\
	"."xstr (CAMFLOW_VERSION_MINOR)					\
	"."xstr (CAMFLOW_VERSION_PATCH)					\

#define CAMFLOW_COMMIT "692bfa2cd42006cd56f77426ab060ea421207085"

#define PROVENANCE_HASH                 "sha256"

#define FLOW_ALLOWED                            0
#define FLOW_DISALLOWED                         1

#define prov_id_buffer(prov)                    ((prov)->node_info.identifier.buffer)
#define node_identifier(node)                   ((node)->node_info.identifier.node_id)
#define relation_identifier(relation)           ((relation)->relation_info.identifier.relation_id)
#define get_prov_identifier(node)               ((node)->node_info.identifier)
#define packet_identifier(packet)               ((packet)->pck_info.identifier.packet_id)
#define ipv6_packet_identifier(packet)          ((packet)->pck_info.identifier.ipv6_packet_id)
#define packet_info(packet)                     ((packet)->pck_info)
#define node_secid(node)                        ((node)->node_info.secid)
#define node_uid(node)                          ((node)->node_info.uid)
#define node_gid(node)                          ((node)->node_info.gid)
#define node_previous_id(node)                  ((node)->node_info.previous_id)
#define node_previous_type(node)                ((node)->node_info.previous_type)
#define node_kernel_version(node)               ((node)->node_info.k_version)

#define prov_flag(prov)                         ((prov)->msg_info.internal_flag)
#define prov_taint(prov)                        ((prov)->msg_info.taint)
#define prov_jiffies(prov)                      ((prov)->msg_info.jiffies)

struct node_identifier {
	uint64_t type;
	uint64_t id;
	uint32_t boot_id;
	uint32_t machine_id;
	uint32_t version;
};

struct relation_identifier {
	uint64_t type;
	uint64_t id;
	uint32_t boot_id;
	uint32_t machine_id;
};

struct packet_identifier {
	uint64_t type;
	uint16_t id;
	uint32_t snd_ip;
	uint32_t rcv_ip;
	uint16_t snd_port;
	uint16_t rcv_port;
	uint8_t protocol;
	uint32_t seq;
	int iv;
};

struct ipv6_packet_identifier {
	uint64_t type;
	struct in6_addr snd_ip;
	struct in6_addr rcv_ip;
	uint16_t snd_port;
	uint16_t rcv_port;
	uint8_t nexthdr;
	uint32_t seq;
	int iv;
};

#define MAX2(a, b) ((a > b) ? (a) : (b))
#define MAX4(a, b, c, d) MAX2(MAX2(a, b), MAX2(c, d))
#define PROV_IDENTIFIER_BUFFER_LENGTH MAX4(sizeof(struct node_identifier),     \
					   sizeof(struct relation_identifier), \
					   sizeof(struct packet_identifier),   \
					   sizeof(struct ipv6_packet_identifier))

union prov_identifier {
	struct node_identifier node_id;
	struct relation_identifier relation_id;
	struct packet_identifier packet_id;
	struct ipv6_packet_identifier ipv6_packet_id;
	uint8_t buffer[PROV_IDENTIFIER_BUFFER_LENGTH];
};

#define prov_set_flag(node, nbit)               (prov_flag(node) |= 1 << nbit)
#define prov_clear_flag(node, nbit)             (prov_flag(node) &= ~(1 << nbit))
#define prov_check_flag(node, nbit)             ((prov_flag(node) & (1 << nbit)) == (1 << nbit))

#define TRACKED_BIT             0
#define set_tracked(node)                       prov_set_flag(node, TRACKED_BIT)
#define clear_tracked(node)                     prov_clear_flag(node, TRACKED_BIT)
#define provenance_is_tracked(node)             prov_check_flag(node, TRACKED_BIT)

#define OPAQUE_BIT              1
#define set_opaque(node)                        prov_set_flag(node, OPAQUE_BIT)
#define clear_opaque(node)                      prov_clear_flag(node, OPAQUE_BIT)
#define provenance_is_opaque(node)              prov_check_flag(node, OPAQUE_BIT)

#define PROPAGATE_BIT           2
#define set_propagate(node)                     prov_set_flag(node, PROPAGATE_BIT)
#define clear_propagate(node)                   prov_clear_flag(node, PROPAGATE_BIT)
#define provenance_does_propagate(node)         prov_check_flag(node, PROPAGATE_BIT)

#define RECORD_PACKET_BIT       3
#define set_record_packet(node)                 prov_set_flag(node, RECORD_PACKET_BIT)
#define clear_record_packet(node)               prov_clear_flag(node, RECORD_PACKET_BIT)
#define provenance_records_packet(node)         prov_check_flag(node, RECORD_PACKET_BIT)

#define OUTGOING_BIT            4
#define set_has_outgoing(node)                  prov_set_flag(node, OUTGOING_BIT)
#define clear_has_outgoing(node)                prov_clear_flag(node, OUTGOING_BIT)
#define provenance_has_outgoing(node)           prov_check_flag(node, OUTGOING_BIT)

#define INITIALIZED_BIT         5
#define set_initialized(node)                   prov_set_flag(node, INITIALIZED_BIT)
#define clear_initialized(node)                 prov_clear_flag(node, INITIALIZED_BIT)
#define provenance_is_initialized(node)         prov_check_flag(node, INITIALIZED_BIT)

#define SAVED_BIT               6
#define set_saved(node)                         prov_set_flag(node, SAVED_BIT)
#define clear_saved(node)                       prov_clear_flag(node, SAVED_BIT)
#define provenance_is_saved(node)               prov_check_flag(node, SAVED_BIT)



#define basic_elements          union prov_identifier identifier; uint32_t epoch; uint32_t nepoch; uint32_t internal_flag; uint64_t jiffies; uint8_t taint[PROV_N_BYTES]
#define shared_node_elements    uint64_t previous_id; uint64_t previous_type; uint32_t k_version; uint32_t secid; uint32_t uid; uint32_t gid; void *var_ptr

struct msg_struct {
	basic_elements;
};

#define FILE_INFO_SET           0x01

struct relation_struct {
	basic_elements;
	uint8_t allowed;
	union prov_identifier snd;
	union prov_identifier rcv;
	uint8_t set;
	int64_t offset;
	uint64_t flags;
	uint64_t task_id;
};

struct node_struct {
	basic_elements;
	shared_node_elements;
};

struct proc_prov_struct {
	basic_elements;
	shared_node_elements;
	uint32_t tgid;
	uint32_t utsns;
	uint32_t ipcns;
	uint32_t mntns;
	uint32_t pidns;
	uint32_t netns;
	uint32_t cgroupns;
};

struct task_prov_struct {
	basic_elements;
	shared_node_elements;
	uint32_t pid;
	uint32_t vpid;
	/* usec */
	uint64_t utime;
	uint64_t stime;
	/* KB */
	uint64_t vm;
	uint64_t rss;
	uint64_t hw_vm;
	uint64_t hw_rss;
	uint64_t rbytes;
	uint64_t wbytes;
	uint64_t cancel_wbytes;
	union long_prov_elt *disc;
};

#define PROV_SBUUID_LEN 16
struct inode_prov_struct {
	basic_elements;
	shared_node_elements;
	uint64_t ino;
	uint16_t mode;
	uint8_t sb_uuid[PROV_SBUUID_LEN];
};

struct iattr_prov_struct {
	basic_elements;
	shared_node_elements;
	uint32_t valid;
	uint16_t mode;
	int64_t size;
	int64_t atime;
	int64_t ctime;
	int64_t mtime;
};

struct msg_msg_struct {
	basic_elements;
	shared_node_elements;
	long type;
};

struct shm_struct {
	basic_elements;
	shared_node_elements;
	uint16_t mode;
};

struct sb_struct {
	basic_elements;
	shared_node_elements;
	uint8_t uuid[16];
};

struct pck_struct {
	basic_elements;
	shared_node_elements;
	uint16_t length;
};

union prov_elt {
	struct msg_struct msg_info;
	struct relation_struct relation_info;
	struct node_struct node_info;
	struct proc_prov_struct proc_info;
	struct task_prov_struct task_info;
	struct inode_prov_struct inode_info;
	struct msg_msg_struct msg_msg_info;
	struct shm_struct shm_info;
	struct sb_struct sb_info;
	struct pck_struct pck_info;
	struct iattr_prov_struct iattr_info;
};

struct str_struct {
	basic_elements;
	shared_node_elements;
	char str[PATH_MAX];
	size_t length;
};

struct file_name_struct {
	basic_elements;
	shared_node_elements;
	char name[PATH_MAX];
	size_t length;
};

struct address_struct {
	basic_elements;
	shared_node_elements;
	size_t length;
	struct sockaddr_storage addr;
};

#define PROV_TRUNCATED    1
struct pckcnt_struct {
	basic_elements;
	shared_node_elements;
	uint8_t content[PATH_MAX];
	size_t length;
	uint8_t truncated;
};

struct arg_struct {
	basic_elements;
	shared_node_elements;
	char value[PATH_MAX];
	size_t length;
	uint8_t truncated;
};

struct disc_node_struct {
	basic_elements;
	shared_node_elements;
	size_t length;
	char content[PATH_MAX];
	union prov_identifier parent;
};

#define PROV_XATTR_NAME_SIZE            256
#define PROV_XATTR_VALUE_SIZE           (PATH_MAX - PROV_XATTR_NAME_SIZE)
struct xattr_prov_struct {
	basic_elements;
	shared_node_elements;
	char name[PROV_XATTR_NAME_SIZE];
	uint8_t value[PROV_XATTR_VALUE_SIZE];
	size_t size;
};

#define PROV_COMMIT_MAX_LENGTH 256
struct machine_struct {
	basic_elements;
	shared_node_elements;
	uint8_t cam_major;
	uint8_t cam_minor;
	uint8_t cam_patch;
	struct new_utsname utsname;
	char commit[PROV_COMMIT_MAX_LENGTH];
};

union long_prov_elt {
	struct msg_struct msg_info;
	struct relation_struct relation_info;
	struct node_struct node_info;
	struct proc_prov_struct proc_info;
	struct task_prov_struct task_info;
	struct inode_prov_struct inode_info;
	struct msg_msg_struct msg_msg_info;
	struct shm_struct shm_info;
	struct sb_struct sb_info;
	struct pck_struct pck_info;
	struct iattr_prov_struct iattr_info;
	struct str_struct str_info;
	struct file_name_struct file_name_info;
	struct arg_struct arg_info;
	struct address_struct address_info;
	struct pckcnt_struct pckcnt_info;
	struct disc_node_struct disc_node_info;
	struct xattr_prov_struct xattr_info;
	struct machine_struct machine_info;
};

typedef union long_prov_elt prov_entry_t;
#endif
