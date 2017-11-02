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
#ifndef _UAPI_LINUX_PROVENANCE_H
#define _UAPI_LINUX_PROVENANCE_H

#ifndef __KERNEL__
#include <linux/limits.h>
#else
#include <linux/socket.h>
#include <linux/limits.h>
#include <linux/mutex.h>
#endif

#define PROVENANCE_HASH "sha256"

#define PROV_GOLDEN_RATIO_64 0x61C8864680B583EBUL
static inline uint32_t prov_hash(uint64_t val)
{
	return (val * PROV_GOLDEN_RATIO_64) >> (64 - 8);
}

#define PROV_K_HASH 7
#define PROV_M_BITS 256
#define PROV_N_BYTES (PROV_M_BITS / 8)
#define PROV_BYTE_INDEX(a) (a / 8)
#define PROV_BIT_INDEX(a) (a % 8)

static inline void prov_bloom_add(uint8_t bloom[PROV_N_BYTES], uint64_t val)
{
	uint8_t i;
	uint32_t pos;

	for (i = 0; i < PROV_K_HASH; i++) {
		pos = prov_hash(val + i) % PROV_M_BITS;
		bloom[PROV_BYTE_INDEX(pos)] |= 1 << PROV_BIT_INDEX(pos);
	}
}

// djb2 hash implementation by Dan Bernstein
static inline uint64_t djb2_hash(const char *str)
{
	uint64_t hash = 5381;
	int c = *str;

	while (c) {
		hash = ((hash<<5)+hash) + c;
		c = *++str;
	}
	return hash;
}
#define generate_label(str) djb2_hash(str)

/* element in set belong to super */
static inline bool prov_bloom_match(const uint8_t super[PROV_N_BYTES], const uint8_t set[PROV_N_BYTES])
{
	uint8_t i;

	for (i = 0; i < PROV_N_BYTES; i++)
		if ((super[i] & set[i]) != set[i])
			return false;
	return true;
}

static inline bool prov_bloom_in(const uint8_t bloom[PROV_N_BYTES], uint64_t val)
{
	uint8_t tmp[PROV_N_BYTES];

	memset(tmp, 0, PROV_N_BYTES);
	prov_bloom_add(tmp, val);
	return prov_bloom_match(bloom, tmp);
}

/* merge src into dest (dest=dest U src) */
static inline void prov_bloom_merge(uint8_t dest[PROV_N_BYTES], const uint8_t src[PROV_N_BYTES])
{
	uint8_t i;

	for (i = 0; i < PROV_N_BYTES; i++)
		dest[i] |= src[i];
}


static inline bool prov_bloom_empty(const uint8_t bloom[PROV_N_BYTES])
{
	uint8_t i;

	for (i = 0; i < PROV_N_BYTES; i++)
		if (bloom[i] != 0)
			return false;
	return true;
}

#define PROV_ENABLE_FILE                      "/sys/kernel/security/provenance/enable"
#define PROV_ALL_FILE                         "/sys/kernel/security/provenance/all"
#define PROV_COMPRESS_FILE                    "/sys/kernel/security/provenance/compress"
#define PROV_NODE_FILE                        "/sys/kernel/security/provenance/node"
#define PROV_RELATION_FILE                    "/sys/kernel/security/provenance/relation"
#define PROV_SELF_FILE                        "/sys/kernel/security/provenance/self"
#define PROV_MACHINE_ID_FILE                  "/sys/kernel/security/provenance/machine_id"
#define PROV_BOOT_ID_FILE                  		"/sys/kernel/security/provenance/boot_id"
#define PROV_NODE_FILTER_FILE                 "/sys/kernel/security/provenance/node_filter"
#define PROV_RELATION_FILTER_FILE             "/sys/kernel/security/provenance/relation_filter"
#define PROV_PROPAGATE_NODE_FILTER_FILE       "/sys/kernel/security/provenance/propagate_node_filter"
#define PROV_PROPAGATE_RELATION_FILTER_FILE   "/sys/kernel/security/provenance/propagate_relation_filter"
#define PROV_FLUSH_FILE                       "/sys/kernel/security/provenance/flush"
#define PROV_PROCESS_FILE                     "/sys/kernel/security/provenance/process"
#define PROV_IPV4_INGRESS_FILE                "/sys/kernel/security/provenance/ipv4_ingress"
#define PROV_IPV4_EGRESS_FILE                 "/sys/kernel/security/provenance/ipv4_egress"
#define PROV_SECCTX                           "/sys/kernel/security/provenance/secctx"
#define PROV_SECCTX_FILTER                    "/sys/kernel/security/provenance/secctx_filter"
#define PROV_NS_FILTER												"/sys/kernel/security/provenance/ns"
#define PROV_LOG_FILE													"/sys/kernel/security/provenance/log"
#define PROV_LOGP_FILE												"/sys/kernel/security/provenance/logp"
#define PROV_POLICY_HASH_FILE									"/sys/kernel/security/provenance/policy_hash"
#define PROV_UID_FILTER												"/sys/kernel/security/provenance/uid"
#define PROV_GID_FILTER												"/sys/kernel/security/provenance/gid"
#define PROV_TYPE															"/sys/kernel/security/provenance/type"
#define PROV_VERSION													"/sys/kernel/security/provenance/version"
#define PROV_CHANNEL													"/sys/kernel/security/provenance/channel"

#define PROV_RELAY_NAME                       "/sys/kernel/debug/provenance"
#define PROV_LONG_RELAY_NAME                  "/sys/kernel/debug/long_provenance"
#define PROV_CHANNEL_ROOT											"/sys/kernel/debug/"

#define FLOW_ALLOWED        0
#define FLOW_DISALLOWED     1

#define prov_type(prov)               ((prov)->node_info.identifier.node_id.type)
#define node_type(node) prov_type(node)
#define edge_type(edge) prov_type(edge)
#define prov_id_buffer(prov)          ((prov)->node_info.identifier.buffer)
#define node_identifier(node)         ((node)->node_info.identifier.node_id)
#define relation_identifier(relation) ((relation)->relation_info.identifier.relation_id)
#define get_prov_identifier(node)			((node)->node_info.identifier)
#define packet_identifier(packet)     ((packet)->pck_info.identifier.packet_id)
#define prov_is_relation(prov)        ((relation_identifier(prov).type & DM_RELATION) != 0)
#define prov_is_node(prov)            ((node_identifier(prov).type & DM_RELATION) == 0)
#define node_secid(node)              ((node)->node_info.secid)
#define node_uid(node)              	((node)->node_info.uid)
#define node_gid(node)              	((node)->node_info.gid)

#define prov_flag(prov) ((prov)->msg_info.flag)
#define prov_taint(prov) ((prov)->msg_info.taint)
#define prov_jiffies(prov) ((prov)->msg_info.jiffies)

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
};

#define PROV_IDENTIFIER_BUFFER_LENGTH sizeof(struct node_identifier)

union prov_identifier {
	struct node_identifier node_id;
	struct relation_identifier relation_id;
	struct packet_identifier packet_id;
	uint8_t buffer[PROV_IDENTIFIER_BUFFER_LENGTH];
};

#define prov_set_flag(node, nbit) 	(prov_flag(node) |= 1 << nbit)
#define prov_clear_flag(node, nbit) (prov_flag(node) &= ~(1 << nbit))
#define prov_check_flag(node, nbit) ((prov_flag(node) & (1 << nbit)) == (1 << nbit))

#define RECORDED_BIT 0
#define set_recorded(node)                  prov_set_flag(node, RECORDED_BIT)
#define clear_recorded(node)                prov_clear_flag(node, RECORDED_BIT)
#define provenance_is_recorded(node)        prov_check_flag(node, RECORDED_BIT)

#define NAME_RECORDED_BIT 1
#define set_name_recorded(node)             prov_set_flag(node, NAME_RECORDED_BIT)
#define clear_name_recorded(node)           prov_clear_flag(node, NAME_RECORDED_BIT)
#define provenance_is_name_recorded(node)   prov_check_flag(node, NAME_RECORDED_BIT)

#define TRACKED_BIT 2
#define set_tracked(node)                   prov_set_flag(node, TRACKED_BIT)
#define clear_tracked(node)                 prov_clear_flag(node, TRACKED_BIT)
#define provenance_is_tracked(node)         prov_check_flag(node, TRACKED_BIT)

#define OPAQUE_BIT 3
#define set_opaque(node)                    prov_set_flag(node, OPAQUE_BIT)
#define clear_opaque(node)                  prov_clear_flag(node, OPAQUE_BIT)
#define provenance_is_opaque(node)          prov_check_flag(node, OPAQUE_BIT)

#define PROPAGATE_BIT 4
#define set_propagate(node)                 prov_set_flag(node, PROPAGATE_BIT)
#define clear_propagate(node)               prov_clear_flag(node, PROPAGATE_BIT)
#define provenance_does_propagate(node)     prov_check_flag(node, PROPAGATE_BIT)

#define RECORD_PACKET_BIT 5
#define set_record_packet(node)							prov_set_flag(node, RECORD_PACKET_BIT)
#define clear_record_packet(node)						prov_clear_flag(node, RECORD_PACKET_BIT)
#define provenance_records_packet(node)			prov_check_flag(node, RECORD_PACKET_BIT)

#define LONG_BIT 6
#define set_is_long(node)							prov_set_flag(node, LONG_BIT)
#define clear_is_long(node)						prov_clear_flag(node, LONG_BIT)
#define provenance_is_long(node)			prov_check_flag(node, LONG_BIT)

#define basic_elements union prov_identifier identifier; uint8_t flag; uint64_t jiffies; uint32_t secid; uint32_t uid; uint32_t gid; uint8_t taint[PROV_N_BYTES];	void *var_ptr

struct msg_struct {
	basic_elements;
};

#define FILE_INFO_SET 0x01

struct relation_struct {
	basic_elements;
	uint8_t allowed;
	union prov_identifier snd;
	union prov_identifier rcv;
	uint8_t set;
	int64_t offset;
};

struct node_struct {
	basic_elements;
};

struct task_prov_struct {
	basic_elements;
	uint32_t pid;
	uint32_t vpid;
	uint32_t ppid;
	uint32_t tgid;
	uint32_t utsns;
	uint32_t ipcns;
	uint32_t mntns;
	uint32_t pidns;
	uint32_t netns;
	uint32_t cgroupns;
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
};

struct inode_prov_struct {
	basic_elements;
	uint64_t ino;
	uint16_t mode;
	uint8_t sb_uuid[16];
};

struct iattr_prov_struct {
	basic_elements;
	uint32_t valid;
	uint16_t mode;
	int64_t size;
	int64_t atime;
	int64_t ctime;
	int64_t mtime;
};

struct msg_msg_struct {
	basic_elements;
	long type;
};

struct shm_struct {
	basic_elements;
	uint16_t mode;
};

struct sb_struct {
	basic_elements;
	uint8_t uuid[16];
};

struct pck_struct {
	basic_elements;
	uint16_t length;
};

union prov_elt {
	struct msg_struct msg_info;
	struct relation_struct relation_info;
	struct node_struct node_info;
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
	char str[PATH_MAX];
	size_t length;
};

struct file_name_struct {
	basic_elements;
	char name[PATH_MAX];
	size_t length;
};

struct address_struct {
	basic_elements;
	struct sockaddr addr;
	size_t length;
};

#define PROV_TRUNCATED 1
struct pckcnt_struct {
	basic_elements;
	uint8_t content[PATH_MAX];
	size_t length;
	uint8_t truncated;
};

struct arg_struct {
	basic_elements;
	char value[PATH_MAX];
	size_t length;
	uint8_t truncated;
};

#define PROV_XATTR_NAME_SIZE    256
#define PROV_XATTR_VALUE_SIZE   (PATH_MAX - PROV_XATTR_NAME_SIZE)
struct xattr_prov_struct {
	basic_elements;
	char name[PROV_XATTR_NAME_SIZE]; // max Linux characters
	int32_t flags;
	uint8_t value[PROV_XATTR_VALUE_SIZE];
	size_t size;
};

struct disc_node_struct {
	basic_elements;
	size_t length;
	char content[PATH_MAX];
	union prov_identifier parent;
};

union long_prov_elt {
	struct msg_struct msg_info;
	struct relation_struct relation_info;
	struct node_struct node_info;
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
};

typedef union long_prov_elt prov_entry_t;

struct prov_filter {
	uint64_t filter;
	uint64_t mask;
	uint8_t add;
};

#define PROV_SET_TRACKED      0x01
#define PROV_SET_OPAQUE       0x02
#define PROV_SET_PROPAGATE    0x04
#define PROV_SET_TAINT        0x08
#define PROV_SET_DELETE       0x10
#define PROV_SET_RECORD       0x20

struct prov_process_config {
	union prov_elt prov;
	uint8_t op;
	uint32_t vpid;
};

struct prov_ipv4_filter {
	uint32_t ip;
	uint32_t mask;
	uint16_t port;
	uint8_t op;
	uint64_t taint;
};

struct secinfo {
	uint32_t secid;
	char secctx[PATH_MAX];
	uint32_t len;
	uint8_t op;
	uint64_t taint;
};

struct userinfo {
	uint32_t uid;
	uint8_t op;
	uint64_t taint;
};

struct groupinfo {
	uint32_t gid;
	uint8_t op;
	uint64_t taint;
};

#define IGNORE_NS 0

struct nsinfo {
	uint32_t utsns;
	uint32_t ipcns;
	uint32_t mntns;
	uint32_t pidns;
	uint32_t netns;
	uint32_t cgroupns;
	uint8_t op;
	uint64_t taint;
};

#endif
