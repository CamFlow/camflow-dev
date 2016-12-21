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
#ifndef _UAPI_LINUX_PROVENANCE_H
#define _UAPI_LINUX_PROVENANCE_H

#ifndef __KERNEL__
#include <linux/limits.h>
#else
#include <linux/socket.h>
#include <uapi/linux/limits.h>
#include <linux/mutex.h>
#endif

#define PROV_GOLDEN_RATIO_64 0x61C8864680B583EBUL
static inline uint32_t prov_hash(uint64_t val){
  return (val * PROV_GOLDEN_RATIO_64) >> (64-8);
}

#define PROV_K_HASH 7
#define PROV_M_BITS 256
#define PROV_N_BYTES (PROV_M_BITS/8)
#define PROV_BYTE_INDEX(a) (a/8)
#define PROV_BIT_INDEX(a) (a%8)

static inline void prov_bloom_add(uint8_t bloom[PROV_N_BYTES], uint64_t val){
  uint8_t i;
  uint32_t pos;
  for(i=0; i < PROV_K_HASH; i++){
    pos= prov_hash(val+i) % PROV_M_BITS;
    bloom[PROV_BYTE_INDEX(pos)] |= 1 << PROV_BIT_INDEX(pos);
  }
}

/* element in set belong to super */
static inline bool prov_bloom_match(const uint8_t super[PROV_N_BYTES], const uint8_t set[PROV_N_BYTES]){
    uint8_t i;
    for(i=0; i<PROV_N_BYTES; i++){
        if((super[i]&set[i]) != set[i]){
            return false;
        }
    }
    return true;
}

static inline bool prov_bloom_in(const uint8_t bloom[PROV_N_BYTES], uint64_t val){
    uint8_t tmp[PROV_N_BYTES];

    memset(tmp, 0, PROV_N_BYTES);
    prov_bloom_add(tmp, val);
    return prov_bloom_match(bloom, tmp);
}

/* merge src into dest (dest=dest U src) */
static inline void prov_bloom_merge(uint8_t dest[PROV_N_BYTES], const uint8_t src[PROV_N_BYTES]){
    uint8_t i;
    for(i=0; i<PROV_N_BYTES; i++){
        dest[i] |= src[i];
    }
}


static inline bool prov_bloom_empty(const uint8_t bloom[PROV_N_BYTES]){
  uint8_t i;
  for(i=0; i<PROV_N_BYTES; i++){
      if( bloom[i] != 0 ){
          return false;
      }
  }
  return true;
}

#define PROV_ENABLE_FILE                      "/sys/kernel/security/provenance/enable"
#define PROV_ALL_FILE                         "/sys/kernel/security/provenance/all"
#define PROV_NODE_FILE                        "/sys/kernel/security/provenance/node"
#define PROV_RELATION_FILE                    "/sys/kernel/security/provenance/relation"
#define PROV_SELF_FILE                        "/sys/kernel/security/provenance/self"
#define PROV_MACHINE_ID_FILE                  "/sys/kernel/security/provenance/machine_id"
#define PROV_NODE_FILTER_FILE                 "/sys/kernel/security/provenance/node_filter"
#define PROV_RELATION_FILTER_FILE             "/sys/kernel/security/provenance/relation_filter"
#define PROV_PROPAGATE_NODE_FILTER_FILE       "/sys/kernel/security/provenance/propagate_node_filter"
#define PROV_PROPAGATE_RELATION_FILTER_FILE   "/sys/kernel/security/provenance/propagate_relation_filter"
#define PROV_FLUSH_FILE                       "/sys/kernel/security/provenance/flush"
#define PROV_FILE_FILE                        "/sys/kernel/security/provenance/file"
#define PROV_PROCESS_FILE                     "/sys/kernel/security/provenance/process"
#define PROV_IPV4_INGRESS_FILE                "/sys/kernel/security/provenance/ipv4_ingress"
#define PROV_IPV4_EGRESS_FILE                 "/sys/kernel/security/provenance/ipv4_egress"

#define PROV_RELAY_NAME                       "/sys/kernel/debug/provenance"
#define PROV_LONG_RELAY_NAME                  "/sys/kernel/debug/long_provenance"

#define TYPE_MASK             0xFFFF000000000000UL
#define SUBTYPE_MASK          0x0000FFFFFFFFFFFFUL

#define W3C_TYPE(type)        (type&TYPE_MASK)
#define SUBTYPE(type)         (type&SUBTYPE_MASK)

/* W3C PROV TYPES */
#define DM_RELATION           0x8000000000000000UL
#define DM_ACTIVITY           0x4000000000000000UL
#define DM_ENTITY             0x2000000000000000UL
#define DM_AGENT              0x1000000000000000UL
/* ALLOWED/DISALLOWED */
#define RL_ALLOWED            0x0200000000000000UL
#define RL_DISALLOWED         0x0100000000000000UL
/* SUBTYPES */
/* RELATIONS W3C TYPE*/
#define RL_DERIVED            (DM_RELATION | 0x0080000000000000ULL)
#define RL_GENERATED          (DM_RELATION | 0x0040000000000000ULL)
#define RL_ATTRIBUTED         (DM_RELATION | 0x0020000000000000ULL)
#define RL_USED               (DM_RELATION | 0x0010000000000000ULL)
#define RL_INFORMED           (DM_RELATION | 0x0008000000000000ULL)
#define RL_ASSOCIATED         (DM_RELATION | 0x0004000000000000ULL)
#define RL_BEHALF             (DM_RELATION | 0x0002000000000000ULL)
#define RL_UNKNOWN            (DM_RELATION | 0x0001000000000000ULL)
/* DERIVED SUBTYPES */
#define RL_NAMED              (RL_DERIVED   | 0x0000000000000001ULL)
#define RL_VERSION            (RL_DERIVED   | 0x0000000000000002ULL)
#define RL_MMAP               (RL_DERIVED   | 0x0000000000000004ULL)
#define RL_SND_PACKET         (RL_DERIVED   | 0x0000000000000008ULL)
#define RL_RCV_PACKET         (RL_DERIVED   | 0x0000000000000010ULL)
/* GENERATED SUBTYPES */
#define RL_CREATE             (RL_GENERATED | 0x0000000000000020ULL)
#define RL_WRITE              (RL_GENERATED | 0x0000000000000040ULL)
#define RL_PERM_WRITE         (RL_GENERATED | 0x0000000000000080ULL)
#define RL_MMAP_WRITE         (RL_GENERATED | 0x0000000000000100ULL)
#define RL_CONNECT            (RL_GENERATED | 0x0000000000000200ULL)
#define RL_LISTEN             (RL_GENERATED | 0x0000000000000400ULL)
#define RL_BIND               (RL_GENERATED | 0x0000000000000800ULL)
#define RL_SND                (RL_GENERATED | 0x0000000000001000ULL)
#define RL_LINK               (RL_GENERATED | 0x0000000000002000ULL)
#define RL_SETATTR            (RL_GENERATED | 0x0000000000004000ULL)
#define RL_SETXATTR           (RL_GENERATED | 0x0000000000008000ULL)
#define RL_RMVXATTR           (RL_GENERATED | 0x0000000000010000ULL)
/* USED SUBTYPES */
#define RL_READ               (RL_USED      | 0x0000000000020000ULL)
#define RL_MMAP_READ          (RL_USED      | 0x0000000000040000ULL)
#define RL_PERM_READ          (RL_USED      | 0x0000000000080000ULL)
#define RL_EXEC               (RL_USED      | 0x0000000000100000ULL)
#define RL_MMAP_EXEC          (RL_USED      | 0x0000000000200000ULL)
#define RL_PERM_EXEC          (RL_USED      | 0x0000000000400000ULL)
#define RL_ACCEPT             (RL_USED      | 0x0000000000800000ULL)
#define RL_RCV                (RL_USED      | 0x0000000001000000ULL)
#define RL_OPEN               (RL_USED      | 0x0000000002000000ULL)
#define RL_SEARCH             (RL_USED      | 0x0000000004000000ULL)
#define RL_GETATTR            (RL_USED      | 0x0000000008000000ULL)
#define RL_READLINK           (RL_USED      | 0x0000000010000000ULL)
#define RL_GETXATTR           (RL_USED      | 0x0000000020000000ULL)
#define RL_LSTXATTR           (RL_USED      | 0x0000000040000000ULL)
#define RL_NAMED_PROCESS      (RL_USED      | 0x0000000080000000ULL)
/* INFORMED SUBTYPES */
#define RL_CLONE              (RL_INFORMED  | 0x0000000100000000ULL)
#define RL_VERSION_PROCESS    (RL_INFORMED  | 0x0000000200000000ULL)
#define RL_CHANGE             (RL_INFORMED  | 0x0000000400000000ULL)
#define RL_EXEC_PROCESS       (RL_INFORMED  | 0x0000000800000000ULL)

/* ACTIVITY SUBTYPES */
#define ACT_TASK              (DM_ACTIVITY  | 0x0000000000000001ULL)
#define ACT_DISC              (DM_ACTIVITY  | 0x0000000000000002ULL)
/* AGENT SUBTYPES */
#define AGT_USR               (DM_AGENT     | 0x0000000000000004ULL)
#define AGT_GRP               (DM_AGENT     | 0x0000000000000008ULL)
#define AGT_DISC              (DM_AGENT     | 0x0000000000000010ULL)
/* ENTITY SUBTYPES */
#define ENT_STR               (DM_ENTITY    | 0x0000000000000020ULL)
#define ENT_INODE_UNKNOWN     (DM_ENTITY    | 0x0000000000000040ULL)
#define ENT_INODE_LINK        (DM_ENTITY    | 0x0000000000000080ULL)
#define ENT_INODE_FILE        (DM_ENTITY    | 0x0000000000000100ULL)
#define ENT_INODE_DIRECTORY   (DM_ENTITY    | 0x0000000000000200ULL)
#define ENT_INODE_CHAR        (DM_ENTITY    | 0x0000000000000400ULL)
#define ENT_INODE_BLOCK       (DM_ENTITY    | 0x0000000000000800ULL)
#define ENT_INODE_FIFO        (DM_ENTITY    | 0x0000000000001000ULL)
#define ENT_INODE_SOCKET      (DM_ENTITY    | 0x0000000000002000ULL)
#define ENT_INODE_MMAP        (DM_ENTITY    | 0x0000000000004000ULL)
#define ENT_MSG               (DM_ENTITY    | 0x0000000000008000ULL)
#define ENT_SHM               (DM_ENTITY    | 0x0000000000010000ULL)
#define ENT_ADDR              (DM_ENTITY    | 0x0000000000020000ULL)
#define ENT_SBLCK             (DM_ENTITY    | 0x0000000000040000ULL)
#define ENT_FILE_NAME         (DM_ENTITY    | 0x0000000000080000ULL)
#define ENT_PACKET            (DM_ENTITY    | 0x0000000000100000ULL)
#define ENT_DISC              (DM_ENTITY    | 0x0000000000200000ULL)
#define ENT_IATTR             (DM_ENTITY    | 0x0000000000400000ULL)
#define ENT_XATTR             (DM_ENTITY    | 0x0000000000800000ULL)

#define FLOW_ALLOWED        1
#define FLOW_DISALLOWED     0

#define prov_type(prov)               ((prov)->node_info.identifier.node_id.type)
#define prov_id_buffer(prov)          ((prov)->node_info.identifier.buffer)
#define node_identifier(node)         ((node)->node_info.identifier.node_id)
#define relation_identifier(relation) ((relation)->relation_info.identifier.relation_id)
#define packet_identifier(packet)     ((packet)->pck_info.identifier.packet_id)
#define prov_is_relation(prov)             ((relation_identifier(prov).type&DM_RELATION)!=0)
#define prov_is_node(prov)                 ((node_identifier(prov).type&DM_RELATION)==0)

#define prov_flag(prov) ((prov)->msg_info.flag)
#define prov_taint(prov) ((prov)->msg_info.taint)
#define prov_jiffies(prov) ((prov)->msg_info.jiffies)

struct node_identifier{
  uint64_t type;
  uint64_t id;
  uint32_t boot_id;
  uint32_t machine_id;
  uint32_t version;
};

struct relation_identifier{
  uint64_t type;
  uint64_t id;
  uint32_t boot_id;
  uint32_t machine_id;
};

struct packet_identifier{
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

typedef union prov_identifier{
  struct node_identifier node_id;
  struct relation_identifier relation_id;
  struct packet_identifier packet_id;
  uint8_t buffer[PROV_IDENTIFIER_BUFFER_LENGTH];
} prov_identifier_t;

#define prov_set_flag(node, nbit) prov_flag(node) |= 1 << nbit
#define prov_clear_flag(node, nbit) prov_flag(node) &= ~(1 << nbit)
#define prov_check_flag(node, nbit) ((prov_flag(node) & (1 << nbit)) == (1 << nbit))

#define RECORDED_BIT 0
#define set_recorded(node)                  prov_set_flag(node, RECORDED_BIT)
#define clear_recorded(node)                prov_clear_flag(node, RECORDED_BIT)
#define provenance_is_recorded(node)        prov_check_flag(node, RECORDED_BIT)

#define NAME_RECORDED_BIT 1
#define set_name_recorded(node)             prov_set_flag(node, NAME_RECORDED_BIT)
#define clear__name_recorded(node)          prov_clear_flag(node, NAME_RECORDED_BIT)
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

#define basic_elements prov_identifier_t identifier; uint8_t flag; uint64_t jiffies; uint8_t taint[PROV_N_BYTES]

struct msg_struct{
  basic_elements;
};

#define FILE_INFO_SET 0x01

struct relation_struct{
  basic_elements;
  uint8_t allowed;
  prov_identifier_t snd;
  prov_identifier_t rcv;
  uint8_t set;
  int64_t offset;
};

struct node_struct{
  basic_elements;
};

struct task_prov_struct{
  basic_elements;
  uint32_t uid;
  uint32_t gid;
  uint32_t pid;
  uint32_t vpid;
  uint32_t cid;
  uint32_t secid;
};

struct inode_prov_struct{
  basic_elements;
  uint32_t uid;
  uint32_t gid;
  uint16_t mode;
  uint8_t sb_uuid[16];
  uint32_t secid;
};

struct iattr_prov_struct{
  basic_elements;
  uint32_t valid;
  uint16_t mode;
  uint32_t uid;
  uint32_t gid;
  int64_t size;
  int64_t atime;
  int64_t ctime;
  int64_t mtime;
};

struct msg_msg_struct{
  basic_elements;
  long type;
};

struct shm_struct{
  basic_elements;
  uint16_t mode;
};

struct sb_struct{
  basic_elements;
  uint8_t uuid[16];
};

struct pck_struct{
  basic_elements;
  uint16_t length;
};

typedef union prov_msg{
  struct msg_struct           msg_info;
  struct relation_struct      relation_info;
  struct node_struct          node_info;
  struct task_prov_struct     task_info;
  struct inode_prov_struct    inode_info;
  struct msg_msg_struct       msg_msg_info;
  struct shm_struct           shm_info;
  struct sb_struct            sb_info;
  struct pck_struct           pck_info;
  struct iattr_prov_struct    iattr_info;
} prov_msg_t;

struct str_struct{
  basic_elements;
  char str[PATH_MAX];
  size_t length;
};

struct file_name_struct{
  basic_elements;
  char name[PATH_MAX];
  size_t length;
};

struct address_struct{
  basic_elements;
  struct sockaddr addr;
  size_t length;
};

#define PROV_XATTR_NAME_SIZE    256
#define PROV_XATTR_VALUE_SIZE   (PATH_MAX - PROV_XATTR_NAME_SIZE)
struct xattr_prov_struct{
  basic_elements;
  char name[PROV_XATTR_NAME_SIZE]; // max Linux characters
  int32_t flags;
  uint8_t value[PROV_XATTR_VALUE_SIZE];
  size_t size;
};

struct disc_node_struct{
  basic_elements;
  size_t length;
  char content[PATH_MAX];
  prov_identifier_t parent;
};

typedef union long_msg{
  struct msg_struct           msg_info;
  struct node_struct          node_info;
  struct str_struct           str_info;
  struct file_name_struct     file_name_info;
  struct address_struct       address_info;
  struct disc_node_struct     disc_node_info;
  struct xattr_prov_struct    xattr_info;
} long_prov_msg_t;

struct prov_filter{
  uint64_t filter;
  uint64_t mask;
  uint8_t add;
};

#define PROV_SET_TRACKED		  0x01
#define PROV_SET_OPAQUE 		  0x02
#define PROV_SET_PROPAGATE    0x04
#define PROV_SET_TAINT        0x08

struct prov_file_config{
  char name[PATH_MAX];
  prov_msg_t prov;
  uint8_t op;
};

struct prov_self_config{
  prov_msg_t prov;
  uint8_t op;
};

struct prov_process_config{
  prov_msg_t prov;
  uint8_t op;
  uint32_t vpid;
};

#define PROV_NET_TRACKED		  0x01
#define PROV_NET_OPAQUE 		  0x02
#define PROV_NET_PROPAGATE    0x04
#define PROV_NET_TAINT        0x08
#define PROV_NET_RECORD       0x10
#define PROV_NET_DELETE       0x20 // to actually delete a filter from the list

struct prov_ipv4_filter{
  uint32_t ip;
  uint32_t mask;
  uint16_t port;
  uint8_t op;
  uint64_t taint;
};

#endif
