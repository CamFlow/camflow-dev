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
#include <linux/ifc.h>
#else
#include <linux/socket.h>
#include <uapi/linux/ifc.h>
#include <uapi/linux/limits.h>
#include <linux/mutex.h>
#endif

#define GOLDEN_RATIO_64 0x61C8864680B583EBull
static inline uint32_t prov_hash(uint64_t val){
  return (val * GOLDEN_RATIO_64) >> (64-8);
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

#define PROV_RELAY_NAME                       "/sys/kernel/debug/provenance"
#define PROV_LONG_RELAY_NAME                  "/sys/kernel/debug/long_provenance"

#define MSG_STR               0x00000001UL
#define MSG_RELATION          0x00000002UL
#define MSG_TASK              0x00000004UL
#define MSG_INODE_UNKNOWN     0x00000008UL
#define MSG_INODE_LINK        0x00000010UL
#define MSG_INODE_FILE        0x00000020UL
#define MSG_INODE_DIRECTORY   0x00000040UL
#define MSG_INODE_CHAR        0x00000080UL
#define MSG_INODE_BLOCK       0x00000100UL
#define MSG_INODE_FIFO        0x00000200UL
#define MSG_INODE_SOCKET      0x00000400UL
#define MSG_MSG               0x00000800UL
#define MSG_SHM               0x00001000UL
#define MSG_SOCK              0x00002000UL
#define MSG_ADDR              0x00004000UL
#define MSG_SB                0x00008000UL
#define MSG_FILE_NAME         0x00010000UL
#define MSG_IFC               0x00020000UL
#define MSG_DISC_ENTITY       0x00040000UL
#define MSG_DISC_ACTIVITY     0x00080000UL
#define MSG_DISC_AGENT        0x00100000UL
#define MSG_DISC_NODE         0x00200000UL
#define MSG_PACKET            0x00400000UL

#define RL_READ               0x00000001UL
#define RL_WRITE              0x00000002UL
#define RL_CREATE             0x00000004UL
#define RL_PASS               0x00000008UL
#define RL_CHANGE             0x00000010UL
#define RL_MMAP_WRITE         0x00000020UL
#define RL_ATTACH             0x00000040UL
#define RL_ASSOCIATE          0x00000080UL
#define RL_BIND               0x00000100UL
#define RL_CONNECT            0x00000200UL
#define RL_LISTEN             0x00000400UL
#define RL_ACCEPT             0x00000800UL
#define RL_OPEN               0x00001000UL
#define RL_PARENT             0x00002000UL
#define RL_VERSION            0x00004000UL
#define RL_LINK               0x00008000UL
#define RL_NAMED              0x00010000UL
#define RL_IFC                0x00020000UL
#define RL_EXEC               0x00040000UL
#define RL_CLONE              0x00080000UL
#define RL_UNKNOWN            0x00100000UL
#define RL_VERSION_PROCESS    0x00200000UL
#define RL_SEARCH             0x00400000UL
#define RL_ALLOWED            0x00800000UL
#define RL_DISALLOWED         0x01000000UL
#define RL_MMAP_READ          0x02000000UL
#define RL_MMAP_EXEC          0x04000000UL
#define RL_SND                0x08000000UL
#define RL_RCV                0x10000000UL
#define RL_PERM_READ          0x20000000UL
#define RL_PERM_WRITE         0x40000000UL
#define RL_PERM_EXEC          0x80000000UL

#define FLOW_ALLOWED        1
#define FLOW_DISALLOWED     0

#define prov_type(prov) ((prov)->node_info.identifier.node_id.type)
#define prov_id_buffer(prov) ((prov)->node_info.identifier.buffer)
#define node_identifier(node) ((node)->node_info.identifier.node_id)
#define relation_identifier(relation) ((relation)->relation_info.identifier.relation_id)
#define packet_identifier(packet) ((packet)->pck_info.identifier.packet_id)
#define prov_flag(prov) ((prov)->msg_info.flag)
#define prov_taint(prov) ((prov)->msg_info.taint)
#define prov_jiffies(prov) ((prov)->msg_info.jiffies)

struct node_identifier{
  uint32_t type;
  uint64_t id;
  uint32_t boot_id;
  uint32_t machine_id;
  uint32_t version;
};

struct relation_identifier{
  uint32_t type;
  uint64_t id;
  uint32_t boot_id;
  uint32_t machine_id;
};

struct packet_identifier{
  uint32_t type;
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
#define provenance_propagate(node)          prov_check_flag(node, PROPAGATE_BIT)

#define basic_elements prov_identifier_t identifier; uint8_t flag; uint64_t jiffies; uint8_t taint[PROV_N_BYTES]

struct msg_struct{
  basic_elements;
};

#define FILE_INFO_SET 0x01

struct relation_struct{
  basic_elements;
  uint32_t type;
  uint8_t allowed;
  prov_identifier_t snd;
  prov_identifier_t rcv;
  uint8_t set;
  int64_t offset;
};

union provmutex{
#ifdef __KERNEL__
  struct mutex l;
#endif
  uint8_t placeholder[70];
};

struct node_struct{
  basic_elements;
  union provmutex lprov;
};

struct task_prov_struct{
  basic_elements;
  union provmutex lprov;
  uint32_t uid;
  uint32_t gid;
};

struct inode_prov_struct{
  basic_elements;
  union provmutex lprov;
  uint32_t uid;
  uint32_t gid;
  uint16_t mode;
  uint8_t sb_uuid[16];
};

struct msg_msg_struct{
  basic_elements;
  union provmutex lprov;
  long type;
};

struct shm_struct{
  basic_elements;
  union provmutex lprov;
  uint16_t mode;
};

struct sock_struct{
  basic_elements;
  union provmutex lprov;
  uint16_t type;
  uint16_t family;
  uint8_t protocol;
};

struct sb_struct{
  basic_elements;
  union provmutex lprov;
  uint8_t uuid[16];
};

struct pck_struct{
  basic_elements;
  union provmutex lprov;
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
  struct sock_struct          sock_info;
  struct sb_struct            sb_info;
  struct pck_struct           pck_info;
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

struct ifc_context_struct{
  basic_elements;
  struct ifc_context context;
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
  struct ifc_context_struct   ifc_info;
  struct disc_node_struct     disc_node_info;
} long_prov_msg_t;

struct prov_filter{
  uint32_t filter;
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

#endif
