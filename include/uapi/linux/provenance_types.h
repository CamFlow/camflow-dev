/*
 *
 * Author: Thomas Pasquier <tfjmp@g.harvard.edu>
 *
 * Copyright (C) 2017 Harvard University
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 */
#ifndef _UAPI_LINUX_PROVENANCE_TYPES_H
#define _UAPI_LINUX_PROVENANCE_TYPES_H

#ifndef __KERNEL__
#include <stdint.h>
#include <stdbool.h>
#endif


#define TYPE_MASK             0xFFFF000000000000UL
#define SUBTYPE_MASK          0x0000FFFFFFFFFFFFUL

#define W3C_TYPE(type)        (type & TYPE_MASK)
#define SUBTYPE(type)         (type & SUBTYPE_MASK)

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
#define RL_USED               (DM_RELATION | 0x0020000000000000ULL)
#define RL_INFORMED           (DM_RELATION | 0x0010000000000000ULL)
/* DERIVED SUBTYPES */
#define RL_NAMED              (RL_DERIVED   | 0x0000000000000001ULL)
#define RL_VERSION            (RL_DERIVED   | (0x0000000000000001ULL<<1))
#define RL_MMAP               (RL_DERIVED   | (0x0000000000000001ULL<<2))
#define RL_SND_PACKET         (RL_DERIVED   | (0x0000000000000001ULL<<3))
#define RL_RCV_PACKET         (RL_DERIVED   | (0x0000000000000001ULL<<4))
#define RL_CLOSED             (RL_DERIVED   | (0x0000000000000001ULL<<5))
#define RL_SETATTR_INODE      (RL_DERIVED   | (0x0000000000000001ULL<<6))
#define RL_ACCEPT_SOCKET      (RL_DERIVED   | (0x0000000000000001ULL<<7))
#define RL_GETXATTR_INODE     (RL_DERIVED   | (0x0000000000000001ULL<<8))
#define RL_SETXATTR_INODE     (RL_DERIVED   | (0x0000000000000001ULL<<9))
#define RL_RMVXATTR_INODE     (RL_DERIVED   | (0x0000000000000001ULL<<10))
#define RL_LINK_INODE         (RL_DERIVED   | (0x0000000000000001ULL<<11))
/* GENERATED SUBTYPES */
#define RL_CREATE             (RL_GENERATED | (0x0000000000000001ULL<<12))
#define RL_WRITE              (RL_GENERATED | (0x0000000000000001ULL<<13))
#define RL_MMAP_WRITE         (RL_GENERATED | (0x0000000000000001ULL<<14))
#define RL_SH_WRITE           (RL_GENERATED | (0x0000000000000001ULL<<15))
#define RL_CONNECT            (RL_GENERATED | (0x0000000000000001ULL<<16))
#define RL_LISTEN             (RL_GENERATED | (0x0000000000000001ULL<<17))
#define RL_BIND               (RL_GENERATED | (0x0000000000000001ULL<<18))
#define RL_SND                (RL_GENERATED | (0x0000000000000001ULL<<19))
#define RL_SND_UNIX           (RL_GENERATED | (0x0000000000000001ULL<<20))
#define RL_LINK               (RL_GENERATED | (0x0000000000000001ULL<<21))
#define RL_SETATTR            (RL_GENERATED | (0x0000000000000001ULL<<22))
#define RL_SETXATTR           (RL_GENERATED | (0x0000000000000001ULL<<23))
#define RL_RMVXATTR           (RL_GENERATED | (0x0000000000000001ULL<<24))
/* USED SUBTYPES */
#define RL_READ               (RL_USED      | (0x0000000000000001ULL<<25))
#define RL_MMAP_READ          (RL_USED      | (0x0000000000000001ULL<<26))
#define RL_SH_READ            (RL_USED      | (0x0000000000000001ULL<<27))
#define RL_EXEC               (RL_USED      | (0x0000000000000001ULL<<28))
#define RL_MMAP_EXEC          (RL_USED      | (0x0000000000000001ULL<<29))
#define RL_ACCEPT             (RL_USED      | (0x0000000000000001ULL<<30))
#define RL_RCV                (RL_USED      | (0x0000000000000001ULL<<31))
#define RL_RCV_UNIX           (RL_USED      | (0x0000000000000001ULL<<32))
#define RL_OPEN               (RL_USED      | (0x0000000000000001ULL<<33))
#define RL_SEARCH             (RL_USED      | (0x0000000000000001ULL<<34))
#define RL_GETATTR            (RL_USED      | (0x0000000000000001ULL<<35))
#define RL_READLINK           (RL_USED      | (0x0000000000000001ULL<<36))
#define RL_GETXATTR           (RL_USED      | (0x0000000000000001ULL<<37))
#define RL_LSTXATTR           (RL_USED      | (0x0000000000000001ULL<<38))
#define RL_NAMED_PROCESS      (RL_USED      | (0x0000000000000001ULL<<39))
#define RL_LOG                (RL_USED      | (0x0000000000000001ULL<<40))
#define RL_ARG                (RL_USED      | (0x0000000000000001ULL<<41))
#define RL_ENV                (RL_USED      | (0x0000000000000001ULL<<42))
#define RL_PERM_READ          (RL_USED      | (0x0000000000000001ULL<<43))
#define RL_PERM_WRITE         (RL_USED      | (0x0000000000000001ULL<<44))
#define RL_PERM_EXEC          (RL_USED      | (0x0000000000000001ULL<<45))
/* INFORMED SUBTYPES */
#define RL_CLONE              (RL_INFORMED  | (0x0000000000000001ULL<<46))
#define RL_VERSION_PROCESS    (RL_INFORMED  | (0x0000000000000001ULL<<47))
#define RL_CHANGE             (RL_INFORMED  | (0x0000000000000001ULL<<48))
#define RL_EXEC_PROCESS       (RL_INFORMED  | (0x0000000000000001ULL<<49))
#define RL_TERMINATE_PROCESS  (RL_INFORMED  | (0x0000000000000001ULL<<50))

/* ACTIVITY SUBTYPES */
#define ACT_TASK              (DM_ACTIVITY  | 0x0000000000000001ULL)
#define ACT_DISC              (DM_ACTIVITY  | (0x0000000000000001ULL<<1))
/* AGENT SUBTYPES */
#define AGT_USR               (DM_AGENT     | 0x0000000000000001ULL<<2))
#define AGT_GRP               (DM_AGENT     | (0x0000000000000001ULL<<3))
#define AGT_DISC              (DM_AGENT     | (0x0000000000000001ULL<<4))
/* ENTITY SUBTYPES */
#define ENT_STR               (DM_ENTITY    | (0x0000000000000001ULL<<5))
#define ENT_INODE_UNKNOWN     (DM_ENTITY    | (0x0000000000000001ULL<<6))
#define ENT_INODE_LINK        (DM_ENTITY    | (0x0000000000000001ULL<<7))
#define ENT_INODE_FILE        (DM_ENTITY    | (0x0000000000000001ULL<<8))
#define ENT_INODE_DIRECTORY   (DM_ENTITY    | (0x0000000000000001ULL<<9))
#define ENT_INODE_CHAR        (DM_ENTITY    | (0x0000000000000001ULL<<10))
#define ENT_INODE_BLOCK       (DM_ENTITY    | (0x0000000000000001ULL<<11))
#define ENT_INODE_FIFO        (DM_ENTITY    | (0x0000000000000001ULL<<12))
#define ENT_INODE_SOCKET      (DM_ENTITY    | (0x0000000000000001ULL<<13))
#define ENT_INODE_MMAP        (DM_ENTITY    | (0x0000000000000001ULL<<14))
#define ENT_MSG               (DM_ENTITY    | (0x0000000000000001ULL<<15))
#define ENT_SHM               (DM_ENTITY    | (0x0000000000000001ULL<<16))
#define ENT_ADDR              (DM_ENTITY    | (0x0000000000000001ULL<<17))
#define ENT_SBLCK             (DM_ENTITY    | (0x0000000000000001ULL<<18))
#define ENT_FILE_NAME         (DM_ENTITY    | (0x0000000000000001ULL<<19))
#define ENT_PACKET            (DM_ENTITY    | (0x0000000000000001ULL<<20))
#define ENT_DISC              (DM_ENTITY    | (0x0000000000000001ULL<<21))
#define ENT_IATTR             (DM_ENTITY    | (0x0000000000000001ULL<<22))
#define ENT_XATTR             (DM_ENTITY    | (0x0000000000000001ULL<<23))
#define ENT_PCKCNT            (DM_ENTITY    | (0x0000000000000001ULL<<24))
#define ENT_ARG               (DM_ENTITY    | (0x0000000000000001ULL<<25))
#define ENT_ENV               (DM_ENTITY    | (0x0000000000000001ULL<<26))

#define prov_type(prov) ((prov)->node_info.identifier.node_id.type)
#define node_type(node) prov_type(node)
#define edge_type(edge) prov_type(edge)
#define prov_is_relation(prov) ((relation_identifier(prov).type & DM_RELATION) != 0)
#define prov_is_node(prov) ((node_identifier(prov).type & DM_RELATION) == 0)

#define prov_is_type(val, type) ((val&type)==type)
#define prov_is_used(val) prov_is_type(type, RL_USED)
#define prov_is_informed(val) prov_is_type(val, RL_INFORMED)
#define prov_is_generated(val) prov_is_type(val, RL_GENERATED)
#define prov_is_derived(val) prov_is_type(val, RL_DERIVED)

static inline bool prov_has_uidgid(uint64_t type)
{
	switch (type) {
  	case ACT_TASK:
  	case ENT_INODE_UNKNOWN:
  	case ENT_INODE_LINK:
  	case ENT_INODE_FILE:
  	case ENT_INODE_DIRECTORY:
  	case ENT_INODE_CHAR:
  	case ENT_INODE_BLOCK:
  	case ENT_INODE_FIFO:
  	case ENT_INODE_SOCKET:
  	case ENT_INODE_MMAP:
  		return true;
  	default: return false;
	}
}

static inline bool prov_is_inode(uint64_t type)
{
	switch (type) {
  	case ENT_INODE_UNKNOWN:
  	case ENT_INODE_LINK:
  	case ENT_INODE_FILE:
  	case ENT_INODE_DIRECTORY:
  	case ENT_INODE_CHAR:
  	case ENT_INODE_BLOCK:
  	case ENT_INODE_FIFO:
  	case ENT_INODE_SOCKET:
  	case ENT_INODE_MMAP:
  		return true;
  	default: return false;
	}
}

static inline bool prov_has_secid(uint64_t type)
{
	switch (type) {
	case ACT_TASK:
	case ENT_INODE_UNKNOWN:
	case ENT_INODE_LINK:
	case ENT_INODE_FILE:
	case ENT_INODE_DIRECTORY:
	case ENT_INODE_CHAR:
	case ENT_INODE_BLOCK:
	case ENT_INODE_FIFO:
	case ENT_INODE_SOCKET:
	case ENT_INODE_MMAP:
		return true;
	default: return false;
	}
}

struct prov_type{
  uint64_t id;
  char str[256];
  uint8_t is_relation;
};

#endif //_UAPI_LINUX_PROVENANCE_TYPES_H
