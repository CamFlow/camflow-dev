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

#ifndef _UAPI_LINUX_PROVENANCE_FS_H
#define _UAPI_LINUX_PROVENANCE_FS_H

#include <linux/provenance.h>

 #define PROV_SEC_PATH                           "/sys/kernel/security/provenance/"
 #define PROV_ENABLE_FILE                        "/sys/kernel/security/provenance/enable"
 #define PROV_ALL_FILE                           "/sys/kernel/security/provenance/all"
 #define PROV_WRITTEN_FILE                       "/sys/kernel/security/provenance/written"
 #define PROV_COMPRESS_NODE_FILE                 "/sys/kernel/security/provenance/compress_node"
 #define PROV_COMPRESS_EDGE_FILE                 "/sys/kernel/security/provenance/compress_edge"
 #define PROV_NODE_FILE                          "/sys/kernel/security/provenance/node"
 #define PROV_RELATION_FILE                      "/sys/kernel/security/provenance/relation"
 #define PROV_SELF_FILE                          "/sys/kernel/security/provenance/self"
 #define PROV_MACHINE_ID_FILE                    "/sys/kernel/security/provenance/machine_id"
 #define PROV_BOOT_ID_FILE                       "/sys/kernel/security/provenance/boot_id"
 #define PROV_NODE_FILTER_FILE                   "/sys/kernel/security/provenance/node_filter"
 #define PROV_DERIVED_FILTER_FILE                "/sys/kernel/security/provenance/derived_filter"
 #define PROV_GENERATED_FILTER_FILE              "/sys/kernel/security/provenance/generated_filter"
 #define PROV_USED_FILTER_FILE                   "/sys/kernel/security/provenance/used_filter"
 #define PROV_INFORMED_FILTER_FILE               "/sys/kernel/security/provenance/informed_filter"
 #define PROV_PROPAGATE_NODE_FILTER_FILE         "/sys/kernel/security/provenance/propagate_node_filter"
 #define PROV_PROPAGATE_DERIVED_FILTER_FILE      "/sys/kernel/security/provenance/propagate_derived_filter"
 #define PROV_PROPAGATE_GENERATED_FILTER_FILE    "/sys/kernel/security/provenance/propagate_generated_filter"
 #define PROV_PROPAGATE_USED_FILTER_FILE         "/sys/kernel/security/provenance/propagate_used_filter"
 #define PROV_PROPAGATE_INFORMED_FILTER_FILE     "/sys/kernel/security/provenance/propagate_informed_filter"
 #define PROV_FLUSH_FILE                         "/sys/kernel/security/provenance/flush"
 #define PROV_PROCESS_FILE                       "/sys/kernel/security/provenance/process"
 #define PROV_IPV4_INGRESS_FILE                  "/sys/kernel/security/provenance/ipv4_ingress"
 #define PROV_IPV4_EGRESS_FILE                   "/sys/kernel/security/provenance/ipv4_egress"
 #define PROV_SECCTX                             "/sys/kernel/security/provenance/secctx"
 #define PROV_SECCTX_FILTER                      "/sys/kernel/security/provenance/secctx_filter"
 #define PROV_NS_FILTER                          "/sys/kernel/security/provenance/ns"
 #define PROV_LOG_FILE                           "/sys/kernel/security/provenance/log"
 #define PROV_LOGP_FILE                          "/sys/kernel/security/provenance/logp"
 #define PROV_POLICY_HASH_FILE                   "/sys/kernel/security/provenance/policy_hash"
 #define PROV_UID_FILTER                         "/sys/kernel/security/provenance/uid"
 #define PROV_GID_FILTER                         "/sys/kernel/security/provenance/gid"
 #define PROV_TYPE                               "/sys/kernel/security/provenance/type"
 #define PROV_VERSION                            "/sys/kernel/security/provenance/version"
 #define PROV_COMMIT                             "/sys/kernel/security/provenance/commit"
 #define PROV_CHANNEL                            "/sys/kernel/security/provenance/channel"
 #define PROV_DUPLICATE_FILE                     "/sys/kernel/security/provenance/duplicate"
 #define PROV_EPOCH_FILE                         "/sys/kernel/security/provenance/epoch"

 #define PROV_RELAY_NAME                         "/sys/kernel/debug/provenance"
 #define PROV_LONG_RELAY_NAME                    "/sys/kernel/debug/long_provenance"
 #define PROV_CHANNEL_ROOT                       "/sys/kernel/debug/"

struct prov_filter {
	uint64_t filter;
	uint64_t mask;
	uint8_t add;
};

 #define PROV_SET_TRACKED        0x01
 #define PROV_SET_OPAQUE         0x02
 #define PROV_SET_PROPAGATE      0x04
 #define PROV_SET_TAINT          0x08
 #define PROV_SET_DELETE         0x10
 #define PROV_SET_RECORD         0x20

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

 #define IGNORE_NS    0

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
