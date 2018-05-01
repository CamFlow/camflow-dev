/*
 *
 * Author: Thomas Pasquier <thomas.pasquier@cl.cam.ac.uk>
 *
 * Copyright (C) 2015-2018 University of Cambridge, Harvard University
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 */
#include <linux/provenance_types.h>
#include "provenance.h"

/* reation string name */
static const char RL_STR_UNKNOWN[]               = "unknown";
static const char RL_STR_READ[]                  = "read";
static const char RL_STR_READ_IOCTL[]            = "read_ioctl";
static const char RL_STR_WRITE[]                 = "write";
static const char RL_STR_WRITE_IOCTL[]           = "write";
static const char RL_STR_CLONE_MEM[]             = "clone_mem";
static const char RL_STR_MSG_CREATE[]            = "msg_create";
static const char RL_STR_SOCKET_CREATE[]         = "socket_create";
static const char RL_STR_INODE_CREATE[]          = "inode_create";
static const char RL_STR_SETUID[]                = "setuid";
static const char RL_STR_SETGID[]                = "setgid";
static const char RL_STR_MMAP_WRITE[]            = "mmap_write";
static const char RL_STR_SH_WRITE[]              = "sh_write";
static const char RL_STR_PROC_WRITE[]            = "proc_write";
static const char RL_STR_BIND[]                  = "bind";
static const char RL_STR_CONNECT[]               = "connect";
static const char RL_STR_LISTEN[]                = "listen";
static const char RL_STR_ACCEPT[]                = "accept";
static const char RL_STR_OPEN[]                  = "open";
static const char RL_STR_FILE_RCV[]              = "file_rcv";
static const char RL_STR_VERSION[]               = "version_entity";
static const char RL_STR_MMAP[]                  = "mmap";
static const char RL_STR_MUNMAP[]                = "munmap";
static const char RL_STR_SHMDT[]                 = "shmdt";
static const char RL_STR_LINK[]                  = "link";
static const char RL_STR_LINK_INODE[]            = "link_inode";
static const char RL_STR_SPLICE[]                = "splice";
static const char RL_STR_SETATTR[]               = "setattr";
static const char RL_STR_SETATTR_INODE[]         = "setattr_inode";
static const char RL_STR_ACCEPT_SOCKET[]         = "accept_socket";
static const char RL_STR_SETXATTR[]              = "setxattr";
static const char RL_STR_SETXATTR_INODE[]        = "setxattr_inode";
static const char RL_STR_RMVXATTR[]              = "removexattr";
static const char RL_STR_RMVXATTR_INODE[]        = "removexattr_inode";
static const char RL_STR_NAMED[]                 = "named";
static const char RL_STR_NAMED_PROCESS[]         = "named_process";
static const char RL_STR_EXEC[]                  = "exec";
static const char RL_STR_EXEC_TASK[]             = "exec_task";
static const char RL_STR_PCK_CNT[]             	 = "packet_content";
static const char RL_STR_CLONE[]                 = "clone";
static const char RL_STR_VERSION_TASK[]          = "version_activity";
static const char RL_STR_SEARCH[]                = "search";
static const char RL_STR_GETATTR[]               = "getattr";
static const char RL_STR_GETXATTR[]              = "getxattr";
static const char RL_STR_GETXATTR_INODE[]        = "getxattr_inode";
static const char RL_STR_LSTXATTR[]              = "listxattr";
static const char RL_STR_READ_LINK[]             = "read_link";
static const char RL_STR_MMAP_READ[]             = "mmap_read";
static const char RL_STR_SH_READ[]               = "sh_read";
static const char RL_STR_PROC_READ[]             = "proc_read";
static const char RL_STR_MMAP_EXEC[]             = "mmap_exec";
static const char RL_STR_SND[]                   = "send";
static const char RL_STR_SND_PACKET[]            = "send_packet";
static const char RL_STR_SND_UNIX[]              = "send_unix";
static const char RL_STR_SND_MSG[]               = "send_msg";
static const char RL_STR_SND_MSG_Q[]             = "send_msg_queue";
static const char RL_STR_RCV[]                   = "receive";
static const char RL_STR_RCV_PACKET[]            = "receive_packet";
static const char RL_STR_RCV_UNIX[]              = "receive_unix";
static const char RL_STR_RCV_MSG[]               = "receive_msg";
static const char RL_STR_RCV_MSG_Q[]             = "receive_msg_queue";
static const char RL_STR_PERM_READ[]             = "perm_read";
static const char RL_STR_PERM_WRITE[]            = "perm_write";
static const char RL_STR_PERM_EXEC[]             = "perm_exec";
static const char RL_STR_TERMINATE_TASK[]        = "terminate_task";
static const char RL_STR_TERMINATE_PROC[]        = "terminate_proc";
static const char RL_STR_CLOSED[]                = "closed";
static const char RL_STR_ARG[]                   = "arg";
static const char RL_STR_ENV[]                   = "env";
static const char RL_STR_LOG[]                   = "log";
static const char RL_STR_SH_ATTACH_READ[]        = "sh_attach_read";
static const char RL_STR_SH_ATTACH_WRITE[]       = "sh_attach_write";
static const char RL_STR_SH_CREATE_READ[]        = "sh_create_read";
static const char RL_STR_SH_CREATE_WRITE[]       = "sh_create_write";

/* node string name */
static const char ND_STR_UNKNOWN[]                           = "unknown";
static const char ND_STR_STR[]                               = "string";
static const char ND_STR_TASK[]                              = "task";
static const char ND_STR_INODE_UNKNOWN[]                     = "inode_unknown";
static const char ND_STR_INODE_LINK[]                        = "link";
static const char ND_STR_INODE_FILE[]                        = "file";
static const char ND_STR_INODE_DIRECTORY[]                   = "directory";
static const char ND_STR_INODE_CHAR[]                        = "char";
static const char ND_STR_INODE_BLOCK[]                       = "block";
static const char ND_STR_INODE_FIFO[]                        = "fifo";
static const char ND_STR_INODE_SOCKET[]                      = "socket";
static const char ND_STR_MSG[]                               = "msg";
static const char ND_STR_SHM[]                               = "shm";
static const char ND_STR_ADDR[]                              = "address";
static const char ND_STR_SB[]                                = "sb";
static const char ND_STR_FILE_NAME[]                         = "file_name";
static const char ND_STR_DISC_ENTITY[]                       = "disc_entity";
static const char ND_STR_DISC_ACTIVITY[]                     = "disc_activity";
static const char ND_STR_DISC_AGENT[]                        = "disc_agent";
static const char ND_STR_PACKET[]                            = "packet";
static const char ND_STR_INODE_MMAP[]                        = "mmaped_file";
static const char ND_STR_IATTR[]                             = "iattr";
static const char ND_STR_XATTR[]                             = "xattr";
static const char ND_STR_PCKCNT[]                            = "packet_content";
static const char ND_STR_ARG[]                               = "argv";
static const char ND_STR_ENV[]                               = "envp";
static const char ND_STR_PROC[]                              = "process";

#define MATCH_AND_RETURN(str1, str2, v) if (strcmp(str1, str2) == 0) return v
/* transform from relation ID to string representation */
const char* relation_str(uint64_t type)
{
	switch (type) {
	case RL_READ:
		return RL_STR_READ;
	case RL_READ_IOCTL:
		return RL_STR_READ_IOCTL;
	case RL_WRITE:
		return RL_STR_WRITE;
	case RL_WRITE_IOCTL:
		return RL_STR_WRITE_IOCTL;
	case RL_CLONE_MEM:
		return RL_STR_CLONE_MEM;
	case RL_MSG_CREATE:
		return RL_STR_MSG_CREATE;
	case RL_SOCKET_CREATE:
		return RL_STR_SOCKET_CREATE;
	case RL_INODE_CREATE:
		return RL_STR_INODE_CREATE;
	case RL_SETUID:
		return RL_STR_SETUID;
	case RL_SETGID:
		return RL_STR_SETGID;
	case RL_MMAP_WRITE:
		return RL_STR_MMAP_WRITE;
	case RL_BIND:
		return RL_STR_BIND;
	case RL_CONNECT:
		return RL_STR_CONNECT;
	case RL_LISTEN:
		return RL_STR_LISTEN;
	case RL_ACCEPT:
		return RL_STR_ACCEPT;
	case RL_OPEN:
		return RL_STR_OPEN;
	case RL_FILE_RCV:
		return RL_STR_FILE_RCV;
	case RL_VERSION:
		return RL_STR_VERSION;
	case RL_MMAP:
		return RL_STR_MMAP;
	case RL_MUNMAP:
		return RL_STR_MUNMAP;
	case RL_SHMDT:
		return RL_STR_SHMDT;
	case RL_LINK:
		return RL_STR_LINK;
	case RL_LINK_INODE:
		return RL_STR_LINK_INODE;
	case RL_SPLICE:
		return RL_STR_SPLICE;
	case RL_SETATTR:
		return RL_STR_SETATTR;
	case RL_SETATTR_INODE:
		return RL_STR_SETATTR_INODE;
	case RL_ACCEPT_SOCKET:
		return RL_STR_ACCEPT_SOCKET;
	case RL_SETXATTR:
		return RL_STR_SETXATTR;
	case RL_SETXATTR_INODE:
		return RL_STR_SETXATTR_INODE;
	case RL_RMVXATTR:
		return RL_STR_RMVXATTR;
	case RL_RMVXATTR_INODE:
		return RL_STR_RMVXATTR_INODE;
	case RL_NAMED:
		return RL_STR_NAMED;
	case RL_NAMED_PROCESS:
		return RL_STR_NAMED_PROCESS;
	case RL_EXEC:
		return RL_STR_EXEC;
	case RL_EXEC_TASK:
		return RL_STR_EXEC_TASK;
	case RL_PCK_CNT:
		return RL_STR_PCK_CNT;
	case RL_CLONE:
		return RL_STR_CLONE;
	case RL_VERSION_TASK:
		return RL_STR_VERSION_TASK;
	case RL_SEARCH:
		return RL_STR_SEARCH;
	case RL_GETATTR:
		return RL_STR_GETATTR;
	case RL_GETXATTR:
		return RL_STR_GETXATTR;
	case RL_GETXATTR_INODE:
		return RL_STR_GETXATTR_INODE;
	case RL_LSTXATTR:
		return RL_STR_LSTXATTR;
	case RL_READ_LINK:
		return RL_STR_READ_LINK;
	case RL_MMAP_READ:
		return RL_STR_MMAP_READ;
	case RL_MMAP_EXEC:
		return RL_STR_MMAP_EXEC;
	case RL_SND:
		return RL_STR_SND;
	case RL_SND_PACKET:
		return RL_STR_SND_PACKET;
	case RL_SND_UNIX:
		return RL_STR_SND_UNIX;
	case RL_SND_MSG:
		return RL_STR_SND_MSG;
	case RL_SND_MSG_Q:
		return RL_STR_SND_MSG_Q;
	case RL_RCV:
		return RL_STR_RCV;
	case RL_RCV_PACKET:
		return RL_STR_RCV_PACKET;
	case RL_RCV_UNIX:
		return RL_STR_RCV_UNIX;
	case RL_RCV_MSG:
		return RL_STR_RCV_MSG;
	case RL_RCV_MSG_Q:
		return RL_STR_RCV_MSG_Q;
	case RL_PERM_READ:
		return RL_STR_PERM_READ;
	case RL_PERM_WRITE:
		return RL_STR_PERM_WRITE;
	case RL_SH_READ:
		return RL_STR_SH_READ;
	case RL_PROC_READ:
		return RL_STR_PROC_READ;
	case RL_SH_WRITE:
		return RL_STR_SH_WRITE;
	case RL_PROC_WRITE:
		return RL_STR_PROC_WRITE;
	case RL_PERM_EXEC:
		return RL_STR_PERM_EXEC;
	case RL_TERMINATE_TASK:
		return RL_STR_TERMINATE_TASK;
	case RL_TERMINATE_PROC:
		return RL_STR_TERMINATE_PROC;
	case RL_CLOSED:
		return RL_STR_CLOSED;
	case RL_ARG:
		return RL_STR_ARG;
	case RL_ENV:
		return RL_STR_ENV;
	case RL_LOG:
		return RL_STR_LOG;
	case RL_SH_ATTACH_READ:
		return RL_STR_SH_ATTACH_READ;
	case RL_SH_ATTACH_WRITE:
		return RL_STR_SH_ATTACH_WRITE;
	case RL_SH_CREATE_READ:
		return RL_STR_SH_CREATE_READ;
	case RL_SH_CREATE_WRITE:
		return RL_STR_SH_CREATE_WRITE;
	default:
		return RL_STR_UNKNOWN;
	}
}
EXPORT_SYMBOL_GPL(relation_str);

/* from string representation to relation ID */
uint64_t relation_id(const char* str)
{
	MATCH_AND_RETURN(str, RL_STR_READ, RL_READ);
	MATCH_AND_RETURN(str, RL_STR_READ_IOCTL, RL_READ_IOCTL);
	MATCH_AND_RETURN(str, RL_STR_WRITE, RL_WRITE);
	MATCH_AND_RETURN(str, RL_STR_WRITE_IOCTL, RL_WRITE_IOCTL);
	MATCH_AND_RETURN(str, RL_STR_CLONE_MEM, RL_CLONE_MEM);
	MATCH_AND_RETURN(str, RL_STR_MSG_CREATE, RL_MSG_CREATE);
	MATCH_AND_RETURN(str, RL_STR_SOCKET_CREATE, RL_SOCKET_CREATE);
	MATCH_AND_RETURN(str, RL_STR_INODE_CREATE, RL_INODE_CREATE);
	MATCH_AND_RETURN(str, RL_STR_SETUID, RL_SETUID);
	MATCH_AND_RETURN(str, RL_STR_SETGID, RL_SETGID);
	MATCH_AND_RETURN(str, RL_STR_MMAP_WRITE, RL_MMAP_WRITE);
	MATCH_AND_RETURN(str, RL_STR_BIND, RL_BIND);
	MATCH_AND_RETURN(str, RL_STR_CONNECT, RL_CONNECT);
	MATCH_AND_RETURN(str, RL_STR_LISTEN, RL_LISTEN);
	MATCH_AND_RETURN(str, RL_STR_ACCEPT, RL_ACCEPT);
	MATCH_AND_RETURN(str, RL_STR_OPEN, RL_OPEN);
	MATCH_AND_RETURN(str, RL_STR_FILE_RCV, RL_FILE_RCV);
	MATCH_AND_RETURN(str, RL_STR_VERSION, RL_VERSION);
	MATCH_AND_RETURN(str, RL_STR_MMAP, RL_MMAP);
	MATCH_AND_RETURN(str, RL_STR_MUNMAP, RL_MUNMAP);
	MATCH_AND_RETURN(str, RL_STR_SHMDT, RL_SHMDT);
	MATCH_AND_RETURN(str, RL_STR_LINK, RL_LINK);
	MATCH_AND_RETURN(str, RL_STR_LINK_INODE, RL_LINK_INODE);
	MATCH_AND_RETURN(str, RL_STR_SPLICE, RL_SPLICE);
	MATCH_AND_RETURN(str, RL_STR_SETATTR, RL_SETATTR);
	MATCH_AND_RETURN(str, RL_STR_SETATTR_INODE, RL_SETATTR_INODE);
	MATCH_AND_RETURN(str, RL_STR_ACCEPT_SOCKET, RL_ACCEPT_SOCKET);
	MATCH_AND_RETURN(str, RL_STR_SETXATTR, RL_SETXATTR);
	MATCH_AND_RETURN(str, RL_STR_SETXATTR_INODE, RL_SETXATTR_INODE);
	MATCH_AND_RETURN(str, RL_STR_RMVXATTR, RL_RMVXATTR);
	MATCH_AND_RETURN(str, RL_STR_RMVXATTR_INODE, RL_RMVXATTR_INODE);
	MATCH_AND_RETURN(str, RL_STR_READ_LINK, RL_READ_LINK);
	MATCH_AND_RETURN(str, RL_STR_NAMED, RL_NAMED);
	MATCH_AND_RETURN(str, RL_STR_NAMED_PROCESS, RL_NAMED_PROCESS);
	MATCH_AND_RETURN(str, RL_STR_EXEC, RL_EXEC);
	MATCH_AND_RETURN(str, RL_STR_EXEC_TASK, RL_EXEC_TASK);
	MATCH_AND_RETURN(str, RL_STR_PCK_CNT, RL_PCK_CNT);
	MATCH_AND_RETURN(str, RL_STR_CLONE, RL_CLONE);
	MATCH_AND_RETURN(str, RL_STR_VERSION_TASK, RL_VERSION_TASK);
	MATCH_AND_RETURN(str, RL_STR_SEARCH, RL_SEARCH);
	MATCH_AND_RETURN(str, RL_STR_GETATTR, RL_GETATTR);
	MATCH_AND_RETURN(str, RL_STR_GETXATTR, RL_GETXATTR);
	MATCH_AND_RETURN(str, RL_STR_GETXATTR_INODE, RL_GETXATTR_INODE);
	MATCH_AND_RETURN(str, RL_STR_LSTXATTR, RL_LSTXATTR);
	MATCH_AND_RETURN(str, RL_STR_MMAP_READ, RL_MMAP_READ);
	MATCH_AND_RETURN(str, RL_STR_MMAP_EXEC, RL_MMAP_EXEC);
	MATCH_AND_RETURN(str, RL_STR_SND, RL_SND);
	MATCH_AND_RETURN(str, RL_STR_SND_PACKET, RL_SND_PACKET);
	MATCH_AND_RETURN(str, RL_STR_SND_UNIX, RL_SND_UNIX);
	MATCH_AND_RETURN(str, RL_STR_SND_MSG, RL_SND_MSG);
	MATCH_AND_RETURN(str, RL_STR_SND_MSG_Q, RL_SND_MSG_Q);
	MATCH_AND_RETURN(str, RL_STR_RCV, RL_RCV);
	MATCH_AND_RETURN(str, RL_STR_RCV_PACKET, RL_RCV_PACKET);
	MATCH_AND_RETURN(str, RL_STR_RCV_UNIX, RL_RCV_UNIX);
	MATCH_AND_RETURN(str, RL_STR_RCV_MSG, RL_RCV_MSG);
	MATCH_AND_RETURN(str, RL_STR_RCV_MSG_Q, RL_RCV_MSG_Q);
	MATCH_AND_RETURN(str, RL_STR_PERM_READ, RL_PERM_READ);
	MATCH_AND_RETURN(str, RL_STR_PERM_WRITE, RL_PERM_WRITE);
	MATCH_AND_RETURN(str, RL_STR_PERM_EXEC, RL_PERM_EXEC);
	MATCH_AND_RETURN(str, RL_STR_SH_READ, RL_SH_READ);
	MATCH_AND_RETURN(str, RL_STR_PROC_READ, RL_PROC_READ);
	MATCH_AND_RETURN(str, RL_STR_SH_WRITE, RL_SH_WRITE);
	MATCH_AND_RETURN(str, RL_STR_PROC_WRITE, RL_PROC_WRITE);
	MATCH_AND_RETURN(str, RL_STR_TERMINATE_TASK, RL_TERMINATE_TASK);
	MATCH_AND_RETURN(str, RL_STR_TERMINATE_PROC, RL_TERMINATE_PROC);
	MATCH_AND_RETURN(str, RL_STR_CLOSED, RL_CLOSED);
	MATCH_AND_RETURN(str, RL_STR_ARG, RL_ARG);
	MATCH_AND_RETURN(str, RL_STR_ENV, RL_ENV);
	MATCH_AND_RETURN(str, RL_STR_LOG, RL_LOG);
	MATCH_AND_RETURN(str, RL_STR_SH_ATTACH_READ, RL_SH_ATTACH_READ);
	MATCH_AND_RETURN(str, RL_STR_SH_ATTACH_WRITE, RL_SH_ATTACH_WRITE);
	MATCH_AND_RETURN(str, RL_STR_SH_CREATE_READ, RL_SH_CREATE_READ);
	MATCH_AND_RETURN(str, RL_STR_SH_CREATE_WRITE, RL_SH_CREATE_WRITE);
	return 0;
}
EXPORT_SYMBOL_GPL(relation_id);

/* from node ID to string representation */
const char* node_str(uint64_t type)
{
	switch (type) {
	case ENT_STR:
		return ND_STR_STR;
	case ACT_TASK:
		return ND_STR_TASK;
	case ENT_INODE_UNKNOWN:
		return ND_STR_INODE_UNKNOWN;
	case ENT_INODE_LINK:
		return ND_STR_INODE_LINK;
	case ENT_INODE_FILE:
		return ND_STR_INODE_FILE;
	case ENT_INODE_DIRECTORY:
		return ND_STR_INODE_DIRECTORY;
	case ENT_INODE_CHAR:
		return ND_STR_INODE_CHAR;
	case ENT_INODE_BLOCK:
		return ND_STR_INODE_BLOCK;
	case ENT_INODE_FIFO:
		return ND_STR_INODE_FIFO;
	case ENT_INODE_SOCKET:
		return ND_STR_INODE_SOCKET;
	case ENT_INODE_MMAP:
		return ND_STR_INODE_MMAP;
	case ENT_MSG:
		return ND_STR_MSG;
	case ENT_SHM:
		return ND_STR_SHM;
	case ENT_ADDR:
		return ND_STR_ADDR;
	case ENT_SBLCK:
		return ND_STR_SB;
	case ENT_FILE_NAME:
		return ND_STR_FILE_NAME;
	case ENT_DISC:
		return ND_STR_DISC_ENTITY;
	case ACT_DISC:
		return ND_STR_DISC_ACTIVITY;
	case AGT_DISC:
		return ND_STR_DISC_AGENT;
	case ENT_PACKET:
		return ND_STR_PACKET;
	case ENT_IATTR:
		return ND_STR_IATTR;
	case ENT_XATTR:
		return ND_STR_XATTR;
	case ENT_PCKCNT:
		return ND_STR_PCKCNT;
	case ENT_ARG:
		return ND_STR_ARG;
	case ENT_ENV:
		return ND_STR_ENV;
	case ENT_PROC:
		return ND_STR_PROC;
	default:
		return ND_STR_UNKNOWN;
	}
}
EXPORT_SYMBOL_GPL(node_str);

/* from string to node ID representation */
uint64_t node_id(const char* str)
{
	MATCH_AND_RETURN(str, ND_STR_TASK, ACT_TASK);
	MATCH_AND_RETURN(str, ND_STR_INODE_UNKNOWN, ENT_INODE_UNKNOWN);
	MATCH_AND_RETURN(str, ND_STR_INODE_LINK, ENT_INODE_LINK);
	MATCH_AND_RETURN(str, ND_STR_INODE_FILE, ENT_INODE_FILE);
	MATCH_AND_RETURN(str, ND_STR_INODE_DIRECTORY, ENT_INODE_DIRECTORY);
	MATCH_AND_RETURN(str, ND_STR_INODE_CHAR, ENT_INODE_CHAR);
	MATCH_AND_RETURN(str, ND_STR_INODE_BLOCK, ENT_INODE_BLOCK);
	MATCH_AND_RETURN(str, ND_STR_INODE_FIFO, ENT_INODE_FIFO);
	MATCH_AND_RETURN(str, ND_STR_INODE_SOCKET, ENT_INODE_SOCKET);
	MATCH_AND_RETURN(str, ND_STR_INODE_MMAP, ENT_INODE_MMAP);
	MATCH_AND_RETURN(str, ND_STR_MSG, ENT_MSG);
	MATCH_AND_RETURN(str, ND_STR_SHM, ENT_SHM);
	MATCH_AND_RETURN(str, ND_STR_ADDR, ENT_ADDR);
	MATCH_AND_RETURN(str, ND_STR_SB, ENT_SBLCK);
	MATCH_AND_RETURN(str, ND_STR_FILE_NAME, ENT_FILE_NAME);
	MATCH_AND_RETURN(str, ND_STR_DISC_ENTITY, ENT_DISC);
	MATCH_AND_RETURN(str, ND_STR_DISC_ACTIVITY, ACT_DISC);
	MATCH_AND_RETURN(str, ND_STR_DISC_AGENT, AGT_DISC);
	MATCH_AND_RETURN(str, ND_STR_PACKET, ENT_PACKET);
	MATCH_AND_RETURN(str, ND_STR_IATTR, ENT_IATTR);
	MATCH_AND_RETURN(str, ND_STR_XATTR, ENT_XATTR);
	MATCH_AND_RETURN(str, ND_STR_PCKCNT, ENT_PCKCNT);
	MATCH_AND_RETURN(str, ND_STR_ARG, ENT_ARG);
	MATCH_AND_RETURN(str, ND_STR_ENV, ENT_ENV);
	MATCH_AND_RETURN(str, ND_STR_PROC, ENT_PROC);
	return 0;
}
EXPORT_SYMBOL_GPL(node_id);
