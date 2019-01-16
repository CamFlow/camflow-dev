/*
 *
 * Author: Thomas Pasquier <thomas.pasquier@bristol.ac.uk>
 *
 * Copyright (C) 2015-2019 University of Cambridge, Harvard University, University of Bristol
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 */
#include <linux/provenance_types.h>
#include "provenance.h"

/* relation string name */
static const char RL_STR_UNKNOWN[] = "unknown";                         // unknown relation should not happen
static const char RL_STR_READ[] = "read";                               // read to inode
static const char RL_STR_READ_IOCTL[] = "read_ioctl";                   // ioctl read
static const char RL_STR_WRITE[] = "write";                             // write to inode
static const char RL_STR_WRITE_IOCTL[] = "write_ioctl";                 // ioctl write
static const char RL_STR_CLONE_MEM[] = "clone_mem";                     // memory copy on clone
static const char RL_STR_MSG_CREATE[] = "msg_create";                   // create msg (IPC message passing)
static const char RL_STR_SOCKET_CREATE[] = "socket_create";             // create socket
static const char RL_STR_SOCKET_PAIR_CREATE[] = "socket_pair_create";   // create socket pair
static const char RL_STR_INODE_CREATE[] = "inode_create";               // create inode
static const char RL_STR_SETUID[] = "setuid";                           // setuid
static const char RL_STR_SETGID[] = "setpgid";                          // setpgid
static const char RL_STR_GETGID[] = "getpgid";                          // getpgid
static const char RL_STR_SH_WRITE[] = "sh_write";                       // writing to shared state
static const char RL_STR_PROC_WRITE[] = "memory_write";                 // writing to process memory (i.e. shared between thread)
static const char RL_STR_BIND[] = "bind";                               // socket bind operation
static const char RL_STR_CONNECT[] = "connect";                         // socket connection operation
static const char RL_STR_LISTEN[] = "listen";                           // socket listen operation
static const char RL_STR_ACCEPT[] = "accept";                           // socket accept operation
static const char RL_STR_OPEN[] = "open";                               // file open operation
static const char RL_STR_FILE_RCV[] = "file_rcv";                       // open file descriptor recevied through IPC
static const char RL_STR_FILE_LOCK[] = "file_lock";                     // represent file lock operation
static const char RL_STR_FILE_SIGIO[] = "file_sigio";                   // represent IO signal
static const char RL_STR_VERSION[] = "version_entity";                  // connect version of entity object
static const char RL_STR_MUNMAP[] = "munmap";                           // munmap operation
static const char RL_STR_SHMDT[] = "shmdt";                             // shmdt operation
static const char RL_STR_LINK[] = "link";                               // create a link
static const char RL_STR_UNLINK[] = "unlink";                           // delete a link
static const char RL_STR_SYMLINK[] = "symlink";                         // create a symlink
static const char RL_STR_SPLICE_IN[] = "splice_in";                     // pipe splice operation from in file
static const char RL_STR_SPLICE_OUT[] = "splice_out";                   // pipe splice operation to out file
static const char RL_STR_SETATTR[] = "setattr";                         // setattr operation (task -> iattr)
static const char RL_STR_SETATTR_INODE[] = "setattr_inode";             // setattr operation (iattr -> inode)
static const char RL_STR_ACCEPT_SOCKET[] = "accept_socket";             // accept operation (parent -> child socket)
static const char RL_STR_SETXATTR[] = "setxattr";                       // setxattr operation (task -> xattr)
static const char RL_STR_SETXATTR_INODE[] = "setxattr_inode";           // setxattr operation (xattr -> inode)
static const char RL_STR_RMVXATTR[] = "removexattr";                    // remove xattr operation (task -> xattr)
static const char RL_STR_RMVXATTR_INODE[] = "removexattr_inode";        // remove xattr operation (xattr -> inode)
static const char RL_STR_NAMED[] = "named";                             // connect path to inode
static const char RL_STR_NAMED_PROCESS[] = "named_process";             // connect path to process_memory
static const char RL_STR_EXEC[] = "exec";                               // exec operation
static const char RL_STR_EXEC_TASK[] = "exec_task";                     // exec operation
static const char RL_STR_PCK_CNT[] = "packet_content";                  // connect netwrok packet to its content
static const char RL_STR_CLONE[] = "clone";                             // clone operation
static const char RL_STR_VERSION_TASK[] = "version_activity";           // connection two versions of an activity
static const char RL_STR_SEARCH[] = "search";                           // search operation on directory
static const char RL_STR_GETATTR[] = "getattr";                         // getattr operation
static const char RL_STR_GETXATTR[] = "getxattr";                       // getxattr operation (xattr -> process)
static const char RL_STR_GETXATTR_INODE[] = "getxattr_inode";           // getxattr operation (inode -> xattr)
static const char RL_STR_LSTXATTR[] = "listxattr";                      // listxattr operation
static const char RL_STR_READ_LINK[] = "read_link";                     // readlink operation
static const char RL_STR_MMAP_READ[] = "mmap_read";                     // mmap mounting with read perm
static const char RL_STR_MMAP_EXEC[] = "mmap_exec";                     // mmap mounting with exec perm
static const char RL_STR_MMAP_WRITE[] = "mmap_write";                   // mmap mounting with write perm
static const char RL_STR_MMAP_READ_PRIVATE[] = "mmap_read_private";     // mmap private mounting with read perm
static const char RL_STR_MMAP_EXEC_PRIVATE[] = "mmap_exec_private";     // mmap private mounting with exec perm
static const char RL_STR_MMAP_WRITE_PRIVATE[] = "mmap_write_private";   // mmap private  mounting with write perm
static const char RL_STR_SH_READ[] = "sh_read";                         // sh_read operation
static const char RL_STR_PROC_READ[] = "memory_read";                   // read from process memory
static const char RL_STR_SND[] = "send";                                // send over socket
static const char RL_STR_SND_PACKET[] = "send_packet";                  // connect socket to packet on send operation
static const char RL_STR_SND_UNIX[] = "send_unix";                      // send over unix socket
static const char RL_STR_SND_MSG[] = "send_msg";                        // send message
static const char RL_STR_SND_MSG_Q[] = "send_msg_queue";                // send message to queue
static const char RL_STR_RCV[] = "receive";                             // receive socket operation
static const char RL_STR_RCV_PACKET[] = "receive_packet";               // connect packet to socket on receive operation
static const char RL_STR_RCV_UNIX[] = "receive_unix";                   // receive on unix socket
static const char RL_STR_RCV_MSG[] = "receive_msg";                     // receive message
static const char RL_STR_RCV_MSG_Q[] = "receive_msg_queue";             // receive message from queue
static const char RL_STR_PERM_READ[] = "perm_read";                     // check read permission
static const char RL_STR_PERM_WRITE[] = "perm_write";                   // check write permission
static const char RL_STR_PERM_EXEC[] = "perm_exec";                     // check exec permission
static const char RL_STR_PERM_APPEND[] = "perm_append";                 // check append permission
static const char RL_STR_TERMINATE_TASK[] = "terminate_task";           // created when task data structure is freed
static const char RL_STR_TERMINATE_PROC[] = "terminate_proc";           // created when cred data structure is freed
static const char RL_STR_FREED[] = "free";                              // created when an inode is freed
static const char RL_STR_ARG[] = "arg";                                 // connect arg value to process
static const char RL_STR_ENV[] = "env";                                 // connect env value to process
static const char RL_STR_LOG[] = "log";                                 // connect string to task
static const char RL_STR_SH_ATTACH_READ[] = "sh_attach_read";           // attach sh with read perm
static const char RL_STR_SH_ATTACH_WRITE[] = "sh_attach_write";         // attach sh with write perm
static const char RL_STR_SH_CREATE_READ[] = "sh_create_read";           // sh create with read perm
static const char RL_STR_SH_CREATE_WRITE[] = "sh_create_write";         // sh create with write perm
static const char RL_STR_LOAD_FILE[] = "load_file";                     // load file into kernel
static const char RL_STR_LOAD_MODULE[] = "load_module";                 // load file into kernel
static const char RL_STR_RAN_ON[] = "ran_on";                           // load file into kernel

/* node string name */
static const char ND_STR_UNKNOWN[] = "unknown";                         // unkown node type should normally not appear
static const char ND_STR_STR[] = "string";                              // simple string used for disclosed log
static const char ND_STR_TASK[] = "task";                               // represent a thread from user space POV
static const char ND_STR_INODE_UNKNOWN[] = "inode_unknown";             // unknown inode type should normally not appear
static const char ND_STR_INODE_LINK[] = "link";                         // link
static const char ND_STR_INODE_FILE[] = "file";                         // standard file
static const char ND_STR_INODE_DIRECTORY[] = "directory";               // directory
static const char ND_STR_INODE_CHAR[] = "char";                         // character device
static const char ND_STR_INODE_BLOCK[] = "block";                       // block device
static const char ND_STR_INODE_PIPE[] = "pipe";                         // pipe
static const char ND_STR_INODE_SOCKET[] = "socket";                     // network socket
static const char ND_STR_MSG[] = "msg";                                 // msg as in IPC message passing
static const char ND_STR_SHM[] = "shm";                                 // shared memory
static const char ND_STR_ADDR[] = "address";                            // network address
static const char ND_STR_SB[] = "sb";                                   // superblock
static const char ND_STR_PATH[] = "path";                               // path associated with a file
static const char ND_STR_DISC_ENTITY[] = "disc_entity";                 // descilosed node representing an entity
static const char ND_STR_DISC_ACTIVITY[] = "disc_activity";             // descilosed node representing an activity
static const char ND_STR_DISC_AGENT[] = "disc_agent";                   // disclosed node representing an agent
static const char ND_STR_MACHINE[] = "machine";                         // machine representing an agent
static const char ND_STR_PACKET[] = "packet";                           // network packet
static const char ND_STR_IATTR[] = "iattr";                             // inode attributes value
static const char ND_STR_XATTR[] = "xattr";                             // extended attributes value
static const char ND_STR_PCKCNT[] = "packet_content";                   // the content of network packet
static const char ND_STR_ARG[] = "argv";                                // argument passed to a process
static const char ND_STR_ENV[] = "envp";                                // environment parameter
static const char ND_STR_PROC[] = "process_memory";                     // process memory

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
	case RL_SOCKET_PAIR_CREATE:
		return RL_STR_SOCKET_PAIR_CREATE;
	case RL_INODE_CREATE:
		return RL_STR_INODE_CREATE;
	case RL_SETUID:
		return RL_STR_SETUID;
	case RL_SETGID:
		return RL_STR_SETGID;
	case RL_GETGID:
		return RL_STR_GETGID;
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
	case RL_FILE_LOCK:
		return RL_STR_FILE_LOCK;
	case RL_FILE_SIGIO:
		return RL_STR_FILE_SIGIO;
	case RL_VERSION:
		return RL_STR_VERSION;
	case RL_MUNMAP:
		return RL_STR_MUNMAP;
	case RL_SHMDT:
		return RL_STR_SHMDT;
	case RL_LINK:
		return RL_STR_LINK;
	case RL_UNLINK:
		return RL_STR_UNLINK;
	case RL_SYMLINK:
		return RL_STR_SYMLINK;
	case RL_SPLICE_OUT:
		return RL_STR_SPLICE_OUT;
	case RL_SPLICE_IN:
		return RL_STR_SPLICE_IN;
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
	case RL_MMAP_WRITE:
		return RL_STR_MMAP_WRITE;
	case RL_MMAP_READ_PRIVATE:
		return RL_STR_MMAP_READ_PRIVATE;
	case RL_MMAP_EXEC_PRIVATE:
		return RL_STR_MMAP_EXEC_PRIVATE;
	case RL_MMAP_WRITE_PRIVATE:
		return RL_STR_MMAP_WRITE_PRIVATE;
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
	case RL_PERM_APPEND:
		return RL_STR_PERM_APPEND;
	case RL_TERMINATE_TASK:
		return RL_STR_TERMINATE_TASK;
	case RL_TERMINATE_PROC:
		return RL_STR_TERMINATE_PROC;
	case RL_FREED:
		return RL_STR_FREED;
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
	case RL_LOAD_FILE:
		return RL_STR_LOAD_FILE;
	case RL_LOAD_MODULE:
		return RL_STR_LOAD_MODULE;
	case RL_RAN_ON:
		return RL_STR_RAN_ON;
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
	MATCH_AND_RETURN(str, RL_STR_SOCKET_PAIR_CREATE, RL_SOCKET_PAIR_CREATE);
	MATCH_AND_RETURN(str, RL_STR_INODE_CREATE, RL_INODE_CREATE);
	MATCH_AND_RETURN(str, RL_STR_SETUID, RL_SETUID);
	MATCH_AND_RETURN(str, RL_STR_SETGID, RL_SETGID);
	MATCH_AND_RETURN(str, RL_STR_GETGID, RL_GETGID);
	MATCH_AND_RETURN(str, RL_STR_BIND, RL_BIND);
	MATCH_AND_RETURN(str, RL_STR_CONNECT, RL_CONNECT);
	MATCH_AND_RETURN(str, RL_STR_LISTEN, RL_LISTEN);
	MATCH_AND_RETURN(str, RL_STR_ACCEPT, RL_ACCEPT);
	MATCH_AND_RETURN(str, RL_STR_OPEN, RL_OPEN);
	MATCH_AND_RETURN(str, RL_STR_FILE_RCV, RL_FILE_RCV);
	MATCH_AND_RETURN(str, RL_STR_FILE_LOCK, RL_FILE_LOCK);
	MATCH_AND_RETURN(str, RL_STR_FILE_SIGIO, RL_FILE_SIGIO);
	MATCH_AND_RETURN(str, RL_STR_VERSION, RL_VERSION);
	MATCH_AND_RETURN(str, RL_STR_MUNMAP, RL_MUNMAP);
	MATCH_AND_RETURN(str, RL_STR_SHMDT, RL_SHMDT);
	MATCH_AND_RETURN(str, RL_STR_LINK, RL_LINK);
	MATCH_AND_RETURN(str, RL_STR_UNLINK, RL_UNLINK);
	MATCH_AND_RETURN(str, RL_STR_SYMLINK, RL_SYMLINK);
	MATCH_AND_RETURN(str, RL_STR_SPLICE_IN, RL_SPLICE_IN);
	MATCH_AND_RETURN(str, RL_STR_SPLICE_OUT, RL_SPLICE_OUT);
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
	MATCH_AND_RETURN(str, RL_STR_MMAP_WRITE, RL_MMAP_WRITE);
	MATCH_AND_RETURN(str, RL_STR_MMAP_READ_PRIVATE, RL_MMAP_READ_PRIVATE);
	MATCH_AND_RETURN(str, RL_STR_MMAP_EXEC_PRIVATE, RL_MMAP_EXEC_PRIVATE);
	MATCH_AND_RETURN(str, RL_STR_MMAP_WRITE_PRIVATE, RL_MMAP_WRITE_PRIVATE);
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
	MATCH_AND_RETURN(str, RL_STR_PERM_APPEND, RL_PERM_APPEND);
	MATCH_AND_RETURN(str, RL_STR_SH_READ, RL_SH_READ);
	MATCH_AND_RETURN(str, RL_STR_PROC_READ, RL_PROC_READ);
	MATCH_AND_RETURN(str, RL_STR_SH_WRITE, RL_SH_WRITE);
	MATCH_AND_RETURN(str, RL_STR_PROC_WRITE, RL_PROC_WRITE);
	MATCH_AND_RETURN(str, RL_STR_TERMINATE_TASK, RL_TERMINATE_TASK);
	MATCH_AND_RETURN(str, RL_STR_TERMINATE_PROC, RL_TERMINATE_PROC);
	MATCH_AND_RETURN(str, RL_STR_FREED, RL_FREED);
	MATCH_AND_RETURN(str, RL_STR_ARG, RL_ARG);
	MATCH_AND_RETURN(str, RL_STR_ENV, RL_ENV);
	MATCH_AND_RETURN(str, RL_STR_LOG, RL_LOG);
	MATCH_AND_RETURN(str, RL_STR_SH_ATTACH_READ, RL_SH_ATTACH_READ);
	MATCH_AND_RETURN(str, RL_STR_SH_ATTACH_WRITE, RL_SH_ATTACH_WRITE);
	MATCH_AND_RETURN(str, RL_STR_SH_CREATE_READ, RL_SH_CREATE_READ);
	MATCH_AND_RETURN(str, RL_STR_SH_CREATE_WRITE, RL_SH_CREATE_WRITE);
	MATCH_AND_RETURN(str, RL_STR_LOAD_FILE, RL_LOAD_FILE);
	MATCH_AND_RETURN(str, RL_STR_LOAD_MODULE, RL_LOAD_MODULE);
	MATCH_AND_RETURN(str, RL_STR_RAN_ON, RL_RAN_ON);
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
	case ENT_INODE_PIPE:
		return ND_STR_INODE_PIPE;
	case ENT_INODE_SOCKET:
		return ND_STR_INODE_SOCKET;
	case ENT_MSG:
		return ND_STR_MSG;
	case ENT_SHM:
		return ND_STR_SHM;
	case ENT_ADDR:
		return ND_STR_ADDR;
	case ENT_SBLCK:
		return ND_STR_SB;
	case ENT_PATH:
		return ND_STR_PATH;
	case ENT_DISC:
		return ND_STR_DISC_ENTITY;
	case ACT_DISC:
		return ND_STR_DISC_ACTIVITY;
	case AGT_DISC:
		return ND_STR_DISC_AGENT;
	case AGT_MACHINE:
		return ND_STR_MACHINE;
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
	MATCH_AND_RETURN(str, ND_STR_INODE_PIPE, ENT_INODE_PIPE);
	MATCH_AND_RETURN(str, ND_STR_INODE_SOCKET, ENT_INODE_SOCKET);
	MATCH_AND_RETURN(str, ND_STR_MSG, ENT_MSG);
	MATCH_AND_RETURN(str, ND_STR_SHM, ENT_SHM);
	MATCH_AND_RETURN(str, ND_STR_ADDR, ENT_ADDR);
	MATCH_AND_RETURN(str, ND_STR_SB, ENT_SBLCK);
	MATCH_AND_RETURN(str, ND_STR_PATH, ENT_PATH);
	MATCH_AND_RETURN(str, ND_STR_DISC_ENTITY, ENT_DISC);
	MATCH_AND_RETURN(str, ND_STR_DISC_ACTIVITY, ACT_DISC);
	MATCH_AND_RETURN(str, ND_STR_DISC_AGENT, AGT_DISC);
	MATCH_AND_RETURN(str, ND_STR_MACHINE, AGT_MACHINE);
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
