/*
* Caffeine Linux Security Module
*
* Author: Thomas Pasquier <tfjmp2@cam.ac.uk>
*
* Copyright (C) 2015 University of Cambridge
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License version 2, as
* published by the Free Software Foundation.
*
*/
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "simplog.h"
#include "provenancelib.h"

#define	LOG_FILE "/tmp/audit.log"
#define gettid() syscall(SYS_gettid)

void tagarr_to_str(const uint64_t* in, const size_t in_size, char* out, size_t out_size){
  int i;
	size_t rm = out_size,cx;
	out[0]='\0';
  for(i = 0; i < in_size-1; i++){
		cx = snprintf(out, rm, "%lu, ", in[i]);
		if(cx<0){
			out[0]='\0';
			return;
		}
		out+=cx;
		rm-=cx;
  }
	cx = snprintf(out, rm, "%lu", in[i]);
	if(cx<0){
		out[0]='\0';
		return;
	}
}

void _init_logs( void ){
  simplog.setLogFile(LOG_FILE);
  simplog.setLineWrap(false);
  simplog.setLogSilentMode(true);
  simplog.setLogDebugLevel(SIMPLOG_VERBOSE);
}

pthread_mutex_t mut = PTHREAD_MUTEX_INITIALIZER;

void write_to_log(const char* fmt, ...){
  char tmp[5096];
	va_list args;
	va_start(args, fmt);
  vsprintf(tmp, fmt, args);
	va_end(args);
  pthread_mutex_lock(&mut);
  simplog.writeLog(SIMPLOG_INFO, tmp);
  pthread_mutex_unlock(&mut);
}

void init( void ){
  pid_t tid = gettid();
  write_to_log("audit writer thread, tid:%ld",
    tid);
}

void log_str(struct str_struct* data){
  write_to_log("%lu-\t%s",
    data->event_id, data->str);
}

void log_link(struct link_struct* link){
  write_to_log("%lu-\tlink[%s]{%lu|%lu|%lu}",
    link->event_id, link->name, link->inode_id, link->task_id, link->dir_id);
}

void log_unlink(struct unlink_struct* unlink){
  write_to_log("%lu-\tunlink[%s]{%lu|%lu|%lu}",
    unlink->event_id, unlink->name, unlink->inode_id, unlink->task_id, unlink->dir_id);
}

void log_edge(struct edge_struct* edge){
    write_to_log("%lu-\t%s{%lu->%lu}%d",
      edge->event_id, edge_str[edge->type], edge->snd_id, edge->rcv_id, edge->allowed);
}

void log_task(struct task_prov_struct* task){
  write_to_log("%lu-\ttask[%lu]{%u|%u}",
    task->event_id, task->node_id, task->uid, task->gid);
}

void log_inode(struct inode_prov_struct* inode){
  write_to_log("%lu-\tinode[%lu:%u]{%u|%u|0X%04hhX}",
    inode->event_id, inode->node_id, inode->rdev, inode->uid, inode->gid, inode->mode);
}

void log_disc(struct disc_node_struct* node){
  write_to_log("%lu-\tdisclosed[%lu]",
    node->event_id, node->node_id);
}

void log_msg(struct msg_msg_struct* msg){
  write_to_log("%lu-\tmsg[%lu]{%ld}",
    msg->event_id, msg->node_id, msg->type);
}

void log_shm(struct shm_struct* shm){
  write_to_log("%lu-\tshm[%lu]{0X%04hhX}",
    shm->event_id, shm->node_id, shm->mode);
}


void log_sock(struct sock_struct* sock){
  write_to_log("%lu-\tsock[%lu]{%u|%u|%u}",
    sock->event_id, sock->node_id, sock->type, sock->family, sock->protocol);
}

void log_address(struct address_struct* address){
  write_to_log("%lu-\taddress[%lu:name]{%u}",
  address->event_id, address->sock_id, address->addr.sa_family);
}

struct provenance_ops ops = {
  .init=init,
  .log_edge=log_edge,
  .log_task=log_task,
  .log_inode=log_inode,
  .log_str=log_str,
  .log_link=log_link,
  .log_unlink=log_unlink,
  .log_disc=log_disc,
  .log_msg=log_msg,
  .log_shm=log_shm,
  .log_sock=log_sock
};

void test(void){
  int rc;

  struct disc_node_struct node1, node2;
  struct task_prov_struct self;
  struct edge_struct edge;
  if((rc = provenance_disclose_node(&node1))<0){
    printf("Error %d\n", rc);
  }
  if((rc = provenance_disclose_node(&node2))<0){
    printf("Error %d\n", rc);
  }
  edge.type = ED_DATA;
  edge.allowed=FLOW_ALLOWED;
  edge.snd_id=node1.node_id;
  edge.rcv_id=node2.node_id;
  provenance_disclose_edge(&edge);
  provenance_self(&self);
  edge.type = ED_DATA;
  edge.allowed=FLOW_ALLOWED;
  edge.snd_id=node1.node_id;
  edge.rcv_id=self.node_id;
  provenance_disclose_edge(&edge);
}

int main(void){
  int rc;
	_init_logs();
  simplog.writeLog(SIMPLOG_INFO, "audit process pid: %d", getpid());
  rc = provenance_register(&ops);
  if(rc){
    simplog.writeLog(SIMPLOG_ERROR, "Failed registering audit operation.");
    exit(rc);
  }
  sleep(2);
  test();
  while(1) sleep(60);
  provenance_stop();
  return 0;
}
