/**
 * krk_monitor.h - Monitor log
 * 
 * Copyright (c) 2011 Yang Yang <paulyang.inf@gmail.com>
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */


#ifndef __KRK_MONITOR_H__
#define __KRK_MONITOR_H__

#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <arpa/inet.h>

#include <krk_list.h>
#include <krk_event.h>
#include <krk_connection.h>
#include <checkers/krk_checker.h>

#define KRK_MONITOR_FLAG_ENABLED 0x1

struct krk_monitor {
	char name[64];

	struct list_head list;
	
	unsigned long interval;
	unsigned long timeout;
	unsigned long threshold;

	struct krk_checker *checker;
	void *checker_param;
	unsigned int checker_param_len; /* size of void *checker_param */

	struct list_head node_list;
	unsigned long nr_nodes;

	struct krk_event *tmout_ev;	

	char *notify_script;

	unsigned int enabled:1;
};

struct krk_node {
	char addr[64];
	unsigned int port;
	struct krk_connection *conn;
	
	union {
		struct sockaddr_in inaddr;
		struct sockaddr_in6 in6addr;
	};

	struct list_head list;

	unsigned int ipv6:1;
	unsigned int down:1;
};

extern struct krk_monitor* krk_monitor_find(const char *name);
extern struct krk_monitor* krk_monitor_create(const char *name);
extern int krk_monitor_destroy(struct krk_monitor *monitor);
extern int krk_monitor_init(void);
extern int krk_all_monitors_destroy(void);
extern int krk_monitor_exit(void);
extern int krk_monitor_add_node(struct krk_monitor *monitor, 
		struct krk_node *node);
extern int krk_monitor_remove_node(struct krk_monitor *monitor, 
		struct krk_node *node);
extern void krk_monitor_enable(struct krk_monitor *monitor);
extern void krk_monitor_disable(struct krk_monitor *monitor);
extern struct krk_node* krk_monitor_create_node(const char *addr, unsigned short port);
extern int krk_monitor_destroy_node(struct krk_node *node);
extern struct krk_node* krk_monitor_find_node(const char *addr, 
		const unsigned short port, struct krk_monitor *monitor);
extern int krk_monitor_get_all_nodes(struct krk_monitor *monitor, 
		struct krk_node *node); 
extern int krk_monitors_destroy_all_nodes(struct krk_monitor *monitor);

#endif
