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

#include <krk_list.h>
#include <krk_event.h>
#include <krk_connection.h>
#include <krk_checker.h>

#define KRK_MONITOR_FLAG_ENABLED 0x1

struct krk_monitor {
	char name[64];

	struct list_head list;
	
	time_t interval;
	time_t timeout;
	unsigned long threshold;

	struct krk_checker *checker;

	struct list_head *node_list;
	unsigned long nr_nodes;

	unsigned int flags;
};

struct krk_node {
	char addr[16];
	unsigned int port;
	struct krk_connection *conn;
};

extern struct krk_monitor* krk_monitor_find(char *name);
extern struct krk_monitor* krk_monitor_create(char *name);
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

#endif
