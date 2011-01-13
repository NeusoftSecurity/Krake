/**
 * krk_checker.h - Krake checker
 * 
 * Copyright (c) 2011 Yang Yang <paulyang.inf@gmail.com>
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef __KRK_CHECKER_H__
#define __KRK_CHECKER_H__

#include <krk_core.h>
#include <krk_event.h>
#include <krk_monitor.h>
#include <krk_connection.h>
#include <krk_socket.h>


#define KRK_CHECKER_ICMP 1
#define KRK_CHECKER_TCP 2
#define KRK_CHECKER_HTTP 3
#define KRK_CHECKER_FTP 4


struct krk_node;
struct krk_monitor;

struct krk_checker {
	char *name;
	unsigned int id;

	int (*parse_param)(struct krk_monitor *monitor, 
			char *param, unsigned int param_len);
	int (*init_node)(struct krk_node *node);
	int (*process_node)(struct krk_node *node, void *param);
};

extern struct krk_checker* krk_checker_find(char *name);

#endif

