/**
 * krk_tcp.c - Krake tcp checker
 * 
 * Copyright (c) 2011 Yang Yang <paulyang.inf@gmail.com>
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <krk_core.h>
#include <checkers/krk_checker.h>
#include <checkers/krk_tcp.h>


static int tcp_parse_param(struct krk_monitor *monitor, 
		char *param, unsigned int param_len);
static int tcp_init_node(struct krk_node *node);
static int tcp_process_node(struct krk_node *node, void *param);

struct krk_checker tcp_checker = {
	"tcp",
	KRK_CHECKER_TCP,
	tcp_parse_param,
	tcp_init_node,
	tcp_process_node,
};

static int tcp_parse_param(struct krk_monitor *monitor, 
		char *param, unsigned int param_len)
{	
	return KRK_OK;
}

static void tcp_read_handler(int sock, short type, void *arg)
{
	struct krk_event *rev;

	rev = arg;
}

static void tcp_write_handler(int sock, short type, void *arg)
{
	struct krk_event *wev;

	wev = arg;

	fprintf(stderr, "write ok!\n");
}

static int tcp_init_node(struct krk_node *node)
{
	/**
	 * 1. create socket;
	 * 2. create connection;
	 * 3. set events;
	 */

	int sock;
	struct krk_connection *conn;
	struct krk_monitor *monitor;

	sock = krk_socket_tcp_create(0);
	if (sock < 0) {
		return KRK_ERROR;
	}

	node->conn = krk_connection_create(node->addr, 0, 0);
	if (!node->conn) {
		return KRK_ERROR;
	}

	conn = node->conn;
	conn->sock = sock;
	conn->rev->handler = tcp_read_handler;
	conn->wev->handler = tcp_write_handler;

	monitor = node->parent;

	conn->wev->timeout = malloc(sizeof(struct timeval));
	if (!conn->wev->timeout) {
		krk_connection_destroy(node->conn);
		return KRK_ERROR;
	}

	node->ready = 1;

	conn->wev->timeout->tv_sec = monitor->timeout;
	fprintf(stderr, "tcp init node, tmout %lu\n", monitor->timeout);
	krk_event_set_write(conn->sock, conn->wev);

	return KRK_OK;
}

static int tcp_process_node(struct krk_node *node, void *param)
{
	fprintf(stderr, "tcp process node, addr %s\n", node->addr);
	return KRK_OK;
}


