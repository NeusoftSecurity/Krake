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

#include <krk_log.h>

static int tcp_parse_param(struct krk_monitor *monitor, 
		char *param, unsigned int param_len);
static int tcp_init_node(struct krk_node *node);
static int tcp_cleanup_node(struct krk_node *node);
static int tcp_process_node(struct krk_node *node, void *param);

struct krk_checker tcp_checker = {
	"tcp",
	KRK_CHECKER_TCP,
	tcp_parse_param,
	tcp_init_node,
	tcp_cleanup_node,
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
	struct krk_connection *conn;
	struct krk_node *node;
	struct krk_monitor *monitor;
	int ret, err;
	socklen_t errlen;

	wev = arg;
	node = wev->data;
	conn = wev->conn;
	monitor = node->parent;

	if (type == EV_WRITE) {
		/* we've got a writable signal, check sockopt */
		errlen = sizeof(err);
		ret = getsockopt(conn->sock, SOL_SOCKET, SO_ERROR, &err, &errlen);
		if (ret == 0) {
			if (err == 0) {
				node->nr_fails = 0;
				if (node->down) {
					node->down = 0;
					krk_monitor_notify(monitor, node);
				}
				goto ok;
			} else {
				krk_log(KRK_LOG_DEBUG, "write failed(%d)!\n", errno);
			}
		}
	} else if (type == EV_TIMEOUT) {
		krk_log(KRK_LOG_DEBUG, "write timeout!\n");
	}
	
	node->nr_fails++;
	if (node->nr_fails == monitor->threshold) {
		node->nr_fails = 0;
		if (!node->down) {
			node->down = 1;
			krk_monitor_notify(monitor, node);
		}
	}

ok:
	krk_monitor_remove_node_connection(node, conn);
	krk_connection_destroy(conn);
}

static int tcp_init_node(struct krk_node *node)
{
	krk_log(KRK_LOG_DEBUG, "tcp init node, node: %s\n", node->addr);
	node->ready = 1;

	return KRK_OK;
}

static int tcp_cleanup_node(struct krk_node *node)
{
	krk_log(KRK_LOG_DEBUG, "tcp cleanup node, node: %s\n", node->addr);
	node->ready = 0;

	return KRK_OK;
}

static int tcp_process_node(struct krk_node *node, void *param)
{
	int sock, ret;
	struct krk_connection *conn;
	struct krk_monitor *monitor;
	
	sock = krk_socket_tcp_create(0);
	if (sock < 0) {
		return KRK_ERROR;
	}

	conn = krk_connection_create(node->addr, 0, 0);
	if (!conn) {
		return KRK_ERROR;
	}

	conn->sock = sock;
	conn->rev->handler = tcp_read_handler;
	conn->wev->handler = tcp_write_handler;

	conn->rev->data = node;
	conn->wev->data = node;
	
	monitor = node->parent;

	/** 
	 * TODO:
	 * connect should be changed into
	 * common form, such as krk_socket_connect...
	 */
	ret = connect(conn->sock, (struct sockaddr*)&node->inaddr, 
			sizeof(struct sockaddr));
	if (ret < 0 && errno != EINPROGRESS) {
		krk_connection_destroy(conn);
		return KRK_ERROR;
	}

	if (errno == EINPROGRESS) {
		conn->wev->timeout = malloc(sizeof(struct timeval));
		if (!conn->wev->timeout) {
			krk_connection_destroy(conn);
			return KRK_ERROR;
		}

		conn->wev->timeout->tv_sec = monitor->timeout;
		conn->wev->timeout->tv_usec = 0;
		krk_event_set_write(conn->sock, conn->wev);
		krk_event_add(conn->wev);

		krk_monitor_add_node_connection(node, conn);

		return KRK_OK;
	}

	/* ret == 0, connect ok */

	/* clear nr fails if success */
	node->nr_fails = 0;

	krk_connection_destroy(conn);
	
	return KRK_OK;
}

