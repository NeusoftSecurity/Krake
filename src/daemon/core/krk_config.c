/**
 * krk_config.c - functions related to configuration
 * 
 * Copyright (c) 2010 Yang Yang <paulyang.inf@gmail.com>
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <krk_core.h>
#include <krk_socket.h>
#include <krk_event.h>
#include <krk_connection.h>
#include <krk_config.h>
#include <krk_buffer.h>
#include <krk_monitor.h>
#include <krk_checker.h>

void krk_config_read(int sock, short type, void *arg);
void krk_config_write(int sock, short type, void *arg);

static inline void krk_config_show_content(struct krk_config *conf)
{
	fprintf(stderr, "config: \n");
	fprintf(stderr, "\tmonitor: %s\n", conf->monitor);
	fprintf(stderr, "\tchecker: %s\n", conf->checker);
	fprintf(stderr, "\tchecker_conf: %s\n", conf->checker_conf);
	fprintf(stderr, "\tchecker_conf_len: %lu\n", conf->checker_conf_len);
	fprintf(stderr, "\tinterval: %lu\n", conf->interval);
	fprintf(stderr, "\ttimeout: %lu\n", conf->timeout);
	fprintf(stderr, "\tthreshold: %lu\n", conf->threshold);
	fprintf(stderr, "\tnode: %s\n", conf->node);
	fprintf(stderr, "\tport: %u\n", conf->port);
}

/**
 * krk_config_check - check config
 * @conf: configuration to check
 *
 *
 * return: KRK_OK on success, KRK_ERROR on failed
 *
 * Finally I decide to do this check at the daemon
 * side instead of in krakectrl. This check could
 * make krake daemon more robust, although this could
 * impact the performance.
 */
static int krk_config_check(struct krk_config *conf)
{
	int ret = KRK_OK;
	return ret;
}

static int krk_config_parse(struct krk_config *conf)
{
	int ret = KRK_OK;
	struct krk_monitor *monitor = NULL;
	struct krk_node *node = NULL;

	if (conf->command != KRK_CONF_CMD_CREATE) {
		monitor = krk_monitor_find(conf->monitor);
		if (monitor == NULL) {
			ret = KRK_ERROR;
			goto out;
		}
	}

	switch (conf->command) {
		case KRK_CONF_CMD_CREATE:
			monitor = krk_monitor_create(conf->monitor);
			if (monitor == NULL) {
				ret = KRK_ERROR;
				goto out;
			}

			monitor->interval = conf->interval;
			break;
		case KRK_CONF_CMD_DESTROY:
			ret = krk_monitor_destroy(monitor);
			break;
		case KRK_CONF_CMD_ADD:
			ret = krk_monitor_add_node(monitor, node);
			break;
		case KRK_CONF_CMD_REMOVE:
			ret = krk_monitor_remove_node(monitor, node);
			break;
		case KRK_CONF_CMD_ENABLE:
			krk_monitor_enable(monitor);
			break;
		case KRK_CONF_CMD_DISABLE:
			krk_monitor_disable(monitor);
			break;
		default:
			ret = KRK_ERROR;
	}

out:
	return ret;
}

static int krk_config_process(struct krk_connection *conn)
{
	struct krk_config *conf = NULL;
	struct krk_event *rev = conn->rev;
	struct krk_event *wev = conn->wev;
	int buf_len, ret;
	char retval[KRK_CONF_RETVAL_LEN];

	memset(retval, 0, KRK_CONF_RETVAL_LEN);
	*(int *)(retval + 1) = 0xcdef5abc;
	
	buf_len = rev->buf->last - rev->buf->pos;
	if (buf_len < sizeof(struct krk_config)) {
		return KRK_AGAIN;
	}

	conf = (struct krk_config*)(rev->buf->pos);
	conf->checker_conf = conf->data;
	
	if (buf_len < 
			(sizeof(struct krk_config) + conf->checker_conf_len)) {
		return KRK_AGAIN;
	}

	if (buf_len >
			(sizeof(struct krk_config) + conf->checker_conf_len)) {
		return KRK_ERROR;
	}

#ifdef KRK_DEBUG
	krk_config_show_content(conf);
#endif

	ret = krk_config_check(conf);
	if (ret != KRK_OK) {
		*retval = KRK_CONF_PARSE_ERROR;
	} else {
		ret = krk_config_parse(conf);
		if (ret != KRK_OK) {
			*retval = KRK_CONF_PARSE_ERROR;
		}
	}

	/* return value to client */
	memcpy(wev->buf->pos, retval, sizeof(retval));
	wev->buf->last += sizeof(retval);

	krk_event_set_write(conn->sock, wev);
	krk_event_add(wev);
	
	return KRK_DONE;
}

void krk_config_read(int sock, short type, void *arg)
{
	int n, ret;
	struct krk_event *rev;
	struct krk_connection *conn;
	
	rev = arg;
	conn = rev->conn;
	
	n = recv(sock, rev->buf->last, rev->buf->end - rev->buf->last, 0);
	if (n == 0) {
		fprintf(stderr, "read config finished\n");
		krk_connection_destroy(conn);
		return;
	}

	if (n < 0) {
		fprintf(stderr, "read config error\n");
		krk_connection_destroy(conn);
		return;
	}

	rev->buf->last += n;
	ret = krk_config_process(conn);

	if (ret == KRK_AGAIN) {
		/* KRK_AGAIN means command not completed */
	}

	if (ret == KRK_DONE 
			|| ret == KRK_ERROR) {
		rev->buf->last = rev->buf->head;
	}

	krk_event_set_read(sock, rev);
	krk_event_add(rev);
}

void krk_config_write(int sock, short type, void *arg)
{
	int n;
	struct krk_event *wev;
	struct krk_connection *conn;

	wev = arg;
	conn = wev->conn;
	
	n = send(sock, wev->buf->pos, wev->buf->last - wev->buf->pos, 0);
	if (n < 0) {
		fprintf(stderr, "write config retval error\n");
		krk_connection_destroy(conn);
		return;
	}

	if (n == (wev->buf->last - wev->buf->pos)) {
		wev->buf->pos = wev->buf->last = wev->buf->head;
		return;
	}

	/* write busy, rearm */
	if (n < (wev->buf->last - wev->buf->pos)) {
		wev->buf->pos += n;
	}

	krk_event_set_write(sock, wev);
	krk_event_add(wev);
}
