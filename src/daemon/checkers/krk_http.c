/**
 * krk_http.c - Krake http checker
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
#include <checkers/krk_http.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>

static int http_parse_param(struct krk_monitor *monitor, 
		char *param, unsigned int param_len);
static int http_init_node(struct krk_node *node);
static int http_cleanup_node(struct krk_node *node);
static int http_process_node(struct krk_node *node, void *param);

struct krk_checker http_checker = {
	"http",
	KRK_CHECKER_HTTP,
	http_parse_param,
	http_init_node,
	http_cleanup_node,
	http_process_node,
};

static int http_parse_param_item(char *param, int offset, char blank)
{
	if (!memcmp(param + offset + blank, "send", 4)) {
		return HTTP_PARSE_SEND;
	}

	if (!memcmp(param + offset + blank, "expected", 8)) {
		return HTTP_PARSE_EXPECTED;
	}

	return -1;
}

static int http_parse_param(struct krk_monitor *monitor, 
		char *param, unsigned int param_len)
{
	int i, j, stage, prev = -1;
	struct http_checker_param *hcp;
	char send_parsed = 0, expected_parsed = 0, failed = 0;

#if KRK_DEBUG
	for (i = 0; i < param_len; i++) {
		fprintf(stderr, "%c", param[i]);
	}

	fprintf(stderr, "\n");
#endif

	hcp = malloc(sizeof(struct http_checker_param));
	if (hcp == NULL) {
		return KRK_ERROR;
	}

	memset(hcp, 0, sizeof(struct http_checker_param));
	monitor->parsed_checker_param = hcp;

	for (i = 0; i < param_len; i++) {
		if (prev != -1 && i + 1 <= param_len && 
				param[i] == '*' && param[i + 1] == '~') {
			param[i] = 0xd;
			param[i + 1] = 0xa;
		}

		if (param[i] == ':' && prev == -1) {
			fprintf(stderr, "find a :\n");
			for (j = i; j >= 0; j--) {
				if (param[j] == ' ') {
					fprintf(stderr, "find a ' '\n");
					/* find a "string:" style*/
					stage = http_parse_param_item(param, j, 1);
					break;
				}

				if (j == 0) {
					fprintf(stderr, "j == 0\n");
					/* find a "string:" style string at the beginning */
					stage = http_parse_param_item(param, j, 0);
					break;
				}
			}
		}

		if (param[i] == '\"') {
			if (prev != -1) {
				fprintf(stderr, "second \"\n");
				/* find a "string" style */
				switch (stage) {
					case HTTP_PARSE_SEND:
						fprintf(stderr, "statge send\n");
						if ((i - prev - 1) > KRK_MAX_HTTP_SEND) {
							break;
						}
						hcp->send_len = i - prev - 1;
						memcpy(hcp->send, param + prev + 1, hcp->send_len);
						send_parsed = 1;
						break;
					case HTTP_PARSE_EXPECTED:
						fprintf(stderr, "statge expected\n");
						if ((i - prev - 1) > KRK_MAX_HTTP_EXPECTED) {
							break;
						}
						hcp->expected_len = i - prev - 1;
						memcpy(hcp->expected, param + prev + 1, hcp->expected_len);
						expected_parsed = 1;
						break;
					default:
						/* parse failed */
						fprintf(stderr, "no stage\n");
						failed = 1;
						goto out;
				}
				prev = -1;
			} else {
				/* first " */
				fprintf(stderr, "first \"\n");
				prev = i;
			}
		}
	}

out:
	if (failed) {
		return KRK_ERROR;
	}

	if (!send_parsed) {
		hcp->send_len = strlen("GET / HTTP/1.1");
		memcpy(hcp->send, "GET / HTTP/1.1", hcp->send_len);
	}

	if (!expected_parsed) {
		hcp->expected_len = 0;
	}

#if KRK_DEBUG
	for (i = 0; i < hcp->send_len; i++) {
		fprintf(stderr, "%c", hcp->send[i]);
	}

	fprintf(stderr, "\n");

	for (i = 0; i < hcp->expected_len; i++) {
		fprintf(stderr, "%c", hcp->expected[i]);
	}

	fprintf(stderr, "\n");
#endif

	return KRK_OK;
}

static int http_match_packet(void* packet, struct krk_node *node)
{
	struct krk_monitor *monitor;
	struct http_checker_param *hcp;
	int i;

	monitor = node->parent;
	hcp = monitor->parsed_checker_param;
	
	for (i = 0; i < 20; i++) {
		fprintf(stderr, "%c", ((char *)packet)[i]);
	}

	fprintf(stderr, "\n");

	if (hcp->expected_len == 0)
		return KRK_OK;

	return KRK_OK;
}

static int http_handle_response_header(void* packet, struct krk_node *node)
{
	return KRK_OK;
}

static void http_read_handler(int sock, short type, void *arg)
{
	struct krk_event *rev;
	struct krk_connection *conn;
	struct krk_node *node;
	struct krk_monitor *monitor;
	void *packet = NULL;
	int ret, packlen;
	socklen_t addrlen;

	fprintf(stderr, "read a http reply, type is %d\n", type);
	rev = arg;
	node = rev->data;
	conn = rev->conn;
	monitor = node->parent;

	if (type == EV_READ) {
		packlen = KRK_MAX_IP_LEN + KRK_MAX_HTTP_LEN;
		packet = malloc(packlen);
		if (packet == NULL) {
			goto out;
		}

		addrlen = sizeof(struct sockaddr);
		ret = recv(sock, packet, packlen, 0);
		if (ret < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				krk_event_add(conn->rev);
				free(packet);
				return;
			}
		}

		ret = http_handle_response_header(packet, node);
		
		/* recv ok */

		if (http_match_packet(packet, node) == KRK_OK) {
			fprintf(stderr, "got correct http reply\n");
			if (node->down) {
				node->down = 0;
				krk_monitor_notify(monitor, node);
			}
		} else {
			node->nr_fails++;
			if (node->nr_fails == monitor->threshold) {
				node->nr_fails = 0;
				if (!node->down) {
					node->down = 1;
					krk_monitor_notify(monitor, node);
				}
			}
		}
	} else if (type == EV_TIMEOUT) {
		node->nr_fails++;
		if (node->nr_fails == monitor->threshold) {
			node->nr_fails = 0;
			if (!node->down) {
				node->down = 1;
				krk_monitor_notify(monitor, node);
			}
		}
	}

out:
	if (packet) {
		free(packet);
	}

	krk_monitor_remove_node_connection(node, conn);
	krk_connection_destroy(conn);
}

static void http_write_handler(int sock, short type, void *arg)
{
	struct krk_event *wev;
	struct krk_connection *conn;
	struct krk_node *node;
	struct krk_monitor *monitor;
	struct http_checker_param *hcp;
	void *packet = NULL;
	int ret;

	wev = arg;
	node = wev->data;
	conn = wev->conn;
	monitor = node->parent;
	hcp = monitor->parsed_checker_param;

	if (type == EV_WRITE) {
		/* we've got a writable signal, send out the http packet */
		packet = malloc(KRK_MAX_HTTP_SEND);
		if (packet == NULL) {
			goto failed;
		}

		memset(packet, 0, KRK_MAX_HTTP_SEND);
		
		/* there is always a send-string, by default it's "GET / HTTP/1.1" */
		memcpy(packet, hcp->send, hcp->send_len);
		
	//	memcpy(packet + hcp->send_len, "\r\nHost: 192.168.184.4\r\nConnection: close\r\n\r\n", 
	//			44);

		/* schedule read handler */
		conn->rev->timeout = malloc(sizeof(struct timeval));
		if (!conn->rev->timeout) {
			goto failed;
		}

		conn->rev->timeout->tv_sec = monitor->timeout;
		conn->rev->timeout->tv_usec = 0;

		ret = send(sock, packet, hcp->send_len, 0);
		if (ret < 0) {
			node->nr_fails++;
			if (node->nr_fails == monitor->threshold) {
				node->nr_fails = 0;
				if (!node->down) {
					node->down = 1;
					krk_monitor_notify(monitor, node);
				}
			}

			goto failed;
		}

		krk_event_set_read(conn->sock, conn->rev);
		krk_event_add(conn->rev);
	} else if (type == EV_TIMEOUT) {
		fprintf(stderr, "write timeout!\n");
		node->nr_fails++;
		if (node->nr_fails == monitor->threshold) {
			node->nr_fails = 0;
			if (!node->down) {
				node->down = 1;
				krk_monitor_notify(monitor, node);
			}
		}
		
		goto failed;
	}

out:
	if (packet)
		free(packet);

	return;

failed:
	krk_monitor_remove_node_connection(node, conn);
	krk_connection_destroy(conn);

	goto out;
}

static int http_init_node(struct krk_node *node)
{
	node->ready = 1;

	return KRK_OK;
}

static int http_cleanup_node(struct krk_node *node)
{
	node->ready = 0;

	return KRK_OK;
}

static int http_process_node(struct krk_node *node, void *param)
{
	int sock, ret;
	struct krk_connection *conn;
	struct krk_monitor *monitor;

	if (node->conn)
		return KRK_OK;

	sock = krk_socket_tcp_create(0);
	if (sock < 0) {
		return KRK_ERROR;
	}

	conn = krk_connection_create(node->addr, 0, 0);
	if (!conn) {
		return KRK_ERROR;
	}

	conn->sock = sock;
	conn->rev->handler = http_read_handler;
	conn->wev->handler = http_write_handler;

	conn->rev->data = node;
	conn->wev->data = node;
	
	monitor = node->parent;

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
	
	krk_monitor_add_node_connection(node, conn);

	return KRK_OK;
}
