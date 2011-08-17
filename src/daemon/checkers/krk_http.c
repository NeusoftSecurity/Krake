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

#include <krk_log.h>

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

static int http_load_response_file(struct http_checker_param *hcp)
{
	int fd, size;
	char tmp;

	fd = open(hcp->expected_file, O_RDONLY);
	if (fd < 0) {
		krk_log(KRK_LOG_DEBUG, "%s, open fd failed\n", __func__);
		return KRK_ERROR;
	}

	size = read(fd, hcp->expected, KRK_MAX_HTTP_EXPECTED);
	if (size < 0) {
		krk_log(KRK_LOG_DEBUG, "%s, read fd failed\n", __func__);
		return KRK_ERROR;
	}

	if (size == KRK_MAX_HTTP_EXPECTED) {
		size = read(fd, &tmp, 1);
		if (size != 0) {
			krk_log(KRK_LOG_INFO, "there are more bytes left in the body, not matched\n");
			close(fd);
			return KRK_ERROR;
		}
	}

	hcp->expected_len = size;

	close(fd);
	return KRK_OK;
}

static int http_parse_param_item(char *param, int offset, char blank)
{
	if (!memcmp(param + offset + blank, "send:", 5)) {
		return HTTP_PARSE_SEND;
	}

	if (!memcmp(param + offset + blank, "expected:", 9)) {
		return HTTP_PARSE_EXPECTED;
	}
	
	if (!memcmp(param + offset + blank, "expected-file:", 14)) {
		return HTTP_PARSE_EXPECTED_FILE;
	}

	return -1;
}

static int http_parse_param(struct krk_monitor *monitor, 
		char *param, unsigned int param_len)
{
	int i, j, stage, prev = -1;
	struct http_checker_param *hcp;
	char send_parsed = 0, expected_parsed = 0, expected_file_parsed = 0, failed = 0;
#if 0
	for (i = 0; i < param_len; i++) {
		krk_log(KRK_LOG_DEBUG, "%c", param[i]);
	}

	krk_log(KRK_LOG_DEBUG, "\n");
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
			krk_log(KRK_LOG_DEBUG, "find a :\n");
			for (j = i; j >= 0; j--) {
				if (param[j] == ' ') {
					krk_log(KRK_LOG_DEBUG, "find a ' '\n");
					/* find a "string:" style*/
					stage = http_parse_param_item(param, j, 1);
					break;
				}

				if (j == 0) {
					krk_log(KRK_LOG_DEBUG, "j == 0\n");
					/* find a "string:" style string at the beginning */
					stage = http_parse_param_item(param, j, 0);
					break;
				}
			}
		}

		if (param[i] == '\"') {
			if (prev != -1) {
				krk_log(KRK_LOG_DEBUG, "second \"\n");
				/* find a "string" style */
				switch (stage) {
					case HTTP_PARSE_SEND:
						krk_log(KRK_LOG_DEBUG, "stage send\n");
						if ((i - prev - 1) > KRK_MAX_HTTP_SEND) {
							break;
						}
						hcp->send_len = i - prev - 1;
						memcpy(hcp->send, param + prev + 1, hcp->send_len);
						send_parsed = 1;
						break;
					case HTTP_PARSE_EXPECTED:
						krk_log(KRK_LOG_DEBUG, "stage expected\n");
						if ((i - prev - 1) > KRK_MAX_HTTP_EXPECTED) {
							break;
						}
						hcp->expected_len = i - prev - 1;
						memcpy(hcp->expected, param + prev + 1, hcp->expected_len);
						expected_parsed = 1;
						break;
					case HTTP_PARSE_EXPECTED_FILE:
						krk_log(KRK_LOG_DEBUG, "stage expected-file\n");
						if ((i - prev - 1) > (KRK_MAX_HTTP_EXPECTED_FILE - 1)) {
							break;
						}
						hcp->expected_file_len = i - prev - 1;
						hcp->expected_in_file = 1;
						memcpy(hcp->expected_file, param + prev + 1, hcp->expected_file_len);
						expected_file_parsed = 1;

						/* load file into memory */
						if (http_load_response_file(hcp) != KRK_OK) {
							failed = 1;
							goto out;
						}
						break;
					default:
						/* parse failed */
						krk_log(KRK_LOG_DEBUG, "no stage\n");
						failed = 1;
						goto out;
				}
				prev = -1;
			} else {
				/* first " */
				krk_log(KRK_LOG_DEBUG, "first \"\n");
				prev = i;
			}
		}
	}

out:
	if (failed) {
		return KRK_ERROR;
	}

	if (expected_parsed && expected_file_parsed) {
		return KRK_ERROR;
	}

	if (!send_parsed) {
		hcp->send_len = strlen(HTTP_DEFAULT_REQUEST);
		memcpy(hcp->send, HTTP_DEFAULT_REQUEST, hcp->send_len);
	}

	if (!expected_parsed && !expected_file_parsed) {
		hcp->expected_len = 0;
	}

#if 0
	for (i = 0; i < hcp->send_len; i++) {
		krk_log(KRK_LOG_DEBUG, "%c", hcp->send[i]);
	}

	krk_log(KRK_LOG_DEBUG, "\n");

	for (i = 0; i < hcp->expected_len; i++) {
		krk_log(KRK_LOG_DEBUG, "%c", hcp->expected[i]);
	}

	krk_log(KRK_LOG_DEBUG, "\n");

	for (i = 0; i < hcp->expected_file_len; i++) {
		krk_log(KRK_LOG_DEBUG, "%c", hcp->expected_file[i]);
	}

	krk_log(KRK_LOG_DEBUG, "\n");
#endif
	return KRK_OK;
}

static int http_match_body(struct krk_node *node)
{
	struct krk_monitor *monitor;
	struct http_checker_param *hcp;
	struct http_response_header *hrh;
	struct krk_buffer *buf;

	monitor = node->parent;
	buf = node->buf;
	hcp = monitor->parsed_checker_param;
	hrh = node->checker_data;

	if (hcp->expected_len == 0)
		return KRK_OK;

	if (hcp->expected_len != hrh->body_len) {
		return KRK_ERROR;
	}

	if (!memcmp(hrh->body_start, hcp->expected, hcp->expected_len)) {
		krk_log(KRK_LOG_INFO, "expected string matched\n");
		return KRK_OK;
	} else {
		krk_log(KRK_LOG_INFO, "expected string not matched\n");
		return KRK_ERROR;
	}

	return KRK_OK;
}

static int http_handle_response(struct krk_node *node)
{
	struct http_response_header *hrh;
	struct http_checker_param *hcp;
	struct krk_buffer *buf;
	struct krk_monitor *monitor;
	int i, prev = -1, len, prev_body_len = -1;
	char code_string[4], body_len_string[64];
	char code_parsed = 0, body_len_parsed = 0;

	hrh = node->checker_data;
	buf = node->buf;

	monitor = node->parent;
	hcp = monitor->parsed_checker_param;

	hrh->header_start = buf->head;
	len = buf->last - buf->head;

	memset(body_len_string, 0, 64);
	
	for (i = 0; i < len; i++) {
		if (buf->head[i] == ' ') {
			if (prev == -1) {
				/* first space in response line */
				prev = i;
			} else {
				/* this is the second space */
				memcpy(code_string, buf->head + prev + 1, 3);
				sscanf(code_string, "%u", &hrh->code);
				code_parsed = 1;
			}
		}

		if ((i + 3) <= len && !memcmp(buf->head + i, "\r\n\r\n", 4)) {
			/* find the last /r/n/r/n of http header */
			hrh->header_last = buf->head + i;
			hrh->body_start = hrh->header_last + 4;
			break;
		}

		if (((i + strlen(HTTP_CONTENT_STRING)) <= len
					&& !memcmp(buf->head + i, HTTP_CONTENT_STRING, strlen(HTTP_CONTENT_STRING)))) {
			prev_body_len = i;
		}
		
		if ((i + 1) <= len && !memcmp(buf->head + i, "\r\n", 2)) {
			/* find the /r/n at the end of each http header line */
			if (prev_body_len != -1) {
				/* there is a "Content-Length" found before */
				memcpy(body_len_string, buf->head + prev_body_len + strlen(HTTP_CONTENT_STRING), 
						i - prev_body_len - strlen(HTTP_CONTENT_STRING));
				sscanf(body_len_string, "%u", &hrh->body_len);
				body_len_parsed = 1;
			}
		}
	}

	if (code_parsed) {
		krk_log(KRK_LOG_DEBUG, "response code: %u\n", hrh->code);
		if (hrh->code != 200) {
			return KRK_ERROR;
		}
	} else {
		return KRK_ERROR;
	}

	if (body_len_parsed) {
		krk_log(KRK_LOG_DEBUG, "repsonse body length: %u, buf length: %d\n", 
				hrh->body_len, (int)(buf->last - buf->head));
		if ((buf->last - buf->head) < hrh->body_len) {
			return KRK_AGAIN;
		}
	} else {
		return KRK_ERROR;
	}

	return KRK_OK;
}

static void http_read_handler(int sock, short type, void *arg)
{
	struct krk_event *rev;
	struct krk_connection *conn;
	struct krk_node *node;
	struct krk_monitor *monitor;
	int ret;

	krk_log(KRK_LOG_DEBUG, "read a http reply, type is %d\n", type);
	rev = arg;
	node = rev->data;
	conn = rev->conn;
	monitor = node->parent;

	if (type == EV_READ) {
		ret = recv(sock, node->buf->last, node->buf->end - node->buf->last, 0);
		if (ret < 0) {
			//if (errno == EAGAIN || errno == EWOULDBLOCK) {
			//	krk_event_add(conn->rev);
			//}
			node->nr_fails++;
			if (node->nr_fails == monitor->threshold) {
				node->nr_fails = 0;
				if (!node->down) {
					node->down = 1;
					krk_monitor_notify(monitor, node);
				}
			}
			goto out;
		}

		if (ret == 0) {
			/* server close the connection, 
			 * maybe we'll never be here */
			goto out;
		}

		/* ret > 0 */

		if ((node->buf->last + ret) == node->buf->end) {
			/* buffer is full, double current size */
			node->buf = krk_buffer_resize(node->buf, node->buf->size * 2);
			if (!node->buf) {
				krk_event_add(conn->rev);
				return;
			}
		}

		node->buf->last += ret;

		ret = http_handle_response(node);
		if (ret == KRK_AGAIN) {
			/* header or body not completed */
			krk_event_add(conn->rev);
			return;
		} 

		if (ret == KRK_ERROR) {
			node->nr_fails++;
			if (node->nr_fails == monitor->threshold) {
				node->nr_fails = 0;
				if (!node->down) {
					node->down = 1;
					krk_monitor_notify(monitor, node);
				}
			}

			goto out;
		}

		/* ret == KRK_OK, start to match the response body */

		if (http_match_body(node) == KRK_OK) {
			krk_log(KRK_LOG_DEBUG, "got correct http reply\n");
			node->buf->last = node->buf->head;
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
		krk_log(KRK_LOG_INFO, "write timeout!\n");
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
	struct http_response_header *hrh;

	node->ready = 1;

	node->buf = krk_buffer_create(4096);
	if (!node->buf) {
		node->ready = 0;
		return KRK_ERROR;
	}

	hrh = malloc(sizeof(struct http_response_header));
	if (!hrh) {
		node->ready = 0;
		krk_buffer_destroy(node->buf);
		return KRK_ERROR;
	}

	node->checker_data = hrh;

	return KRK_OK;
}

static int http_cleanup_node(struct krk_node *node)
{
	node->ready = 0;

	krk_buffer_destroy(node->buf);

	free(node->checker_data);

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
