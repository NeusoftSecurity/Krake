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

void krk_config_read(int sock, short type, void *arg);
void krk_config_write(int sock, short type, void *arg);

int krk_config_process(struct krk_connection *conn)
{
	/* return value to client */
//	krk_event_set_write(sock, conn->wev);
//	krk_event_add(wev);

	return 0;
}

void krk_config_read(int sock, short type, void *arg)
{
	int n, ret;
	struct krk_event *rev;
	struct krk_connection *conn;
	
	fprintf(stderr, "read config\n");

	rev = arg;
	conn = rev->conn;
	
	n = recv(sock, rev->buf->last, rev->buf->end - rev->buf->last, 0);
	if (n == 0 || n < 0) {
		fprintf(stderr, "read config finished or error\n");
		krk_connection_destroy(conn);
		return;
	}

	ret = krk_config_process(conn);
	if (ret == KRK_AGAIN) {
		/* KRK_AGAIN means command not completed */
		goto re_arm;
	}

re_arm:
	krk_event_set_read(sock, rev);
	krk_event_add(rev);
}

void krk_config_write(int sock, short type, void *arg)
{

}
