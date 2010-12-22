/**
 * krk_socket.c - functions related to socket
 * 
 * Copyright (c) 2010 Yang Yang <paulyang.inf@gmail.com>
 *
 * This file contains the functions related to socket, such as
 * event process, 
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

void krk_local_accept(int listen_sock, short type, void *arg)
{
	fprintf(stderr, "accept one unix connection\n");
}

static int krk_open_local_socket(void)
{
	int sock, ret;
	struct sockaddr_un addr;

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		fprintf(stderr, "Fatal: create unix socket failed\n");
		return -1;
	}

	fcntl(sock, F_SETFL, O_NONBLOCK);

	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, "/tmp/krake.sock", 
			sizeof(addr.sun_path) - 1);
	
	ret = bind(sock, (struct sockaddr*)&addr, sizeof(struct sockaddr_un));
	if (ret < 0) {
		fprintf(stderr, "Fatal: bind unix socket failed\n");
		return -1;
	}

	ret = listen(sock, 5);
	if (ret < 0) {
		fprintf(stderr, "Fatal: listen unix socket failed\n");
		return -1;
	}

	return sock;
}

static int krk_close_local_socket(int local_sock)
{
	return close(local_sock);
}

/**
 * krk_local_socket_init - init the cmd channel
 * @
 *
 * open a unix tcp socket for receive commands
 * from krakectrl, return 0 if success.
 */
int krk_local_socket_init(void) 
{
	int sock;
	struct krk_connection *listen_conn;

	sock = krk_open_local_socket();
	if (sock < 0) {
		return -1;
	}

	listen_conn = krk_connection_create("local_listen");
	if (!listen_conn) {
		return -1;
	}

	listen_conn->sock = sock;
	listen_conn->rev->handler = krk_local_accept;

	krk_event_set_read(sock, listen_conn->rev);

	return krk_event_add(listen_conn->rev);
}
