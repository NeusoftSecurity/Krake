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

int krk_open_local_socket(void);

/**
 * krk_open_local_socket - open a unix socket
 * @
 *
 * open a unix tcp socket for receive commands
 * from krakectrl, return 0 if success.
 */
int krk_open_local_socket(void)
{
	int sock;
	struct sockaddr_un addr;

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		fprintf(stderr, "Fatal: create unix socket failed\n");
		return -1;
	}

	fcntl(sock, F_SETFL, O_NONBLOCK);
}


