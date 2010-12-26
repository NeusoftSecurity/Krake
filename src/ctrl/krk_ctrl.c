/**
 * krk_ctrl.c - Krake configuration client
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


int main(int argc, char* argv[])
{
	int sock, ret;
	struct sockaddr_un addr;
	char buf[] = "Hello krake daemon\n";

	/* TODO:
	 * 1) handle argv
	 * 2) handle socket to krake daemon
	 * 3) send configuration to krake daemon
	 * 4) get result from krake daemon
	 */
	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("socket");
		return 1;
	}

	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, LOCAL_SOCK_PATH, 
			sizeof(addr.sun_path) - 1);

	ret = connect(sock, (struct sockaddr*)&addr, sizeof(struct sockaddr_un));
	if (ret < 0) {
		perror("connect");
		return 1;
	}

	ret = send(sock, buf, sizeof(buf), 0);

	close(sock);

	return 0;
}
