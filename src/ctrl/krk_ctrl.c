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

#include <config.h>
#include <krk_core.h>
#include <krk_socket.h>
#include <krk_config.h>

#define KRK_OPTION_ENABLE 1
#define KRK_OPTION_DISABLE 2
#define KRK_OPTION_CHECKER 3
#define KRK_OPTION_CHECKER_CONF 4
#define KRK_OPTION_MONITOR 5
#define KRK_OPTION_INTERVAL 6
#define KRK_OPTION_TIMEOUT 7
#define KRK_OPTION_THRESHOLD 8
#define KRK_OPTION_NODE 9
#define KRK_OPTION_NODE_PORT 10


static const struct option optlong[] = {
	{"help", 0, NULL, 'h'},
	{"version", 0, NULL, 'v'},
	{"create", 0, NULL, 'C'},
	{"destroy", 0, NULL, 'D'},
	{"add", 0, NULL, 'A'},
	{"remove", 0, NULL, 'R'},
	{"enable", 0, NULL, KRK_OPTION_ENABLE},
	{"disable", 0, NULL, KRK_OPTION_DISABLE},
	{"checker", 1, NULL, KRK_OPTION_CHECKER},
	{"checker-conf", 1, NULL, KRK_OPTION_CHECKER_CONF},
	{"monitor", 1, NULL, KRK_OPTION_MONITOR},
	{"interval", 1, NULL, KRK_OPTION_INTERVAL},
	{"timeout", 1, NULL, KRK_OPTION_TIMEOUT},
	{"threshold", 1, NULL, KRK_OPTION_THRESHOLD},
	{"node", 1, NULL, KRK_OPTION_NODE},
	{"node-port", 1, NULL, KRK_OPTION_NODE_PORT},
	{NULL, 0, NULL, 0}
};

static const char* optstring = "hvCDAR";

static void krk_ctrl_usage(void)
{
	printf("Usage: krakectrl [option]\n"
			"\t--version/-v		Show Krake version\n"
			"\t--help/-h		Show this help\n");
}

static void krk_ctrl_version(void)
{
	printf("Krake ver: %s\n", PACKAGE_VERSION);
}

int main(int argc, char* argv[])
{
	int sock, ret;
	int opt, quit = 0, mutex = 0, n;
	struct sockaddr_un addr;
	struct krk_config config;

	/* TODO:
	 * 1) handle argv
	 * 2) handle socket to krake daemon
	 * 3) send configuration to krake daemon
	 * 4) get result from krake daemon
	 */

	if (argc <= 1) {
		krk_ctrl_usage();
		return 1;
	}

	memset(&config, 0, sizeof(struct krk_config));
	
	while (1) {
		opt = getopt_long(argc, argv, optstring, optlong, NULL);

		if (opt == -1)
			break;

		switch (opt) {
			case 'h':
				krk_ctrl_usage();
				quit = 1;
				break;
			case 'v':
				krk_ctrl_version();
				quit = 1;
				break;
			case 'C':
				if (mutex == 0) {
					config.command = KRK_CONF_CMD_CREATE;
					config.type = KRK_CONF_TYPE_MONITOR;
					mutex = 1;
				} else {
					goto failed;
				}
				break;
			case 'D':
				if (mutex == 0) {
					config.command = KRK_CONF_CMD_DESTROY;
					config.type = KRK_CONF_TYPE_MONITOR;
					mutex = 1;
				} else {
					goto failed;
				}
				break;
			case 'A':
				if (mutex == 0) {
					config.command = KRK_CONF_CMD_ADD;
					config.type = KRK_CONF_TYPE_NODE;
					mutex = 1;
				} else {
					goto failed;
				}
				break;
			case 'R':
				if (mutex == 0) {
					config.command = KRK_CONF_CMD_REMOVE;
					config.type = KRK_CONF_TYPE_NODE;
					mutex = 1;
				} else {
					goto failed;
				}
				break;
			case KRK_OPTION_ENABLE:
				if (mutex == 0) {
					config.command = KRK_CONF_CMD_ENABLE;
					config.type = KRK_CONF_TYPE_MONITOR;
					mutex = 1;
				} else {
					goto failed;
				}
				break;
			case KRK_OPTION_DISABLE:
				if (mutex == 0) {
					config.command = KRK_CONF_CMD_DISABLE;
					config.type = KRK_CONF_TYPE_MONITOR;
					mutex = 1;
				} else {
					goto failed;
				}
				break;
			default:
				/* never could be here */
				break;
		}
	}

	if (quit) {
		return 0;
	}

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

	n = send(sock, &config, sizeof(config), 0);

	close(sock);

	return 0;

failed:
	fprintf(stderr, "%s: parse command line failed\n", argv[0]);
	return 1;
}
