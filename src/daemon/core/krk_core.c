/**
 * krk_core.c - Krake core
 * 
 * Copyright (c) 2010 Yang Yang <paulyang.inf@gmail.com>
 *
 * This file is the entry of krake daemon, it handles cmd-line args
 * and go into the main event loop.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <config.h>
#include <krk_core.h>
#include <krk_socket.h>

static const struct option optlong[] = {
	{"pid-file", 1, NULL, 'p'},
	{"help", 0, NULL, 'h'},
	{"version", 0, NULL, 'v'},
	{NULL, 0, NULL, 0}
};

static const char* optstring = "p:hv";

static void krk_usage(void)
{
	printf("Usage: krake [option]\n"
			"\t--pid-file/-p	Change path of pid file, default is /tmp/krake.pid\n"
			"\t--version/-v		Show Krake version\n"
			"\t--help/-h		Show this help\n");
}

static void krk_version(void)
{
	printf("Krake ver: %s\n", PACKAGE_VERSION);
}

/**
 *	krk_daemonize - daemonize routine
 *	@
 *
 *	a "standard" daemon init routine according to 
 *	Richard Stevens' APUE.
 *	returns 0 for success.
 */
static int krk_daemonize(void)
{
	pid_t pid;

	if ((pid = fork()) < 0)
		return -1;
	else if (pid != 0)
		exit(0);

	setsid();
	
	if (chdir("/"))
		return -1;

	umask(0);

	return 0;
}

int main(int argc, char* argv[])
{
	int opt, quit = 0;
	char pid_file[PATH_MAX] = {0};
	
	/**
	 * 1) Handle the args;
	 * 2) Make myself a daemon;
	 * 3) Enter main loop and wait for some events.
	 */

	while (1) {
		opt = getopt_long(argc, argv, optstring, optlong, NULL);

		if (opt == -1)
			break;

		switch (opt) {
			case 'p':
				if (strlen(optarg) >= PATH_MAX) {
					fprintf(stderr, "Fatal: pid filename too long\n");
					exit(1);
				}
				
				strcpy(pid_file, optarg);
				break;
			case 'h':
				krk_usage();
				quit = 1;
				break;;
			case 'v':
				krk_version();
				quit = 1;
				break;
			default:
				/* never could be here */
				break;
		}
	}

	if (quit)
		return 0;

	/* handle pid file */
	
	/* daemonize myself */
	if (krk_daemonize()) {
		fprintf(stderr, "Fatal: failed to become a daemon\n");
		return 1;
	}
	
	return 0;
}
