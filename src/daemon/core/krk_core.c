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
#include <krk_event.h>
#include <krk_connection.h>
#include <krk_monitor.h>
#include <krk_log.h>

static const struct option optlong[] = {
	{"help", 0, NULL, 'h'},
	{"version", 0, NULL, 'v'},
	{NULL, 0, NULL, 0}
};

static const char* optstring = "hv";

static void krk_usage(void)
{
	printf("Usage: krake [option]\n"
			"\t--version/-v		Show Krake version\n"
			"\t--help/-h		Show this help\n");
}

static void krk_version(void)
{
	printf("Krake ver: %s\n", PACKAGE_VERSION);
}

/**
 * krk_daemonize - daemonize routine
 * @
 *
 * a "standard" daemon init routine according to 
 * Richard Stevens' APUE.
 * returns 0 for success.
 */
static inline int krk_daemonize(void)
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

inline int krk_remove_pid_file()
{
	int ret;

	ret = unlink(PID_FILE);
	if (ret) 
		return -1;
	
	return 0;
}

/**
 * krk_create_pid_file - check and create pid file
 * @
 *
 * check if there is a pid file already. if not, 
 * create a new one.
 */
static inline int krk_create_pid_file(void)
{
	pid_t pid;
	int n;
	int fd = 0;
	
	fd = open(PID_FILE, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
	
	if (fd < 0 && errno == EEXIST) {
		fprintf(stderr, "Fatal: krake already running\n");
		return -1;
	} else {
		pid = getpid();
		
		n = write(fd, &pid, sizeof(pid));
		if (n != sizeof(pid)) {
			fprintf(stderr, "Fatal: write pid file failed\n");
			(void)krk_remove_pid_file();
			close(fd);
			return -1;
		}
	}

	close(fd);
	
	return 0;
}

/** 
 * should I move the signal related functions 
 * into a new file? 
 */
static inline int __krk_smooth_quit(void)
{
	krk_local_socket_exit();
	krk_remove_pid_file();
	
	krk_monitor_exit();

	krk_connection_exit();
	
	krk_event_exit();
	
	krk_log_exit();

	return KRK_OK;
}

static inline void krk_smooth_quit(int signo)
{
	int ret;

	krk_log(KRK_LOG_NOTICE, "caught signal %d\n", signo);

	ret = __krk_smooth_quit();

	if (ret)
		exit(1);
	else
		exit(0);
}

static inline void krk_child_quit(int signo)
{
	pid_t pid;
	int status;

	while((pid = waitpid(-1, &status, WNOHANG)) > 0) {
		/* do nothing */
	}
}

static inline void krk_signals(void)
{
	signal(SIGINT, krk_smooth_quit);	
	signal(SIGKILL, krk_smooth_quit);	
	signal(SIGQUIT, krk_smooth_quit);	
	signal(SIGTERM, krk_smooth_quit);	
	signal(SIGSEGV, krk_smooth_quit);
	signal(SIGBUS, krk_smooth_quit);
	signal(SIGCHLD, krk_child_quit);
}

int main(int argc, char* argv[])
{
	int opt, quit = 0;

	while (1) {
		opt = getopt_long(argc, argv, optstring, optlong, NULL);

		if (opt == -1)
			break;

		switch (opt) {
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
	
	/* daemonize myself */
	if (krk_daemonize()) {
		fprintf(stderr, "Fatal: failed to become a daemon\n");
		return 1;
	}
	
	/* pid file must be handled after daemonize */
	if(krk_create_pid_file()) {
		return 1;
	}

	/* handle signals */
	krk_signals();
	
	if (krk_log_init()) {
		fprintf(stderr, "Fatal: init log failed\n");
		return 1;
	}

	if (krk_connection_init()) {
		krk_log(KRK_LOG_ALERT, "Fatal: init connection failed\n");
		return 1;
	}
	
	if (krk_event_init()) {
		krk_log(KRK_LOG_ALERT, "Fatal: init event failed\n");
		return 1;
	}

	if (krk_local_socket_init()) {
		krk_log(KRK_LOG_ALERT, "Fatal: init event failed\n");
		return 1;
	}

	if (krk_monitor_init()) {
		krk_log(KRK_LOG_ALERT, "Fatal: init event failed\n");
		return 1;
	}

	krk_log(KRK_LOG_NOTICE, "krake started\n");
	krk_event_loop();

	/* quit */
	if (__krk_smooth_quit()) {
		krk_log(KRK_LOG_ALERT, "Fatal: smooth quit failed\n");
		return 1;
	}
	
	return 0;
}
