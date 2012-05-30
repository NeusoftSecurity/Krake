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
#include <config_layout.h>
#include <krk_core.h>
#include <krk_socket.h>
#include <krk_event.h>
#include <krk_connection.h>
#include <krk_monitor.h>
#include <krk_log.h>

static const struct option optlong[] = {
    {"help", 0, NULL, 'h'},
    {"version", 0, NULL, 'v'},
    {"config", 0, NULL, 'c'},
    {"reload", 0, NULL, 'r'},
    {"show", 0, NULL, 's'},
    {"quit", 0, NULL, 'q'},
    {NULL, 0, NULL, 0}
};

static const char* optstring = "hvrmqs:c:";

static void krk_usage(void)
{
    printf("Usage: krake [option]\n"
            "\t--config/-c		Assign the configruation file\n"
            "\t--reload/-r		Reload the configruation file\n"
            "\t--show/-s		Show the configruation, -s all for all monitor, -s monitor_name for one monitor\n"
            "\t--quit/-q		Shutdown the krake\n"
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

    //fclose(stderr);

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

static inline pid_t krk_get_daemon_pid(void)
{
    pid_t pid;
    int n;
    int fd = 0;

    fd = open(PID_FILE, O_RDONLY, S_IRUSR | S_IWUSR);

    if (fd < 0) {
        fprintf(stderr, "Fatal: get pid failed!\n");
        return -1;
    }

    n = read(fd, &pid, sizeof(pid));
    if (n != sizeof(pid)) {
        fprintf(stderr, "Fatal: write pid file failed\n");
        close(fd);
        return -1;
    }

    close(fd);

    return pid;
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

    krk_ssl_exit();

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

#define KRK_CONFIG_FILE_NAME_LEN 200

char krk_config_file[KRK_CONFIG_FILE_NAME_LEN] = {};

static inline int krk_connect_local(void)
{
	struct sockaddr_un addr;
    int sockfd = 0;
    int ret = 0;

	sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sockfd < 0) {
		perror("socket");
		return -1;
	}

	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, LOCAL_SOCK_PATH, 
			sizeof(addr.sun_path) - 1);

	ret = connect(sockfd, (struct sockaddr*)&addr, sizeof(struct sockaddr_un));
	if (ret < 0) {
        close(sockfd);
		perror("connect");
		return -1;
	}

    return sockfd;
}

static inline void krk_reload_config(void)
{
    struct krk_config_ret conf_ret = {};
    int sockfd = 0;
    int snd_len = 0;
    int ret = 0;

	sockfd = krk_connect_local();
	if (sockfd < 0) {
		perror("socket");
		return;
	}

    conf_ret.retval = KRK_CONF_RET_RELOAD; 
	snd_len = send(sockfd, &conf_ret, sizeof(conf_ret), 0);
    if (snd_len < 0) {
        perror("send");
    }

    close(sockfd);
}

static inline void krk_show_monitor_config(char *name)
{
    struct krk_config_ret conf_ret = {};
    char m_name[KRK_NAME_LEN] = {};
    void *buf = NULL;
    void *rcv_buf = NULL;
    struct krk_node_info *n_info = NULL;
    int sockfd = 0;
    int buf_size = 0;
    int buf_len = 0;
    int snd_len = 0;
    int rcv_len = 0;
    int ret = 0;

    if (!strcmp(name, "all")) {
        conf_ret.retval = KRK_CONF_RET_SHOW_ALL_MONITOR; 
        buf_size = KRK_MONITOR_MAX_NR * KRK_NAME_LEN;
    } else {
        conf_ret.retval = KRK_CONF_RET_SHOW_ONE_MONITOR; 
        strncpy(conf_ret.monitor, name, KRK_NAME_LEN);
        buf_size = (sizeof(struct krk_monitor_info) + KRK_NODE_MAX_NUM * sizeof(struct krk_node_info));
    }

    buf = calloc(1, buf_size);
    if (buf == NULL) {
        printf("alloc mem failed!\n");
        return;
    }

	sockfd = krk_connect_local();
	if (sockfd < 0) {
		perror("socket");
        goto out;
	}

	snd_len = send(sockfd, &conf_ret, sizeof(conf_ret), 0);
    if (snd_len < sizeof(conf_ret)) {
        perror("send");
        goto out;
    }

    while (1) {
        rcv_buf = buf + rcv_len;
        rcv_len = recv(sockfd, rcv_buf, buf_size, 0);
        if (rcv_len < 0) {
            perror("recv");
            goto out;
        }

        if (rcv_len == 0) {
            break;
        }
        buf_size -= rcv_len;
        buf_len += rcv_len;
    }

    if (buf_len == 0) {
        goto out;
    }

    if (!strcmp(name, "all")) {
        rcv_buf = buf;
        while (buf_len > 0) {
            strncpy(m_name, rcv_buf, KRK_NAME_LEN);
            fprintf(stderr, "Monitor: %s\n", m_name);
            buf_len -= KRK_NAME_LEN;
            rcv_buf += KRK_NAME_LEN;
        }
    } else {
        krk_show_monitor_info(buf);
        n_info = buf + sizeof(struct krk_monitor_info);
        buf_len -= sizeof(struct krk_monitor_info);
        if (buf_len == 0) {
            goto out;
        }

        fprintf(stderr, "node informations:\n");
        while (buf_len > 0) {
            fprintf(stderr, "====================\n");
            krk_show_node_info(n_info);
            fprintf(stderr, "====================\n");
            buf_len -= sizeof(struct krk_node_info);
            n_info++;
        }
    }

out:
    if (buf != NULL) {
        free(buf);
    }
    close(sockfd);
}


static inline void krk_show_config(int signo)
{
    krk_monitor_show();
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
    signal(SIGUSR2, krk_show_config);
}

int main(int argc, char* argv[])
{
    pid_t pid;
    char monitor[KRK_NAME_LEN] = {};
    int opt, quit = 0;

    strncpy(krk_config_file, KRK_DEFAULT_CONF, KRK_CONFIG_FILE_NAME_LEN);

    if (argc == 1) {
        goto start;
    }

    while (1) {
        opt = getopt_long(argc, argv, optstring, optlong, NULL);

        if (opt == -1) {
            quit = 1;
            break;
        }

        switch (opt) {
            case 'h':
                krk_usage();
                quit = 1;
                break;;
            case 'v':
                krk_version();
                quit = 1;
                break;
            case 'c':
                if (strlen(optarg) > KRK_CONFIG_FILE_NAME_LEN) {
                    quit = 1;
                }
                strcpy(krk_config_file, optarg);
                break;
            case 'r':
                krk_reload_config();
                return 0;
            case 's':
                strncpy(monitor, optarg, KRK_NAME_LEN);
                krk_show_monitor_config(monitor);
                return 0;
            case 'm':
                pid = krk_get_daemon_pid();
                if (pid < 0) {
                    printf("Show configuration failed!\n");
                    return -1;
                }
                kill(pid, SIGUSR2);
                return 0;
            case 'q':
                pid = krk_get_daemon_pid();
                if (pid < 0) {
                    printf("Shutdown krake failed!\n");
                    return -1;
                }
                kill(pid, SIGTERM);
                return 0;
            

            default:
                /* never could be here */
                break;
        }
    }

    if (quit) {
        return 0;
    }

start:
    /* daemonize myself */
    if (krk_daemonize()) {
        fprintf(stderr, "Fatal: failed to become a daemon\n");
        return 1;
    }

    /* pid file must be handled after daemonize */
    if(krk_create_pid_file()) {
        fprintf(stderr, "Fatal: create pid file failed!\n");
        return 1;
    }

    /* handle signals */
    krk_signals();

    if (krk_log_init()) {
        fprintf(stderr, "Fatal: init log failed\n");
        krk_remove_pid_file();
        return 1;
    }

    if (krk_connection_init()) {
        krk_log(KRK_LOG_ALERT, "Fatal: init connection failed\n");
        krk_remove_pid_file();
        return 1;
    }

    if (krk_event_init()) {
        krk_log(KRK_LOG_ALERT, "Fatal: init event failed\n");
        krk_remove_pid_file();
        return 1;
    }

    if (krk_ssl_init()) {
        krk_log(KRK_LOG_ALERT, "Fatal: init ssl failed\n");
        krk_remove_pid_file();
        return 1;
    }

    if (krk_local_socket_init()) {
        krk_log(KRK_LOG_ALERT, "Fatal: init local socket failed\n");
        krk_remove_pid_file();
        return 1;
    }

    if (krk_monitor_init()) {
        krk_log(KRK_LOG_ALERT, "Fatal: init monitor failed\n");
        krk_remove_pid_file();
        return 1;
    }

    if (krk_config_load(krk_config_file)) {
        krk_log(KRK_LOG_ALERT, "Fatal: failed to load configuration file!\n");
        krk_remove_pid_file();
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
