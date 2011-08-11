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
#include <krk_monitor.h>
#include <checkers/krk_checker.h>

#define KRK_OPTION_ENABLE 1
#define KRK_OPTION_DISABLE 2
#define KRK_OPTION_CHECKER 3
#define KRK_OPTION_CHECKER_PARAM 4
#define KRK_OPTION_MONITOR 5
#define KRK_OPTION_INTERVAL 6
#define KRK_OPTION_TIMEOUT 7
#define KRK_OPTION_THRESHOLD 8
#define KRK_OPTION_NODE 9
#define KRK_OPTION_PORT 10
#define KRK_OPTION_SCRIPT 11


static const struct option optlong[] = {
	{"help", 0, NULL, 'h'},
	{"version", 0, NULL, 'v'},
	{"create", 0, NULL, 'C'},
	{"destroy", 0, NULL, 'D'},
	{"add", 0, NULL, 'A'},
	{"remove", 0, NULL, 'R'},
	{"show", 0, NULL, 'S'},
	{"enable", 0, NULL, KRK_OPTION_ENABLE},
	{"disable", 0, NULL, KRK_OPTION_DISABLE},
	{"checker", 1, NULL, KRK_OPTION_CHECKER},
	{"checker-param", 1, NULL, KRK_OPTION_CHECKER_PARAM},
	{"monitor", 1, NULL, KRK_OPTION_MONITOR},
	{"interval", 1, NULL, KRK_OPTION_INTERVAL},
	{"timeout", 1, NULL, KRK_OPTION_TIMEOUT},
	{"threshold", 1, NULL, KRK_OPTION_THRESHOLD},
	{"node", 1, NULL, KRK_OPTION_NODE},
	{"port", 1, NULL, KRK_OPTION_PORT},
	{"script", 1, NULL, KRK_OPTION_SCRIPT},
	{NULL, 0, NULL, 0}
};

static const char* optstring = "hvCDARS";

static void krk_ctrl_title(void)
{
	printf("%s, version %s\n\n", PACKAGE_NAME, PACKAGE_VERSION);
}

static void krk_ctrl_tail(void)
{
	printf("\nReport bugs to <%s>\n", PACKAGE_BUGREPORT);
	printf("Krake homepage: <%s>\n", PACKAGE_URL);
	printf("Copyright (c) 2010 Yang Yang <paulyang.inf@gmail.com>\n");
}

static void krk_ctrl_usage(void)
{
	krk_ctrl_title();
	printf("Usage: krakectrl [option]\n"
			"options:\n"
			"\t-v, --version		show version\n"
			"\t-h, --help		show this help\n"
			"\t-C, --create		create a new monitor\n"
			"\t-D, --destroy		destroy a monitor\n"
			"\t-A, --add		add a node to a monitor\n"
			"\t-R, --remove		remove a node from a monitor\n"
			"\t-S, --show		show the configuration of a monitor\n"
			"\t--enable		enable a monitor, this option starts the monitor's timer\n"
			"\t--disable		disable a monitor, this option stops the monitor's timer\n"
			"\t--checker		specify a checker using by a monitor, use \"help\" \n"
			"\t         		to see the checker list\n"
			"\t--checker-param		checker's parameters\n"
			"\t--monitor		name of a monitor\n"
			"\t--interval		interval of monitor's timer in seconds\n"
			"\t--timeout		time out value of checked host in seconds\n"
			"\t--threshold		how many times of failures happens, marking host as down\n"
			"\t--node		ip address of a checked host, either ipv4 or ipv6 address is valid\n"
			"\t--port		port number of a checked host, range is 1 ~ 65535\n"
			"\t--script		failure notification, if user specify this option, \n"
			"\t        		when a failure of a checked host is deteceted, krake will call this script\n"
		  );
	krk_ctrl_tail();
}

static void krk_ctrl_version(void)
{
	printf("Krake version: %s\n", PACKAGE_VERSION);
}

static void krk_ctrl_show_one_monitor(void *data, unsigned int len)
{
	struct krk_config_monitor *monitor;
	struct krk_config_node *node;
	char *checker_param;
	int i;

	monitor = (struct krk_config_monitor *)data;

	fprintf(stdout, "Monitor Info:\n");
	fprintf(stdout, "\tmonitor: %s\n", monitor->monitor);
	fprintf(stdout, "\tinterval: %lu\n", monitor->interval);
	fprintf(stdout, "\ttimeout: %lu\n",monitor->timeout);
	fprintf(stdout, "\tthreshold: %lu\n",monitor->threshold);
	fprintf(stdout, "\tchecker: %s\n", monitor->checker);

	if (monitor->checker_param_len) {
		checker_param = malloc(monitor->checker_param_len + 1);
		if (checker_param == NULL) {
			fprintf(stdout, "Out of memory\n");
			return;
		}

		snprintf(checker_param, monitor->checker_param_len, "%s", 
				(char *)(data + sizeof(struct krk_config_monitor)));
		fprintf(stdout, "\t\tchecker_param: %s\n", checker_param);
	}

	fprintf(stdout, "\tnr_nodes: %u\n", monitor->nr_nodes);
	
	if (monitor->nr_nodes) {
		node = (struct krk_config_node *)(data + sizeof(struct krk_config_monitor) + 
			monitor->checker_param_len);

		for (i = 0; i < monitor->nr_nodes; i++) {
			fprintf(stdout, "\t\tnode: %s:%u %s\n", node[i].addr, node[i].port, 
					node[i].down ? "down" : "up");
		}
	}
}

static void krk_ctrl_show_monitor_names(void *data, unsigned int len)
{
	char *name;
	int i;

	name = (char *)data;

	fprintf(stdout, "Monitor List:\n");
	for(i = 0; i < len; i++) {
		if (*name)
			fprintf(stderr, "\t%s\n", name);
		name += KRK_NAME_LEN;
	}
}

int main(int argc, char* argv[])
{
	int sock, ret, len;
	int opt, quit = 0, mutex = 0, n = 0, param_len = 0;
	void *ptr, *data;
	struct sockaddr_un addr;
	struct krk_config *config;
	struct krk_config_ret *result;

	/* 
	 * 1) handle argv
	 * 2) handle socket to krake daemon
	 * 3) send configuration to krake daemon
	 * 4) get result from krake daemon
	 */

	if (argc <= 1) {
		krk_ctrl_usage();
		return 1;
	}

	config = malloc(sizeof(struct krk_config));
	memset(config, 0, sizeof(struct krk_config));
	
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
					config->command = KRK_CONF_CMD_CREATE;
					config->type = KRK_CONF_TYPE_MONITOR;
					mutex = 1;
				} else {
					goto failed;
				}
				break;
			case 'D':
				if (mutex == 0) {
					config->command = KRK_CONF_CMD_DESTROY;
					config->type = KRK_CONF_TYPE_MONITOR;
					mutex = 1;
				} else {
					goto failed;
				}
				break;
			case 'S':
				if (mutex == 0) {
					config->command = KRK_CONF_CMD_SHOW;
					config->type = KRK_CONF_TYPE_MONITOR;
					mutex = 1;
				} else {
					goto failed;
				}
				break;
			case 'A':
				if (mutex == 0) {
					config->command = KRK_CONF_CMD_ADD;
					config->type = KRK_CONF_TYPE_NODE;
					mutex = 1;
				} else {
					goto failed;
				}
				break;
			case 'R':
				if (mutex == 0) {
					config->command = KRK_CONF_CMD_REMOVE;
					config->type = KRK_CONF_TYPE_NODE;
					mutex = 1;
				} else {
					goto failed;
				}
				break;
			case KRK_OPTION_ENABLE:
				if (mutex == 0) {
					config->command = KRK_CONF_CMD_ENABLE;
					config->type = KRK_CONF_TYPE_MONITOR;
					mutex = 1;
				} else {
					goto failed;
				}
				break;
			case KRK_OPTION_DISABLE:
				if (mutex == 0) {
					config->command = KRK_CONF_CMD_DISABLE;
					config->type = KRK_CONF_TYPE_MONITOR;
					mutex = 1;
				} else {
					goto failed;
				}
				break;
			case KRK_OPTION_MONITOR:
				if (config->type == KRK_CONF_TYPE_MONITOR
						|| config->type == KRK_CONF_TYPE_NODE) {
					strncpy(config->monitor, optarg, KRK_NAME_LEN);
					config->monitor[KRK_NAME_LEN - 1] = 0;
				} else {
					goto failed;
				}
				break;
			case KRK_OPTION_CHECKER:
				if (config->type == KRK_CONF_TYPE_MONITOR
						&& config->monitor[0]) {
					strncpy(config->checker, optarg, KRK_NAME_LEN);
					config->checker[KRK_NAME_LEN - 1] = 0;
				} else {
					goto failed;
				}
				break;
			case KRK_OPTION_CHECKER_PARAM:
				if (config->type == KRK_CONF_TYPE_MONITOR
						&& config->checker[0]) {
					param_len = strlen(optarg) + 1;
					config = realloc(config, 
							sizeof(struct krk_config) + param_len);
					config->checker_param = config->data;
					memset(config->checker_param, 0, param_len);
					strcpy(config->checker_param, optarg);
					config->checker_param_len = param_len;
				} else {
					goto failed;
				}
				break;
			case KRK_OPTION_INTERVAL:
				if (config->type == KRK_CONF_TYPE_MONITOR
						&& config->monitor[0]) {
					config->interval = atoi(optarg);
				} else {
					goto failed;
				}
				break;
			case KRK_OPTION_TIMEOUT:
				if (config->type == KRK_CONF_TYPE_MONITOR
						&& config->monitor[0]) {
					config->timeout = atoi(optarg);
				} else {
					goto failed;
				}
				break;
			case KRK_OPTION_THRESHOLD:
				if (config->type == KRK_CONF_TYPE_MONITOR
						&& config->monitor[0]) {
					config->threshold = atoi(optarg);
				} else {
					goto failed;
				}
				break;
			case KRK_OPTION_NODE:
				if (config->type == KRK_CONF_TYPE_NODE
						&& config->monitor[0]) {
					strncpy(config->node, optarg, KRK_IPADDR_LEN);
					config->node[KRK_IPADDR_LEN - 1] = 0;
				} else {
					goto failed;
				}
				break;
			case KRK_OPTION_PORT:
				if (config->type == KRK_CONF_TYPE_NODE
						&& config->node[0]) {
					config->port = atoi(optarg);
				} else {
					goto failed;
				}
				break;
			case KRK_OPTION_SCRIPT:
				if (config->type == KRK_CONF_TYPE_MONITOR) {
					strncpy(config->script, optarg, KRK_NAME_LEN);
					config->script[KRK_NAME_LEN - 1] = 0;
				} else {
					goto failed;
				}
				break;
			default:
				/* never could be here */
				goto failed;
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

	ptr = config;
	len = sizeof(struct krk_config) + param_len;
	
	while(1) {
		n = send(sock, ptr, len, 0);
		if (n < 0) {
			perror("send");
			return 1;
		}

		if (n == len) {
			break;
		} else {
			ptr += n;
			len -= n;
		}
	}

	/* wait for reply from krake daemon */
	result = malloc(sizeof(struct krk_config_ret));
	len = sizeof(struct krk_config_ret);
	ptr = result;

	while (1) {
		n = recv(sock, ptr, len, 0);
		if (n < 0) {
			perror("recv");
			return 1;
		}

		if (n == len) {
			break;
		} else {
			ptr += n;
			len -= n;
		}
	}

	if (result->retval != KRK_OK) {
		fprintf(stderr, "Daemon parse failed\n");
		fprintf(stderr, "result is %d\n", result->retval);
		goto failed;
	}

	if (result->data_len != 0) {
		len = result->data_len;
		data = malloc(len);

		while (1) {
			n = recv(sock, data, len, 0);
			if (n < 0) {
				perror("recv");
				return 1;
			}

			if (n == len) {
				break;
			} else {
				ptr += n;
				len -= n;
			}
		}

		if (config->command == KRK_CONF_CMD_SHOW) {
			if (config->monitor[0]) {
				krk_ctrl_show_one_monitor(data, result->data_len);
			} else {
				krk_ctrl_show_monitor_names(data, result->data_len);
			}
		}
		
		free(data);
	}

	close(sock);
	free(result);
	free(config);

	return 0;

failed:
	fprintf(stderr, "Parse command line failed\n");
	return 1;
}
