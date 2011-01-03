/**
 * krk_config.h - Krake configuration
 * 
 * Copyright (c) 2010 Yang Yang <paulyang.inf@gmail.com>
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef __KRK_CONFIG_H__
#define __KRK_CONFIG_H__

extern void krk_config_read(int sock, short type, void *arg);
extern void krk_config_write(int sock, short type, void *arg);

#define KRK_CONFIG_MAX_LEN 4096

#define KRK_CONF_CMD_CREATE 1
#define KRK_CONF_CMD_DESTROY 2
#define KRK_CONF_CMD_ADD 3
#define KRK_CONF_CMD_REMOVE 4
#define KRK_CONF_CMD_ENABLE 5
#define KRK_CONF_CMD_DISABLE 6

#define KRK_CONF_TYPE_MONITOR 1
#define KRK_CONF_TYPE_NODE 2

struct krk_config {
	char command;
	char type;	/* if command is enable/disable,
				 * type indicate monitor/node
				 */

	/* args of monitor */
	char monitor_name[64];
	unsigned short monitor_checker;
	void *checker_conf;
	unsigned long checker_conf_len;

	/* args of node */
	char node_name[16]; /* only accept ip address */
	unsigned short node_port;
};

#endif
