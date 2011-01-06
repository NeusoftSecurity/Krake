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

#define KRK_CONF_PARSE_OK 0
#define KRK_CONF_PARSE_ERROR -1

#define KRK_CONF_RETVAL_LEN 5

struct krk_config {
	char command;
	char type;

	/* args of monitor */
	char monitor[64];
	char checker[64];
	char *checker_conf; /* point to data */
	unsigned long checker_conf_len;

	unsigned long interval;
	unsigned long timeout;
	unsigned long threshold;

	/* args of node */
	char node[16]; /* only accept ip address */
	unsigned short port;

	char data[0]; /* additional data */
};

#endif
