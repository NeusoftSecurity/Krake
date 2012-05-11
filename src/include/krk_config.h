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

#include <krk_core.h>

#define KRK_CONFIG_MAX_LEN 4096

#define KRK_CONF_CMD_CREATE 1
#define KRK_CONF_CMD_DESTROY 2
#define KRK_CONF_CMD_ADD 3
#define KRK_CONF_CMD_REMOVE 4
#define KRK_CONF_CMD_ENABLE 5
#define KRK_CONF_CMD_DISABLE 6
#define KRK_CONF_CMD_SHOW 7
#define KRK_CONF_CMD_FLUSH 8
#define KRK_CONF_CMD_LOG 9

#define KRK_CONF_TYPE_MONITOR 1
#define KRK_CONF_TYPE_NODE 2
#define KRK_CONF_TYPE_LOG 3

#define KRK_CONF_RETVAL_LEN 5

#define KRK_CONF_DEFAULT_INTERVAL 5
#define KRK_CONF_DEFAULT_TIMEOUT 3
#define KRK_CONF_DEFAULT_THRESHOLD 3

struct krk_config_monitor {
    char monitor[KRK_NAME_LEN];
    unsigned long interval;
    unsigned long timeout;
    unsigned long threshold;

    char checker[KRK_NAME_LEN];
    unsigned long checker_param_len;

    unsigned int nr_nodes;
};

struct krk_config_node {
    struct krk_config_node *next;
    char addr[KRK_IPADDR_LEN]; /* only accept ip address */
    unsigned short port;

    unsigned int down:1;
};

struct krk_config {
    char command;
    /* args of monitor */
    char monitor[KRK_NAME_LEN];
    char checker[KRK_NAME_LEN];
    char *checker_param;
    unsigned long checker_param_len;
    char script[KRK_NAME_LEN];

    unsigned long interval;
    unsigned long timeout;
    unsigned long threshold;

    /* log */
    char log_type[KRK_ARG_LEN];
    char log_level[KRK_ARG_LEN];

    /* args of node */
    struct krk_config_node *node;
    unsigned long node_num;
};

struct krk_config_ret {
    int retval;
    unsigned int data_len;
};

extern int krk_config_load (char *config_file);

#endif
