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

#include <stdbool.h>
#include <krk_core.h>

#define KRK_CONFIG_MAX_LEN 4096

#define KRK_CONF_MONITOR_NAME           0x001
#define KRK_CONF_MONITOR_STATUS         0x002
#define KRK_CONF_MONITOR_CHECKER        0x004
#define KRK_CONF_MONITOR_CHECKER_PARAM  0x008
#define KRK_CONF_MONITOR_INTERVAL       0x010
#define KRK_CONF_MONITOR_TIMEOUT        0x020
#define KRK_CONF_MONITOR_F_THRESHOLD      0x040
#define KRK_CONF_MONITOR_S_THRESHOLD      0x080
#define KRK_CONF_MONITOR_SCRIPT         0x100
#define KRK_CONF_MONITOR_LOG            0x200
#define KRK_CONF_MONITOR_LOGTYPE        0x400
#define KRK_CONF_MONITOR_LOGLEVEL       0x800

#define KRK_CONF_MONITOR_NODE_HOST      0x01
#define KRK_CONF_MONITOR_NODE_PORT      0x02

#define KRK_CONF_TYPE_MONITOR 1
#define KRK_CONF_TYPE_NODE 2
#define KRK_CONF_TYPE_LOG 3

#define KRK_CONF_RETVAL_LEN 5

#define KRK_CONF_DEFAULT_INTERVAL 5
#define KRK_CONF_DEFAULT_TIMEOUT 3
#define KRK_CONF_DEFAULT_F_THRESHOLD 3
#define KRK_CONF_DEFAULT_S_THRESHOLD 3

struct krk_config_node {
    struct krk_config_node *next;
    unsigned int config;
    char addr[KRK_IPADDR_LEN]; /* only accept ip address */
    unsigned short port;
};

struct krk_config_monitor {
    struct krk_config_monitor *next;
    unsigned int config;
    bool enable;
    /* args of monitor */
    char monitor[KRK_NAME_LEN];
    char checker[KRK_NAME_LEN];
    char *checker_param;
    unsigned long checker_param_len;
    char script[KRK_NAME_LEN];

    unsigned long interval;
    unsigned long timeout;
    unsigned long failure_threshold;
    unsigned long success_threshold;

    /* args of node */
    struct krk_config_node *node;
};

struct krk_config_log {
    unsigned int config;
    char log_type[KRK_ARG_LEN];
    char log_level[KRK_ARG_LEN];
};

struct krk_config {
    unsigned int config;
    struct krk_config_monitor *monitor;
    struct krk_config_log log;
};

enum {
    KRK_CONF_RET_RELOAD = 1,
    KRK_CONF_RET_SHOW_ONE_MONITOR,
    KRK_CONF_RET_SHOW_ALL_MONITOR,
};

struct krk_config_ret {
    int retval;
    char monitor[KRK_NAME_LEN];
};

extern int krk_config_load(char *config_file);
extern void krk_config_read(int sock, short type, void *arg);
extern void krk_config_write(int sock, short type, void *arg);

#endif
