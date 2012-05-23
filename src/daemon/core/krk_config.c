/**
 * krk_config.c - functions related to configuration
 * 
 * Copyright (c) 2010 Yang Yang <paulyang.inf@gmail.com>
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <stdlib.h>
#include <ctype.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

#include <krk_core.h>
#include <krk_socket.h>
#include <krk_event.h>
#include <krk_connection.h>
#include <krk_config.h>
#include <krk_buffer.h>
#include <krk_monitor.h>
#include <krk_log.h>
#include <checkers/krk_checker.h>

struct krk_config_param {
    xmlChar *key;
    int cmd_label;
};

struct krk_config_parser {
    struct krk_config_param param;
    int (*parser)(struct krk_config_param *param, void *arg,
                xmlDocPtr doc, xmlNodePtr cur);
};

static int krk_config_parse_first(struct krk_config_param *param, 
                    char *conf_value, int conf_string_len, 
                    unsigned int *conf_cmd,
                    xmlDocPtr doc, xmlNodePtr cur)
{
    xmlChar *key;
    int key_len = 0;

    key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
//    printf("%s: %s\n",param->key, key);
    key_len = xmlStrlen(key); 
    if (key_len > conf_string_len) {
        printf("the %s configuration length %d is bigger than %d\n",param->key,key_len,conf_string_len);
        xmlFree(key);
        return KRK_ERROR;
    }

    if (key_len == 0) {
        printf("the length of the key is 0!\n");
        xmlFree(key);
        return KRK_OK;
    }

    if (param->cmd_label) {
        if (*conf_cmd & param->cmd_label) {
            printf("%s configuration repeated!\n", param->key);
            xmlFree(key);
            return KRK_ERROR;
        }
        *conf_cmd |= param->cmd_label;
    }

    strncpy(conf_value, key, conf_string_len);
    xmlFree(key);

    return KRK_OK;
}

static int krk_config_parse_xml_node(struct krk_config_parser *conf_parser, 
                    int parser_num, void *arg, xmlDocPtr doc, xmlNodePtr cur) 
{
    struct krk_config_parser *c_parser = NULL;
    int p = 0;
    int ret = 0;
    
	cur = cur->xmlChildrenNode;
	while (cur != NULL) {
        c_parser = conf_parser;
        for (p = 0; p < parser_num; p++) {
		    if ((!xmlStrcmp(cur->name, c_parser->param.key))) {
                ret = c_parser->parser(&c_parser->param, arg, doc, cur);
                if (ret < 0) {
                    printf("paese %s failed!\n",c_parser->param.key);
                    return KRK_ERROR;
                }
            }
            c_parser++;
        }
        cur = cur->next;
    }


    return KRK_OK;
}

static int krk_config_node_host(struct krk_config_param *param, void *arg,
                    xmlDocPtr doc, xmlNodePtr cur)
{
    struct krk_config_node *node = arg; 

    return krk_config_parse_first(param, node->addr, 
                        sizeof(node->addr),
                        &node->config, doc, cur);
}

static int krk_config_node_port(struct krk_config_param *param, void *arg,
                    xmlDocPtr doc, xmlNodePtr cur)
{
    struct krk_config_node *node = arg; 
    char config_value[5] = {};//5 is sizeof 65535
    int i = 0;
    int ret = 0;

    ret = krk_config_parse_first(param, config_value, 
                        sizeof(config_value),
                        &node->config, doc, cur);
    if (ret < 0) {
        return KRK_ERROR;
    }

    for (i = 0; i < strlen(config_value); i++) {
        if (!isdigit(config_value[i])) {
            printf("port configuration is not number!\n");
            return KRK_ERROR;
        }
    }

    node->port = atoi(config_value);
    if ((short)node->port <= 0 ){
        printf("port configuration error!\n");
        return KRK_ERROR;
    }

    return KRK_OK;
}

static struct krk_config_parser krk_node_parser[] = {
    {{"host", KRK_CONF_MONITOR_NODE_HOST}, krk_config_node_host},
    {{"port", KRK_CONF_MONITOR_NODE_PORT}, krk_config_node_port},
};

#define krk_config_node_parser_num \
    (sizeof(krk_node_parser)/sizeof(struct krk_config_parser))

static int krk_config_node_parse(struct krk_config_param *param, void *arg,
                    xmlDocPtr doc, xmlNodePtr cur) 
{
    struct krk_config_monitor *monitor = arg;
    struct krk_config_node *node = NULL;

    node = calloc(1, sizeof(*node));
    if (node == NULL) {
        return KRK_ERROR;
    }

    node->next = monitor->node;
    monitor->node = node;

    return krk_config_parse_xml_node(krk_node_parser, 
                    krk_config_node_parser_num, node, doc, cur);
}

static int krk_config_log_type(struct krk_config_param *param, void *arg,
                    xmlDocPtr doc, xmlNodePtr cur)
{
    struct krk_config_log *log = arg;

    return krk_config_parse_first(param, log->log_type, 
                        sizeof(log->log_type),
                        &log->config, doc, cur);
}

static int krk_config_log_level(struct krk_config_param *param, void *arg,
                    xmlDocPtr doc, xmlNodePtr cur)
{
    struct krk_config_log *log = arg;

    return krk_config_parse_first(param, log->log_level, 
                        sizeof(log->log_level),
                        &log->config, doc, cur);
}

static struct krk_config_parser krk_log_parser[] = {
    {{"logtype", KRK_CONF_MONITOR_LOGTYPE}, krk_config_log_type},
    {{"loglevel", KRK_CONF_MONITOR_LOGLEVEL}, krk_config_log_level},
};

#define krk_config_log_parser_num \
    (sizeof(krk_log_parser)/sizeof(struct krk_config_parser))

static int krk_config_log_parse(struct krk_config_param *param, void *arg,
                    xmlDocPtr doc, xmlNodePtr cur) 
{
    struct krk_config *conf = arg;

    if (param->cmd_label) {
        if (conf->config & param->cmd_label) {
            printf("%s configuration repeated!\n", param->key);
            return KRK_ERROR;
        }
        conf->config |= param->cmd_label;
    }

    return krk_config_parse_xml_node(krk_log_parser, 
                    krk_config_log_parser_num, &conf->log, doc, cur);
}

static int krk_config_monitor_name(struct krk_config_param *param, void *arg,
                    xmlDocPtr doc, xmlNodePtr cur)
{
    struct krk_config_monitor *monitor = arg;

    return krk_config_parse_first(param, monitor->monitor, 
                        sizeof(monitor->monitor), 
                        &monitor->config, doc, cur);
}

static int krk_config_monitor_status(struct krk_config_param *param, void *arg,
                    xmlDocPtr doc, xmlNodePtr cur)
{
    struct krk_config_monitor *monitor = arg;
    char m_enable[] = {"enable"};
    char m_disable[] = {"disable"};
    char config_value[7] = {}; //7 is sizeof "disable"
    int ret = 0;

    ret = krk_config_parse_first(param, config_value, 
                        sizeof(config_value), 
                        &monitor->config, doc, cur);
    if (ret < 0) {
        return KRK_ERROR;
    }

    if (!strncmp(config_value, m_enable, strlen(m_enable))) {
        monitor->enable = 1;
        return KRK_OK;
    }

    if (!strncmp(config_value, m_disable, strlen(m_disable))) {
        monitor->enable = 0;
        return KRK_OK;
    }

    printf("Unable to parse status configuration!\n");
    return KRK_ERROR;
}

static int krk_config_monitor_checker(struct krk_config_param *param, void *arg,
                    xmlDocPtr doc, xmlNodePtr cur)
{
    struct krk_config_monitor *monitor = arg;

    return krk_config_parse_first(param, monitor->checker, 
                        sizeof(monitor->checker), 
                        &monitor->config, doc, cur);
}

static int krk_config_monitor_checker_param(struct krk_config_param *param, void *arg,
                    xmlDocPtr doc, xmlNodePtr cur)
{
    struct krk_config_monitor *monitor = arg;
    char config_value[KRK_CONFIG_MAX_LEN] = {};
    int param_len = 0;
    int ret = 0;

    ret = krk_config_parse_first(param, config_value, 
                        sizeof(config_value),
                        &monitor->config, doc, cur);
    if (ret < 0) {
        return KRK_ERROR;
    }

    param_len = strlen(config_value);
    monitor->checker_param = calloc(1, param_len);
    if (monitor->checker_param == NULL) {
        return KRK_ERROR;
    }
    strncpy(monitor->checker_param, config_value, param_len);
    monitor->checker_param_len = param_len;

    return KRK_OK;
}

static int krk_config_monitor_interval(struct krk_config_param *param, void *arg,
                xmlDocPtr doc, xmlNodePtr cur)
{
    struct krk_config_monitor *monitor = arg;
    char config_value[KRK_CONFIG_MAX_LEN] = {};
    int i = 0;
    int ret = 0;

    ret = krk_config_parse_first(param, config_value, 
                        sizeof(config_value), 
                        &monitor->config, doc, cur);
    if (ret < 0) {
        return KRK_ERROR;
    }

    for (i = 0; i < strlen(config_value); i++) {
        if (!isdigit(config_value[i])) {
            printf("interval configuration is not number!\n");
            return KRK_ERROR;
        }
    }

    monitor->interval = atol(config_value);
    if ((long)monitor->interval < 0) {
        return KRK_ERROR;
    }

    return KRK_OK;
}

static int krk_config_monitor_timeout(struct krk_config_param *param, void *arg,
                xmlDocPtr doc, xmlNodePtr cur)
{
    struct krk_config_monitor *monitor = arg;
    char config_value[KRK_CONFIG_MAX_LEN] = {};
    int i = 0;
    int ret = 0;

    ret = krk_config_parse_first(param, config_value, 
                        sizeof(config_value),  
                        &monitor->config, doc, cur);
    if (ret < 0) {
        printf("parse configuration first failed!\n");
        return KRK_ERROR;
    }

    for (i = 0; i < strlen(config_value); i++) {
        if (!isdigit(config_value[i])) {
            printf("timeout configuration is not number!\n");
            return KRK_ERROR;
        }
    }

    monitor->timeout = atol(config_value);
    if (((long)monitor->timeout < 0)
            || (monitor->interval <= monitor->timeout)) {
        return KRK_ERROR;
    }

    return KRK_OK;
}

static int krk_config_monitor_failure_threshold(struct krk_config_param *param, void *arg,
                xmlDocPtr doc, xmlNodePtr cur)
{
    struct krk_config_monitor *monitor = arg;
    char config_value[KRK_CONFIG_MAX_LEN] = {};
    int i = 0;
    int ret = 0;

    ret = krk_config_parse_first(param, config_value, 
                        sizeof(config_value),  
                        &monitor->config, doc, cur);
    if (ret < 0) {
        return KRK_ERROR;
    }

    for (i = 0; i < strlen(config_value); i++) {
        if (!isdigit(config_value[i])) {
            printf("failure threshold configuration is not number!\n");
            return KRK_ERROR;
        }
    }

    monitor->failure_threshold = atol(config_value);
    if ((long)monitor->failure_threshold < 0) {
        return KRK_ERROR;
    }

    return KRK_OK;
}

static int krk_config_monitor_success_threshold(struct krk_config_param *param, void *arg,
                xmlDocPtr doc, xmlNodePtr cur)
{
    struct krk_config_monitor *monitor = arg;
    char config_value[KRK_CONFIG_MAX_LEN] = {};
    int i = 0;
    int ret = 0;

    ret = krk_config_parse_first(param, config_value, 
                        sizeof(config_value),  
                        &monitor->config, doc, cur);
    if (ret < 0) {
        return KRK_ERROR;
    }

    for (i = 0; i < strlen(config_value); i++) {
        if (!isdigit(config_value[i])) {
            printf("success threshold configuration is not number!\n");
            return KRK_ERROR;
        }
    }

    monitor->success_threshold = atol(config_value);
    if ((long)monitor->success_threshold < 0) {
        return KRK_ERROR;
    }

    return KRK_OK;
}

static int krk_config_monitor_script(struct krk_config_param *param, void *arg,
                xmlDocPtr doc, xmlNodePtr cur)
{
    struct krk_config_monitor *monitor = arg;

    return krk_config_parse_first(param, monitor->script, 
                        sizeof(monitor->script),
                        &monitor->config, doc, cur);
}

static int krk_config_monitor_node(struct krk_config_param *param, void *arg,
            xmlDocPtr doc, xmlNodePtr cur)
{
    struct krk_config_monitor *monitor = arg;

    return krk_config_node_parse(param, monitor, doc, cur);
}

static struct krk_config_parser krk_monitor_parser[] = {
    {{"name", KRK_CONF_MONITOR_NAME}, krk_config_monitor_name},
    {{"status", KRK_CONF_MONITOR_STATUS}, krk_config_monitor_status},
    {{"checker", KRK_CONF_MONITOR_CHECKER}, krk_config_monitor_checker},
    {{"checker-param", KRK_CONF_MONITOR_CHECKER_PARAM}, krk_config_monitor_checker_param},
    {{"interval", KRK_CONF_MONITOR_INTERVAL}, krk_config_monitor_interval},
    {{"timeout", KRK_CONF_MONITOR_TIMEOUT}, krk_config_monitor_timeout},
    {{"failure_threshold", KRK_CONF_MONITOR_F_THRESHOLD}, krk_config_monitor_failure_threshold},
    {{"success_threshold", KRK_CONF_MONITOR_S_THRESHOLD}, krk_config_monitor_success_threshold},
    {{"script", KRK_CONF_MONITOR_SCRIPT}, krk_config_monitor_script},
    {{"node", 0}, krk_config_monitor_node},
};

#define krk_config_monitor_parser_num \
    (sizeof(krk_monitor_parser)/sizeof(struct krk_config_parser))

static int krk_config_monitor_parse(struct krk_config_param *param, void *arg,
                xmlDocPtr doc, xmlNodePtr cur) 
{
    struct krk_config *conf = arg;
    struct krk_config_monitor *monitor = NULL; 
    int p = 0;
    int ret = 0;

    monitor = calloc(1, sizeof(*monitor));
    if (monitor == NULL) {
        return KRK_ERROR;
    }

    monitor->next = conf->monitor;
    conf->monitor = monitor;

    return krk_config_parse_xml_node(krk_monitor_parser, 
                    krk_config_monitor_parser_num, monitor, doc, cur);
}

static void krk_config_monitor_free(struct krk_config_monitor *monitor)
{
    struct krk_config_node *node = NULL;
    struct krk_config_node *tmp = NULL;

    if (monitor->checker_param) {
        free(monitor->checker_param);
    }

    node = monitor->node; 
    while (node != NULL) {
        tmp = node;
        node = node->next;
        free(tmp);
    }

    free(monitor);
}

static void krk_config_free(struct krk_config *conf)
{    
    struct krk_config_monitor *monitor = NULL;
    struct krk_config_monitor *tmp = NULL;

    monitor = conf->monitor; 
    while (monitor != NULL) {
        tmp = monitor;
        monitor = monitor->next;
        krk_config_monitor_free(tmp);
    }
}

static struct krk_config_parser krk_parser[] = {
    {{"monitor", 0}, krk_config_monitor_parse},
    {{"log", KRK_CONF_MONITOR_SCRIPT}, krk_config_log_parse},
};

#define krk_config_parser_num \
    (sizeof(krk_parser)/sizeof(struct krk_config_parser))


static int krk_config_parse(char *config_file, struct krk_config *conf)
{
	xmlDocPtr xml_file;
	xmlNodePtr cur;
    int ret = 0;

    memset(conf, 0, sizeof(*conf));

	xml_file = xmlReadFile(config_file, NULL, 0);
	if (xml_file == NULL ) {
		fprintf(stderr,"%s not parsed successfully. \n",config_file);
		return KRK_ERROR;
	}

	cur = xmlDocGetRootElement(xml_file);
	if (cur == NULL) {
		fprintf(stderr,"empty document\n");
		xmlFreeDoc(xml_file);
		return KRK_ERROR;
	}

    if (xmlStrcmp(cur->name, (const xmlChar *) "krk_config")) {
        fprintf(stderr,"document of the wrong type, root node != krk_config");
        xmlFreeDoc(xml_file);
		return KRK_ERROR;
    }

    ret = krk_config_parse_xml_node(krk_parser, krk_config_parser_num, 
                        conf, xml_file, cur);

	xmlFreeDoc(xml_file);
	return ret;
}

static int krk_config_parse_pathname(struct krk_monitor *monitor)
{
    char *ptr;
    int len, i;

    len = strlen(monitor->notify_script);
    ptr = monitor->notify_script;

    for (i = len; i >= 0; i--) {
        if (ptr[i] == '/') {
            break;
        }
    }

    strncpy(monitor->notify_script_name, &ptr[i + 1], KRK_NAME_LEN);
    monitor->notify_script_name[KRK_NAME_LEN - 1] = 0;

    return KRK_OK;
}

static int krk_config_process_log(struct krk_config_log *log) 
{
    return krk_log_set_type(log->log_type, log->log_level);
}

static int krk_config_update_node(struct krk_config_node *conf_node, 
                    struct krk_node *node) 
{
    return KRK_OK;
}

static int krk_config_update_monitor(struct krk_config_monitor *conf_monitor, 
                    struct krk_monitor *monitor) 
{
    struct krk_checker *checker = NULL;
    struct krk_config_node *conf_node = NULL;
    struct krk_node *node = NULL;
    int ret = KRK_OK;

    monitor->interval = conf_monitor->interval;
    monitor->timeout = conf_monitor->timeout;
    monitor->failure_threshold = conf_monitor->failure_threshold;
    monitor->success_threshold = conf_monitor->success_threshold;

    if (!strcmp(conf_monitor->checker, "https")) {
        monitor->ssl_flag = 1;
        if (krk_monitor_init_ssl(monitor) != KRK_OK) {
            ret = KRK_ERROR;
            goto out;
        }
        strncpy(conf_monitor->checker, "http",KRK_NAME_LEN);
    }

    if (conf_monitor->script[0]) {
        strncpy(monitor->notify_script, conf_monitor->script, KRK_NAME_LEN);
        monitor->notify_script[KRK_NAME_LEN - 1] = 0;
        ret = krk_config_parse_pathname(monitor);
        if (ret != KRK_OK) {
            goto out;
        }
    }

    checker = krk_checker_find(conf_monitor->checker);
    if (checker == NULL) {
        ret = KRK_ERROR;
        goto out;
    }

    monitor->checker = checker;

    if (checker->parse_param) {
        if (monitor->parsed_checker_param) {
            free(monitor->parsed_checker_param);
        }

        ret = checker->parse_param(monitor, conf_monitor->checker_param, 
                conf_monitor->checker_param_len);
        if (ret != KRK_OK) {
            goto out;
        }
    }

    ret = krk_remove_unused_node(conf_monitor, monitor);
    if (ret == KRK_ERROR) {
        return ret;
    }

    conf_node = conf_monitor->node;
    while (conf_node != NULL) {
        node = krk_monitor_find_node(conf_node->addr, conf_node->port, monitor);
        if (node == NULL) {
            node = krk_monitor_create_node(conf_node->addr, conf_node->port);
            if (node == NULL) {
                ret = KRK_ERROR;
                goto out;
            }

            ret = krk_monitor_add_node(monitor, node);
            if (ret == KRK_ERROR) {
                goto out;
            }
        } else {
            ret = krk_config_update_node(conf_node, node);
            if (ret == KRK_ERROR) {
                goto out;
            }
        }

        conf_node = conf_node->next;
    }

    if (conf_monitor->enable) {
        krk_monitor_enable(monitor);
    } else {
        krk_monitor_disable(monitor);
    }

out:
    return ret;
}

static int krk_config_new_monitor(struct krk_config_monitor *conf_monitor) 
{
    struct krk_monitor *monitor = NULL;

    monitor = krk_monitor_create(conf_monitor->monitor);
    if (monitor == NULL) {
        printf("create monitor failed!\n");
        return KRK_ERROR;
    }

    return krk_config_update_monitor(conf_monitor, monitor);
}

static int krk_config_process(struct krk_config *conf) 
{
    struct krk_config_monitor *conf_monitor = NULL; 
    struct krk_monitor *monitor = NULL; 
    int ret = KRK_OK;

    ret = krk_config_process_log(&conf->log);
    if (ret == KRK_ERROR) {
        printf("process log failed!\n");
        return ret;
    }

    ret = krk_remove_unused_monitor(conf);
    if (ret == KRK_ERROR) {
        printf("remove unused monitor failed!\n");
        return ret;
    }

    conf_monitor = conf->monitor;
    while (conf_monitor != NULL) {
        monitor = krk_monitor_find(conf_monitor->monitor);
        if (monitor == NULL) {
            ret = krk_config_new_monitor(conf_monitor);
            if (ret == KRK_ERROR) {
                printf("config new monitor failed!\n");
                goto out;
            }
        } else {
            ret = krk_config_update_monitor(conf_monitor, monitor);
            if (ret == KRK_ERROR) {
                printf("update monitor failed!\n");
                goto out;
            }
        }
        conf_monitor = conf_monitor->next;
    }
out:
    return ret;
}

int krk_config_load(char *config_file)
{
    struct krk_config conf;
    int ret = KRK_OK;

    ret = krk_config_parse(config_file, &conf);
    if (ret == KRK_ERROR) {
        printf("config pase failed!\n");
        goto out;
    }

    ret = krk_config_process(&conf);
    if (ret == KRK_ERROR) {
        printf("process config failed!\n");
        krk_all_monitors_destroy();
    }
out:
    krk_config_free(&conf);

    return ret;
}

#define KRK_RCV_BUF_LEN 10

void krk_config_read(int sock, short type, void *arg)
{
	int n, ret;
	struct krk_event *rev;
	struct krk_connection *conn;
    char rcv_buf[KRK_RCV_BUF_LEN] = {};
	
	rev = arg;
	conn = rev->conn;
	
	n = recv(sock, rcv_buf, sizeof(rcv_buf), 0);
	if (n == 0) {
		/* fprintf(stderr, "read config finished\n"); */
		krk_connection_destroy(conn);
		return;
	}

	if (n < 0) {
		/* fprintf(stderr, "read config error\n"); */
		krk_connection_destroy(conn);
		return;
	}

    if (!strcmp(rcv_buf, "reload")) {
        if (krk_config_load(krk_config_file)) {
            printf("reload configuration failed!");
        }
    } else if (!strcmp(rcv_buf, "show")) {
        krk_monitor_show();
    } else {
        return;
    }

	krk_event_set_read(sock, rev);
	krk_event_add(rev);
}

void krk_config_write(int sock, short type, void *arg)
{
}
