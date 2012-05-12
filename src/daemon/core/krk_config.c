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

static char krk_config_value[KRK_CONFIG_MAX_LEN] = {};

struct krk_config_param {
    xmlChar *key;
    int cmd_label;
    int param_max_len;
};

struct krk_config_monitor_parser {
    struct krk_config_param param;
    int (*parser)(struct krk_config_param *param,
                struct krk_config_monitor *monitor, 
                xmlDocPtr doc, xmlNodePtr cur);
};

static int krk_config_parse_first(struct krk_config_param *param, 
                    char *conf_value, unsigned int *conf_cmd,
                    xmlDocPtr doc, xmlNodePtr cur)
{
    xmlChar *key;
    int key_len = 0;

    key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
    printf("%s: %s\n",param->key, key);
    key_len = xmlStrlen(key); 
    if (key_len > param->param_max_len) {
        printf("the %s configuration length %d is bigger than %d\n",param->key,key_len,param->param_max_len);
        xmlFree(key);
        return -1;
    }

    if (key_len == 0) {
        xmlFree(key);
        return 0;
    }

    if (param->cmd_label) {
        if (*conf_cmd & param->cmd_label) {
            printf("%s configuration repeated!\n", param->key);
            xmlFree(key);
            return -1;
        }
        *conf_cmd |= param->cmd_label;
    }

    memset(krk_config_value, 0, param->param_max_len);
    strcpy(krk_config_value, key);
    xmlFree(key);

    return 0;
}

static int krk_config_node_host(struct krk_config_param *param,
                    struct krk_config_node *node, 
                    xmlDocPtr doc, xmlNodePtr cur)
{
    return krk_config_parse_first(param, node->addr, 
                        &node->config, doc, cur);
}

static int krk_config_node_port(struct krk_config_param *param,
                    struct krk_config_node *node, 
                    xmlDocPtr doc, xmlNodePtr cur)
{
    int ret = 0;

    ret = krk_config_parse_first(param, krk_config_value, 
                        &node->config, doc, cur);
    if (ret < 0) {
        return -1;
    }

    node->port = atoi(krk_config_value);
    if ((short)node->port < 0 ){
        return -1;
    }

    return 0;
}

struct krk_config_node_parser {
    struct krk_config_param param;
    int (*parser)(struct krk_config_param *param,
                struct krk_config_node *node, 
                xmlDocPtr doc, xmlNodePtr cur);
};

static struct krk_config_node_parser krk_node_parser[] = {
    {{"host", KRK_CONF_MONITOR_NODE_HOST, KRK_IPADDR_LEN}, krk_config_node_host},
    {{"port", KRK_CONF_MONITOR_NODE_PORT, 5}, krk_config_node_port},
};

#define krk_config_node_parser_num \
    (sizeof(krk_node_parser)/sizeof(struct krk_config_node_parser))

static int krk_config_parse_node(struct krk_config_param *param,
                    struct krk_config_monitor *monitor, 
                    xmlDocPtr doc, xmlNodePtr cur) 
{
    struct krk_config_node *node = NULL;
    struct krk_config_node_parser *parser = NULL;
    int p = 0;
    int ret = 0;

    node = calloc(1, sizeof(*node));
    if (node == NULL) {
        return -1;
    }

    node->next = monitor->node;
    monitor->node = node;

	cur = cur->xmlChildrenNode;
	while (cur != NULL) {
        for (p = 0; p < krk_config_node_parser_num; p++) {
            parser = &krk_node_parser[p];
		    if ((!xmlStrcmp(cur->name, parser->param.key))) {
                ret = parser->parser(&parser->param, node, doc, cur);
                if (ret < 0) {
                    return -1;
                }
            }
        }
        cur = cur->next;
    }

    return 0;
}

static int krk_config_log_type(struct krk_config_param *param,
                    struct krk_config_monitor *monitor, 
                    xmlDocPtr doc, xmlNodePtr cur)
{
    return krk_config_parse_first(param, monitor->log_type, 
                        &monitor->config, doc, cur);
}

static int krk_config_log_level(struct krk_config_param *param,
                    struct krk_config_monitor *monitor, 
                    xmlDocPtr doc, xmlNodePtr cur)
{
    return krk_config_parse_first(param, monitor->log_level, 
                        &monitor->config, doc, cur);
}

static struct krk_config_monitor_parser krk_log_parser[] = {
    {{"logtype", KRK_CONF_MONITOR_LOGTYPE, KRK_ARG_LEN}, krk_config_log_type},
    {{"loglevel", KRK_CONF_MONITOR_LOGLEVEL, KRK_ARG_LEN}, krk_config_log_level},
};

#define krk_config_log_parser_num \
    (sizeof(krk_log_parser)/sizeof(struct krk_config_monitor_parser))

static int krk_config_parse_log (struct krk_config_param *param,
                    struct krk_config_monitor *monitor, 
                    xmlDocPtr doc, xmlNodePtr cur) 
{
    struct krk_config_monitor_parser *parser = NULL;
    int p = 0;
    int ret = 0;

	cur = cur->xmlChildrenNode;
    while (cur != NULL) {
        for (p = 0; p < krk_config_log_parser_num; p++) {
            parser = &krk_log_parser[p];
            if ((!xmlStrcmp(cur->name, parser->param.key))) {
                ret = parser->parser(&parser->param, monitor, doc, cur);
                if (ret < 0) {
                    return -1;
                }
            }
        }
        cur = cur->next;
    }

    return 0;
}

static int krk_config_monitor_name(struct krk_config_param *param,
                    struct krk_config_monitor *monitor, 
                    xmlDocPtr doc, xmlNodePtr cur)
{
    return krk_config_parse_first(param, monitor->monitor, 
                        &monitor->config, doc, cur);
}

static int krk_config_monitor_status(struct krk_config_param *param,
                    struct krk_config_monitor *monitor, 
                    xmlDocPtr doc, xmlNodePtr cur)
{
    int ret = 0;

    ret = krk_config_parse_first(param, krk_config_value, 
                        &monitor->config, doc, cur);
    if (ret < 0) {
        return -1;
    }

    if (!strcmp(krk_config_value, "enable")) {
        monitor->enable = 1;
        return 0;
    }

    if (!strcmp(krk_config_value, "disable")) {
        monitor->enable = 0;
        return 0;
    }

    return -1;
}

static int krk_config_monitor_checker(struct krk_config_param *param,
                    struct krk_config_monitor *monitor, 
                    xmlDocPtr doc, xmlNodePtr cur)
{
    return krk_config_parse_first(param, monitor->checker, 
                        &monitor->config, doc, cur);
}

static int krk_config_monitor_checker_param(struct krk_config_param *param,
                    struct krk_config_monitor *monitor, 
                    xmlDocPtr doc, xmlNodePtr cur)
{
    int param_len = 0;
    int ret = 0;

    ret = krk_config_parse_first(param, krk_config_value, 
                        &monitor->config, doc, cur);
    if (ret < 0) {
        return -1;
    }

    param_len = strlen(krk_config_value) + 1;
    monitor->checker_param = calloc(1, param_len);
    if (monitor->checker_param == NULL) {
        return -1;
    }
    strcpy(monitor->checker_param, krk_config_value);
    monitor->checker_param_len = param_len;

    return 0;
}

static int krk_config_monitor_interval(struct krk_config_param *param,
                struct krk_config_monitor *monitor, 
                xmlDocPtr doc, xmlNodePtr cur)
{
    int ret = 0;

    ret = krk_config_parse_first(param, krk_config_value, 
                        &monitor->config, doc, cur);
    if (ret < 0) {
        return -1;
    }

    monitor->interval = atol(krk_config_value);
    if ((long)monitor->interval < 0) {
        return -1;
    }

    return 0;
}

static int krk_config_monitor_timeout(struct krk_config_param *param,
                struct krk_config_monitor *monitor, 
                xmlDocPtr doc, xmlNodePtr cur)
{
    int ret = 0;

    ret = krk_config_parse_first(param, krk_config_value, 
                        &monitor->config, doc, cur);
    if (ret < 0) {
        return -1;
    }

    monitor->timeout = atol(krk_config_value);
    if ((long)monitor->timeout < 0) {
        return -1;
    }

    return 0;
}

static int krk_config_monitor_threshold(struct krk_config_param *param,
                struct krk_config_monitor *monitor, 
                xmlDocPtr doc, xmlNodePtr cur)
{
    int ret = 0;

    ret = krk_config_parse_first(param, krk_config_value, 
                        &monitor->config, doc, cur);
    if (ret < 0) {
        return -1;
    }

    monitor->threshold = atol(krk_config_value);
    if ((long)monitor->threshold < 0) {
        return -1;
    }

    return 0;
}

static int krk_config_monitor_script(struct krk_config_param *param,
                struct krk_config_monitor *monitor, 
                xmlDocPtr doc, xmlNodePtr cur)
{
    return krk_config_parse_first(param, monitor->script, 
                        &monitor->config, doc, cur);
}

static int krk_config_monitor_node(struct krk_config_param *param,
            struct krk_config_monitor *monitor, 
            xmlDocPtr doc, xmlNodePtr cur)
{
    return krk_config_parse_node(param, monitor, doc, cur);
}

static int krk_config_monitor_log(struct krk_config_param *param,
                struct krk_config_monitor *monitor, 
                xmlDocPtr doc, xmlNodePtr cur)
{
    return krk_config_parse_log(param, monitor, doc, cur);
}

static struct krk_config_monitor_parser krk_monitor_parser[] = {
    {{"name", KRK_CONF_MONITOR_NAME, KRK_NAME_LEN}, krk_config_monitor_name},
    {{"status", KRK_CONF_MONITOR_STATUS, 8}, krk_config_monitor_status},
    {{"checker", KRK_CONF_MONITOR_CHECKER, KRK_NAME_LEN}, krk_config_monitor_checker},
    {{"checker-param", KRK_CONF_MONITOR_CHECKER_PARAM, KRK_CONFIG_MAX_LEN}, krk_config_monitor_checker},
    {{"interval", KRK_CONF_MONITOR_INTERVAL, KRK_CONFIG_MAX_LEN}, krk_config_monitor_interval},
    {{"timeout", KRK_CONF_MONITOR_TIMEOUT, KRK_CONFIG_MAX_LEN}, krk_config_monitor_timeout},
    {{"threshold", KRK_CONF_MONITOR_THRESHOLD, KRK_CONFIG_MAX_LEN}, krk_config_monitor_threshold},
    {{"script", KRK_CONF_MONITOR_SCRIPT, KRK_CONFIG_MAX_LEN}, krk_config_monitor_script},
    {{"node", 0, 0}, krk_config_monitor_node},
    {{"log",0,0}, krk_config_monitor_log},
};

#define krk_config_monitor_parser_num \
    (sizeof(krk_monitor_parser)/sizeof(struct krk_config_monitor_parser))

static int krk_config_parse_monitor(struct krk_config *conf, 
                xmlDocPtr doc, xmlNodePtr cur) 
{
    struct krk_config_monitor_parser *parser = NULL;
    struct krk_config_monitor *monitor = NULL; 
    int p = 0;
    int ret = 0;

    monitor = calloc(1, sizeof(*monitor));
    if (monitor == NULL) {
        return -1;
    }

    monitor->next = conf->monitor;
    conf->monitor = monitor;

	cur = cur->xmlChildrenNode;
	while (cur != NULL) {
        for (p = 0; p < krk_config_monitor_parser_num; p++) {
            parser = &krk_monitor_parser[p];
            if ((!xmlStrcmp(cur->name, parser->param.key))) {
                ret = parser->parser(&parser->param, monitor, doc, cur);
                if (ret < 0) {
                    return -1;
                }
            }
        }
        cur = cur->next;
    }
    return 0;
}

static void krk_config_monitor_free (struct krk_config_monitor *monitor)
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

static void krk_config_free (struct krk_config *conf)
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

static int krk_config_parse (char *config_file, struct krk_config *conf)
{
	xmlDocPtr config;
	xmlNodePtr cur;
    int ret = 0;

    memset(conf, 0, sizeof(*conf));

	config = xmlReadFile(config_file, NULL, 0);

	if (config == NULL ) {
		fprintf(stderr,"Document not parsed successfully. \n");
		return -1;
	}

	cur = xmlDocGetRootElement(config);

	if (cur == NULL) {
		fprintf(stderr,"empty document\n");
		xmlFreeDoc(config);
		return -1;
	}

    if (xmlStrcmp(cur->name, (const xmlChar *) "krk_config")) {
        fprintf(stderr,"document of the wrong type, root node != krk_config");
        xmlFreeDoc(config);
        return 1;
    }

	cur = cur->xmlChildrenNode;
	while (cur != NULL) {
		if ((!xmlStrcmp(cur->name, (const xmlChar *)"monitor"))){
			ret = krk_config_parse_monitor (conf, config, cur);
            if (ret < 0) {
                return -1;
            }
		}

		cur = cur->next;
	}

	xmlFreeDoc(config);
	return 0;
}

static int krk_config_process(struct krk_config *conf) 
{
    return 0;
}

int krk_config_load (char *config_file)
{
    struct krk_config conf;
    int ret = 0;

    ret = krk_config_parse (config_file, &conf);
    if (ret < 0) {
        ret = -1;
        goto out;
    }

    ret = krk_config_process(&conf);
out:
    krk_config_free(&conf);

    return ret;
}

#if 0
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

static int krk_config_parse2(struct krk_config *conf)
{
    int ret = KRK_OK;
    struct krk_monitor *monitor = NULL;
    struct krk_node *node = NULL;
    struct krk_checker *checker = NULL;

    if (conf->command != KRK_CONF_CMD_CREATE
            && conf->command != KRK_CONF_CMD_LOG) {
        monitor = krk_monitor_find(conf->monitor);
        if (monitor == NULL) {
            ret = KRK_ERROR;
            goto out;
        }
    }

    switch (conf->command) {
        case KRK_CONF_CMD_CREATE:
            monitor = krk_monitor_create(conf->monitor);
            if (monitor == NULL) {
                ret = KRK_ERROR;
                goto out;
            }

            monitor->interval = conf->interval;
            monitor->timeout = conf->timeout;
            monitor->threshold = conf->threshold;

            if (conf->script[0]) {
                strncpy(monitor->notify_script, conf->script, KRK_NAME_LEN);
                monitor->notify_script[KRK_NAME_LEN - 1] = 0;
                ret = krk_config_parse_pathname(monitor);
                if (ret != KRK_OK) {
                    goto out;
                }
            }

            checker = krk_checker_find(conf->checker);
            if (checker == NULL) {
                ret = KRK_ERROR;
                goto out;
            }

            monitor->checker = checker;

            if (checker->parse_param) {
                ret = checker->parse_param(monitor, conf->checker_param, 
                        conf->checker_param_len);
            }

            break;
        case KRK_CONF_CMD_DESTROY:
            ret = krk_monitor_destroy(monitor);
            break;
        case KRK_CONF_CMD_ADD:
//            node = krk_monitor_create_node(conf->node, conf->port);
            if (node == NULL) {
                ret = KRK_ERROR;
                goto out;
            }

            ret = krk_monitor_add_node(monitor, node);
            break;
        case KRK_CONF_CMD_REMOVE:
 //           node = krk_monitor_find_node(conf->node, conf->port, monitor);
            if (node == NULL) {
                ret = KRK_ERROR;
                goto out;
            }

            ret = krk_monitor_remove_node(monitor, node);
            break;
        case KRK_CONF_CMD_ENABLE:
            krk_monitor_enable(monitor);
            break;
        case KRK_CONF_CMD_DISABLE:
            krk_monitor_disable(monitor);
            break;
        case KRK_CONF_CMD_LOG:
            krk_log_set_type(conf->log_type, conf->log_level);
            break;
        default:
            ret = KRK_ERROR;
    }

out:
    if (monitor && !node && ret != KRK_OK) {
        krk_monitor_destroy(monitor);
    }

    if (node && ret != KRK_OK) {
        krk_monitor_destroy_node(node);
    }

    return ret;
}

#endif
