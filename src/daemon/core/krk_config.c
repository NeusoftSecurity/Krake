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

static int krk_config_parse_node (struct krk_config_monitor *monitor, xmlDocPtr doc, xmlNodePtr cur) 
{
	xmlChar *key = NULL;
    struct krk_config_node *node = NULL;

    node = calloc(1, sizeof(*node));
    if (node == NULL) {
        return -1;
    }

    node->next = monitor->node;
    monitor->node = node;

	cur = cur->xmlChildrenNode;
	while (cur != NULL) {
		if ((!xmlStrcmp(cur->name, (const xmlChar *)"host"))) {
			key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
			printf("host: %s\n", key);
            if (xmlStrlen(key) == 0 || xmlStrlen(key) > KRK_IPADDR_LEN) {
                xmlFree(key);
                return -1;
            }
            strcpy(node->addr, key);
            xmlFree(key);
		}
		if ((!xmlStrcmp(cur->name, (const xmlChar *)"port"))) {
			key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
			printf("port: %s\n", key);
            node->port = atoi(key);
			xmlFree(key);
            if ((short)node->port < 0 ){
                return -1;
            }
		}
        cur = cur->next;
    }

    return 0;
}

static int krk_config_parse_log (struct krk_config_monitor *monitor, xmlDocPtr doc, xmlNodePtr cur) 
{
	xmlChar *key = NULL;

	cur = cur->xmlChildrenNode;
	while (cur != NULL) {
		if ((!xmlStrcmp(cur->name, (const xmlChar *)"logtype"))) {
			key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
			printf("logtype: %s\n", key);
            if (xmlStrlen(key) == 0 || xmlStrlen(key) > KRK_ARG_LEN) {
                xmlFree(key);
                return -1;
            }
            strcpy(monitor->log_type, key);
			xmlFree(key);
		} else if ((!xmlStrcmp(cur->name, (const xmlChar *)"loglevel"))) {
            key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
			printf("loglevel: %s\n", key);
            if (xmlStrlen(key) == 0 || xmlStrlen(key) > KRK_ARG_LEN) {
                xmlFree(key);
                return -1;
            }
            strcpy(monitor->log_level, key);
			xmlFree(key);
		}
        cur = cur->next;
    }

    return 0;
}

static int krk_config_monitor_name(struct krk_config_monitor *monitor, xmlDocPtr doc, xmlNodePtr cur)
{
	xmlChar *key;

    key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
    if (xmlStrlen(key) == 0 || xmlStrlen(key) > KRK_NAME_LEN) {
        xmlFree(key);
        return -1;
    }
    strcpy(monitor->monitor, key);
    printf("monitor name: %s\n", key);
    xmlFree(key);

    return 0;
}

static int krk_config_monitor_status(struct krk_config_monitor *monitor, xmlDocPtr doc, xmlNodePtr cur)
{
    xmlChar *key;

    key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
    printf("status: %s\n", key);
    if (!xmlStrcmp(key,(const xmlChar *)"enable")) {
        monitor->enable = 1;
    } else if (!xmlStrcmp(key,(const xmlChar *)"disable")) {
        monitor->enable = 0;
    } else {
        xmlFree(key);
        return -1;
    }
    xmlFree(key);

    return 0;
}

static int krk_config_monitor_checker(struct krk_config_monitor *monitor, xmlDocPtr doc, xmlNodePtr cur)
{
    xmlChar *key;

    key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
    printf("checker: %s\n", key);
    if (xmlStrlen(key) == 0 || xmlStrlen(key) > KRK_NAME_LEN) {
        xmlFree(key);
        return -1;
    }
    strcpy(monitor->checker, key);

    xmlFree(key);

    return 0;
}

static int krk_config_monitor_checker_param(struct krk_config_monitor *monitor, xmlDocPtr doc, xmlNodePtr cur)
{
    xmlChar *key;
    int param_len = 0;

    key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
    printf("check-param: %s\n", key);
    param_len = xmlStrlen(key) + 1;
    monitor->checker_param = calloc(1, param_len);
    if (monitor->checker_param == NULL) {
        xmlFree(key);
        return -1;
    }
    strcpy(monitor->checker_param, key);
    monitor->checker_param_len = param_len;

    xmlFree(key);

    return 0;
}

static int krk_config_monitor_interval(struct krk_config_monitor *monitor, xmlDocPtr doc, xmlNodePtr cur)
{
    xmlChar *key;

    key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
    printf("interval: %s\n", key);
    monitor->interval = atol(key);
    xmlFree(key);
    if ((long)monitor->interval < 0) {
        return -1;
    }

    return 0;
}

static int krk_config_monitor_timeout(struct krk_config_monitor *monitor, xmlDocPtr doc, xmlNodePtr cur)
{
    xmlChar *key;

    key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
    printf("timeout: %s\n", key);
    monitor->timeout = atol(key);
    xmlFree(key);
    if ((long)monitor->timeout < 0) {
        return -1;
    }

    return 0;
}

static int krk_config_monitor_threshold(struct krk_config_monitor *monitor, xmlDocPtr doc, xmlNodePtr cur)
{
    xmlChar *key;

    key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
    printf("threshold: %s\n", key);
    monitor->threshold = atol(key);
    xmlFree(key);
    if ((long)monitor->threshold < 0) {
        return -1;
    }

    return 0;
}

static int krk_config_monitor_script(struct krk_config_monitor *monitor, xmlDocPtr doc, xmlNodePtr cur)
{
    xmlChar *key;

    key = xmlNodeListGetString(doc, cur->xmlChildrenNode, 1);
    printf("script: %s\n", key);
    if (xmlStrlen(key) == 0 || xmlStrlen(key) > KRK_NAME_LEN) {
        xmlFree(key);
        return -1;
    }
    strcpy(monitor->script, key);
    xmlFree(key);

    return 0;
}

static int krk_config_monitor_node(struct krk_config_monitor *monitor, xmlDocPtr doc, xmlNodePtr cur)
{
    return krk_config_parse_node(monitor, doc, cur);
}

static int krk_config_monitor_log(struct krk_config_monitor *monitor, xmlDocPtr doc, xmlNodePtr cur)
{
    return krk_config_parse_log(monitor, doc, cur);
}

struct krk_config_monitor_parser {
    xmlChar *key;
    int (*paser)(struct krk_config_monitor *monitor, xmlDocPtr doc, xmlNodePtr cur);
};

static struct krk_config_monitor_parser krk_monitor_paser[] = {
    {"name", krk_config_monitor_name},
    {"status", krk_config_monitor_status},
    {"checker", krk_config_monitor_checker},
    {"checker-param", krk_config_monitor_checker},
    {"interval", krk_config_monitor_interval},
    {"timeout", krk_config_monitor_timeout},
    {"threshold", krk_config_monitor_threshold},
    {"script", krk_config_monitor_script},
    {"node", krk_config_monitor_node},
    {"log", krk_config_monitor_log},
};

#define krk_config_monitor_parser_name \
    (sizeof(krk_monitor_paser)/sizeof(struct krk_config_monitor_parser))

static int krk_config_parse_monitor(struct krk_config *conf, 
                xmlDocPtr doc, xmlNodePtr cur) 
{
    struct krk_config_monitor_parser *paser = NULL;
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
        for (p = 0; p < krk_config_monitor_parser_name; p++) {
            paser = &krk_monitor_paser[p];
            if ((!xmlStrcmp(cur->name, paser->key))) {
                ret = paser->paser(monitor, doc, cur);
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
