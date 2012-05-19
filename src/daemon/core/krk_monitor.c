/**
 * krk_monitor.c - Krake monitor
 * 
 * Copyright (c) 2011 Yang Yang <paulyang.inf@gmail.com>
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <krk_core.h>
#include <krk_monitor.h>
#include <checkers/krk_checker.h>
#include <krk_log.h>

struct krk_monitor* krk_monitor_find(const char *name);
struct krk_monitor* krk_monitor_create(const char *name);
int krk_monitor_destroy(struct krk_monitor *monitor);
int krk_monitor_init(void);
int krk_all_monitors_destroy(void);
int krk_monitor_exit(void);
int krk_monitor_add_node(struct krk_monitor *monitor, 
        struct krk_node *node);
int krk_monitor_remove_node(struct krk_monitor *monitor, 
        struct krk_node *node);
void krk_monitor_enable(struct krk_monitor *monitor);
void krk_monitor_disable(struct krk_monitor *monitor);
struct krk_node* krk_monitor_create_node(const char *addr, unsigned short port);
int krk_monitor_destroy_node(struct krk_node *node);
int krk_monitors_destroy_all_nodes(struct krk_monitor *monitor);
struct krk_node* krk_monitor_find_node(const char *addr, 
        const unsigned short port, struct krk_monitor *monitor);
int krk_monitor_get_all_nodes(struct krk_monitor *monitor, 
        struct krk_node *node); 
void krk_monitor_notify(struct krk_monitor *monitor, 
        struct krk_node *node);
int krk_monitor_add_node_connection(struct krk_node *node, struct krk_connection *conn);
int krk_monitor_remove_node_connection(struct krk_node *node, struct krk_connection *conn);

LIST_HEAD(krk_all_monitors);
unsigned int krk_max_monitors = 0;
unsigned int krk_nr_monitors = 0;
unsigned short krk_nr_nodes = 0;

void krk_monitor_notify(struct krk_monitor *monitor, 
        struct krk_node *node)
{
    pid_t notifier;

    if (!monitor->notify_script[0]) {
        krk_log(KRK_LOG_NOTICE, "no script found, do nothing\n");
        return;
    }

    notifier = fork();
    if (notifier < 0) {
        krk_log(KRK_LOG_ALERT, "fork failed\n");
        return;
    }

    if (notifier == 0) {
        char port[8];

        memset(port, 0, 8);
        sprintf(port, "%d", node->port);

        if (execlp(monitor->notify_script, monitor->notify_script_name, 
                    monitor->name, node->addr, port, node->down ? "down" : "up", NULL) < 0) {
            exit(1);
        }
    } else if (notifier > 0) {
        /* do nothing */
    }
}

/**
 * krk_monitor_find - find a monitor by name
 * @name: name of monitor to find.
 *
 *
 */
struct krk_monitor* krk_monitor_find(const char *name)
{
    struct krk_monitor *tmp;
    struct list_head *p, *n;

    list_for_each_safe(p, n, &krk_all_monitors) {
        tmp = list_entry(p, struct krk_monitor, list);
        if (!strcmp(name, tmp->name)) {
            return tmp;
        }
    }

    return NULL;
}

int krk_monitor_get_all_monitors(struct krk_monitor *monitors) 
{
    struct krk_monitor *tmp;
    struct list_head *p, *n;
    int i = 0;

    if (monitors == NULL) {
        return KRK_ERROR;
    }

    list_for_each_safe(p, n, &krk_all_monitors) {
        tmp = list_entry(p, struct krk_monitor, list);
        memcpy(&monitors[i], tmp, sizeof(struct krk_monitor));
        i++;
    }

    return i;
}

void krk_monitor_timeout_handler(int sock, short type, void *arg)
{
    struct krk_event *ev;
    struct krk_monitor *monitor;
    struct list_head *p, *n;
    struct krk_node *tmp;
    int ret;

    ev = arg;
    monitor = ev->data;

    pthread_mutex_lock(&monitor->mutex);
    list_for_each_safe(p, n, &monitor->node_list) {
        tmp = list_entry(p, struct krk_node, list);

        if (tmp->ready) {
            ret = monitor->checker->process_node(tmp, monitor->checker_param);
            if (ret == KRK_ERROR) {
                /* TODO: just log, do nothing */
            } else if (ret == KRK_OK) {
                /* TODO: just log, do nothing */
            } else if (ret == KRK_AGAIN) {
                /* TODO: just log, do nothing */
            } 

            krk_log(KRK_LOG_INFO, "node %s:%d, nr_fails: %u\n", 
                    tmp->addr, tmp->port, tmp->nr_fails); 
        }
    }

    krk_event_add(monitor->tmout_ev);
    pthread_mutex_unlock(&monitor->mutex);
}

/**
 * krk_monitor_create - create a monitor
 * @name: name of monitor to create.
 *
 *
 * return address of new monitor  on success;
 * NULL means failed.
 */
struct krk_monitor* krk_monitor_create(const char *name)
{	
    struct krk_monitor *monitor = NULL;
    int ret = 0;

    if (!name) {
        printf("name = NULL!\n");
        return NULL;
    }

    monitor = krk_monitor_find(name);
    if (monitor != NULL) {
        printf("%s is existing!\n",name);
        return NULL;
    }

    if (krk_nr_monitors == krk_max_monitors) {
        printf("monitor number (%d) is full(%d)!\n",krk_nr_monitors, krk_max_monitors);
        return NULL;
    }

    monitor = malloc(sizeof(struct krk_monitor));
    if (!monitor) {
        printf("alloc monitor failed!\n");
        return NULL;
    }

    memset(monitor, 0, sizeof(struct krk_monitor));
    INIT_LIST_HEAD(&monitor->node_list);

    ret = pthread_mutex_init(&monitor->mutex, NULL);
    if (ret != 0) {
        free(monitor);
        printf("init mutex failed!\n");
        return NULL;
    }

    monitor->tmout_ev = krk_event_create(0);
    if (monitor->tmout_ev == NULL) {
        free(monitor);
        printf("create event failed!\n");
        return NULL;
    }

    monitor->tmout_ev->data = (void *)monitor; 
    monitor->tmout_ev->handler = krk_monitor_timeout_handler;
    krk_event_set_timer(monitor->tmout_ev);

    strncpy(monitor->name, name, KRK_NAME_LEN);
    monitor->name[KRK_NAME_LEN - 1] = 0;

    list_add_tail(&monitor->list, &krk_all_monitors);

    monitor->id = krk_nr_monitors;

    krk_nr_monitors++;

    return monitor;
}

int krk_monitor_destroy(struct krk_monitor *monitor)
{
    if (!monitor) {
        return KRK_ERROR;
    }

    krk_event_destroy(monitor->tmout_ev);

    if (krk_monitor_destroy_all_nodes(monitor)
            != KRK_OK) {
        return KRK_ERROR;
    }

    list_del(&monitor->list);

    if (monitor->parsed_checker_param) {
        free(monitor->parsed_checker_param);
    }

    pthread_mutex_destroy(&monitor->mutex);

    free(monitor);

    krk_nr_monitors--;

    return KRK_OK;
}

int krk_remove_unused_monitor(struct krk_config *conf)
{
    struct krk_config_monitor *conf_monitor = NULL;
    struct krk_monitor *monitor = NULL;
    struct list_head *p, *n;
    int found = 0;
    int ret = 0;

    list_for_each_safe(p, n, &krk_all_monitors) {
        found = 0;
        monitor = list_entry(p, struct krk_monitor, list);
        conf_monitor = conf->monitor;
        while (conf_monitor != NULL) {
            if (!strcmp(monitor->name, conf_monitor->monitor)) {
                found = 1;
                break;
            }
            conf_monitor = conf_monitor->next;
        }
        if (!found) {
            ret = krk_monitor_destroy(monitor);
            if (ret == KRK_ERROR) {
                return ret;
            }
        }
    }

    return KRK_OK;
}

int krk_all_monitors_destroy(void)
{
    struct list_head *p, *n;
    struct krk_monitor *tmp;
    int ret = KRK_OK;

    list_for_each_safe(p, n, &krk_all_monitors) {
        tmp = list_entry(p, struct krk_monitor, list);
        if (krk_monitor_destroy(tmp)) {
            ret = KRK_ERROR;
        }
    }

    return ret;
}

struct krk_node* krk_monitor_find_node(const char *addr, 
        const unsigned short port, struct krk_monitor *monitor)
{
    struct krk_node *tmp;
    struct list_head *p, *n;

    if (addr == NULL || monitor == NULL || port == 0) {
        return NULL;
    }

    list_for_each_safe(p, n, &monitor->node_list) {
        tmp = list_entry(p, struct krk_node, list);
        if (!strcmp(addr, tmp->addr)
                && port == tmp->port) {
            return tmp;
        }
    }

    return NULL;
}

struct krk_node* krk_monitor_find_node_by_id(const unsigned char id, 
        struct krk_monitor *monitor)
{
    struct krk_node *tmp;
    struct list_head *p, *n;

    if (monitor == NULL) {
        return NULL;
    }

    list_for_each_safe(p, n, &monitor->node_list) {
        tmp = list_entry(p, struct krk_node, list);
        if (id == tmp->id) {
            return tmp;
        }
    }

    return NULL;
}

int krk_monitor_add_node_connection(struct krk_node *node, struct krk_connection *conn)
{
    /**
     * currently we do not allow
     * the timeout value is less than the 
     * interval value, so there must be one
     * connect per main-timeout.
     */

    if (conn == NULL
            || node == NULL) {
        return KRK_ERROR;
    }

#if 1
    node->conn = conn;
#else
    list_add_tail(&conn->node, &node->connection_list);
    node->nr_connections++;
#endif

    return KRK_OK;
}

int krk_monitor_remove_node_connection(struct krk_node *node, struct krk_connection *conn)
{
    if (conn == NULL
            || node == NULL) {
        return KRK_ERROR;
    }

#if 1
    node->conn = NULL;
#else
    list_del(&conn->node);
    node->nr_connections--;
#endif

    return KRK_OK;
}

void krk_monitor_destroy_node_connections(struct krk_node *node)
{
#if 1
    if (node == NULL) {
        return;
    }

    if (node->conn) {
        krk_connection_destroy(node->conn);
    }
#else
    struct krk_connection *tmp;
    struct list_head *p, *n;

    if (node == NULL) {
        return;
    }

    list_for_each_safe(p, n, &node->connection_list) {
        tmp = list_entry(p, struct krk_connection, list);
        krk_monitor_remove_node_connection(node, tmp);
        krk_connection_destroy(tmp);
    }
#endif

    return;
}

struct krk_node* krk_monitor_create_node(const char *addr, unsigned short port)
{
    struct krk_node *node = NULL;
    int ret = KRK_OK;

    if (!addr || port == 0) {
        return NULL;
    }

    node = malloc(sizeof(struct krk_node));
    if (node == NULL) {
        return NULL;
    }

    memset(node, 0, sizeof(struct krk_node));

    if (addr[0] == '[') {
        node->ipv6 = 1;
    }

    if (node->ipv6) {
    } else {
        ret = inet_aton(addr, &node->inaddr.sin_addr);
        if (ret == 0) {
            free(node);
            return NULL;
        }

        node->inaddr.sin_port = htons(port);
        node->inaddr.sin_family = AF_INET;
    }

    strncpy(node->addr, addr, KRK_IPADDR_LEN);
    node->addr[KRK_IPADDR_LEN - 1] = 0;

    node->port = port;

    INIT_LIST_HEAD(&node->connection_list);

    /* id begins at 0 */
    node->id = krk_nr_nodes;

    krk_nr_nodes++;

    return node;
}

int krk_monitor_destroy_node(struct krk_node *node)
{
    if (node == NULL) {
        return KRK_ERROR;
    }

    krk_monitor_destroy_node_connections(node);

    free(node);

    krk_nr_nodes--;

    return KRK_OK;
}

int krk_monitor_destroy_all_nodes(struct krk_monitor *monitor)
{
    struct list_head *p, *n;
    struct krk_node *tmp;
    int ret = KRK_OK;

    list_for_each_safe(p, n, &monitor->node_list) {
        tmp = list_entry(p, struct krk_node, list);
        if (krk_monitor_destroy_node(tmp)) {
            ret = KRK_ERROR;
        }
    }

    return ret;
}

int krk_monitor_add_node(struct krk_monitor *monitor, 
        struct krk_node *node)
{
    if (monitor == NULL
            || node == NULL) {
        return KRK_ERROR;
    }

    node->parent = monitor;

    list_add_tail(&node->list, &monitor->node_list);
    monitor->nr_nodes++;

    if (monitor->checker->init_node(node)
            != KRK_OK) {
        return KRK_ERROR;
    }

    return KRK_OK;
}

int krk_monitor_remove_node(struct krk_monitor *monitor,
        struct krk_node *node)
{
    if (monitor == NULL
            || node == NULL) {
        return KRK_ERROR;
    }

    list_del(&node->list);
    node->parent = NULL;
    monitor->nr_nodes--;

    if (monitor->checker->cleanup_node(node)
            != KRK_OK) {
        return KRK_ERROR;
    }

    return KRK_OK;
}

int krk_remove_unused_node(struct krk_config_monitor *conf_monitor, struct krk_monitor *monitor)
{
    struct list_head *p, *n;
    struct krk_node *tmp;
    struct krk_config_node *node;
    int found = 0;
    int ret = KRK_OK;

    list_for_each_safe(p, n, &monitor->node_list) {
        tmp = list_entry(p, struct krk_node, list);
        node = conf_monitor->node;
        found = 0;
        while (node != NULL) {
            if (!strcmp(node->addr, tmp->addr) && 
                        node->port == tmp->port) {
                found = 1;
                break;
            }
            node = node->next;
        }
        if (!found) {
            ret = krk_monitor_remove_node(monitor, tmp);
            if (ret == KRK_ERROR) {
                krk_monitor_destroy_node(tmp);
                return ret;
            }
            ret = krk_monitor_destroy_node(tmp);
            if (ret == KRK_ERROR) {
                return ret;
            }
        }
    }

    return KRK_OK;
}

int krk_mointor_set_node_status(struct krk_monitor *monitor, 
        unsigned char id, int status)
{
    struct krk_node *node;

    node = krk_monitor_find_node_by_id(id, monitor);
    if (node == NULL) {
        return KRK_ERROR;
    }

    node->down = status;

    return KRK_OK;
}

int krk_monitor_init_ssl(struct krk_monitor *monitor)
{
    krk_log(KRK_LOG_DEBUG, "monitor(%p) has ssl, init\n", monitor);
    
    monitor->ssl = krk_ssl_new_ctx();
    if (!monitor->ssl) {
        return KRK_ERROR;
    }

    return krk_ssl_init_ctx(monitor->ssl);
}

int krk_monitor_get_all_nodes(struct krk_monitor *monitor, 
        struct krk_node *nodes) 
{
    struct krk_node *tmp;
    struct list_head *p, *n;
    int i = 0;

    if (nodes == NULL || monitor == NULL) {
        return KRK_ERROR;
    }

    list_for_each_safe(p, n, &monitor->node_list) {
        tmp = list_entry(p, struct krk_node, list);
        memcpy(&nodes[i], tmp, sizeof(struct krk_node));
        i++;
    }

    return i;
}

int krk_monitor_get_nodes_by_addr(const char *addr, 
        struct krk_node *nodes)
{
    struct list_head *p, *n;
    struct list_head *k, *m;
    struct krk_monitor *tmp;
    struct krk_node *tmp_node;
    int i = 0;

    list_for_each_safe(p, n, &krk_all_monitors) {
        tmp = list_entry(p, struct krk_monitor, list);

        list_for_each_safe(k, m, &tmp->node_list) {
            tmp_node = list_entry(k, struct krk_node, list);
            if (!strcmp(addr, tmp_node->addr)) {
                memcpy(&nodes[i], tmp_node, sizeof(struct krk_node));
                i++;
                if (i > 255)
                    return i;
            }
        }
    }

    return i;
}

static void krk_monitor_show_checker(struct krk_checker *checker)
{
    printf("checker name = %s\n",checker->name);
}

static void krk_monitor_show_node(struct krk_node *node)
{
    printf("------------node------------\n");
    printf("node addr = %s\n", node->addr);
    printf("node port = %u\n", node->port);
    printf("node nr_fails = %u\n", node->nr_fails);
    printf("node id = %d\n", node->id);
    printf("node ipv6 = %d\n", node->ipv6);
    printf("node down = %d\n", node->down);
    printf("node ready = %d\n", node->ready);
    printf("------------node end------------\n");
}

static void krk_monitor_show_one(struct krk_monitor *monitor)
{
    struct list_head *k, *m;
    struct krk_node *node;

    pthread_mutex_lock(&monitor->mutex);
    printf("============monitor============\n");
    printf("monitor name = %s\n",monitor->name);
    printf("id = %d\n",monitor->id);
    printf("interval = %lu\n",monitor->interval);
    printf("timeout = %lu\n",monitor->timeout);
    printf("threshold = %lu\n",monitor->threshold);

    krk_monitor_show_checker(monitor->checker);

    printf("notify_script= %s\n",monitor->notify_script);
    printf("notify_script_name= %s\n",monitor->notify_script_name);

    printf("eanble= %d\n",monitor->enabled);

    list_for_each_safe(k, m, &monitor->node_list) {
        node = list_entry(k, struct krk_node, list);
        krk_monitor_show_node(node);
    }
    printf("============monitor end============\n");
    pthread_mutex_unlock(&monitor->mutex);
}

void krk_monitor_show(void)
{
    struct list_head *p, *n;
    struct krk_monitor *monitor;

    list_for_each_safe(p, n, &krk_all_monitors) {
        monitor = list_entry(p, struct krk_monitor, list);
        krk_monitor_show_one(monitor);
    }
}

void krk_monitor_enable(struct krk_monitor *monitor)
{
    if (monitor->enabled == 0) {
        monitor->enabled = 1;

        monitor->tmout_ev->timeout = malloc(sizeof(struct timeval));
        monitor->tmout_ev->timeout->tv_sec = monitor->interval;
        monitor->tmout_ev->timeout->tv_usec = 0;

        krk_event_add(monitor->tmout_ev);
    }
}

void krk_monitor_disable(struct krk_monitor *monitor)
{
    if (monitor->enabled == 1) {
        monitor->enabled = 0;

        free(monitor->tmout_ev->timeout);
        monitor->tmout_ev->timeout = NULL;

        krk_event_del(monitor->tmout_ev);
    }
}

int krk_monitor_init(void)
{
    INIT_LIST_HEAD(&krk_all_monitors);

    krk_max_monitors = 64;

    return KRK_OK;
}

int krk_monitor_exit(void)
{
    return krk_all_monitors_destroy();
}

void krk_monitor_node_failure_inc(struct krk_monitor *monitor, 
        struct krk_node *node)
{
    node->nr_fails++;
    if (node->nr_fails == monitor->threshold) {
        node->nr_fails = 0;
        if (!node->down) {
            node->down = 1;
            krk_monitor_notify(monitor, node);
        }
    }
}

void krk_monitor_node_success_inc(struct krk_monitor *monitor, 
        struct krk_node *node)
{
}
