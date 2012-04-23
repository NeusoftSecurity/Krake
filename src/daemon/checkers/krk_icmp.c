/**
 * krk_icmp.c - Krake icmp checker
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
#include <checkers/krk_checker.h>
#include <checkers/krk_icmp.h>

#include <netinet/ip.h>
//#include <netinet/ip_icmp.h>

#include <krk_log.h>

static int icmp_parse_param(struct krk_monitor *monitor, 
        char *param, unsigned int param_len);
static int icmp_init_node(struct krk_node *node);
static int icmp_cleanup_node(struct krk_node *node);
static int icmp_process_node(struct krk_node *node, void *param);

struct krk_checker icmp_checker = {
    "icmp",
    KRK_CHECKER_ICMP,
    icmp_parse_param,
    icmp_init_node,
    icmp_cleanup_node,
    icmp_process_node,
};

static int icmp_parse_param(struct krk_monitor *monitor, 
        char *param, unsigned int param_len)
{	
    return KRK_OK;
}

static int icmp_match_packet(void* packet, struct krk_node *node)
{
    struct krk_icmphdr *icp;
    unsigned char monitor_id;
    unsigned char node_id;
    struct krk_monitor *monitor;

    icp = packet;
    node_id = icp->un.echo.id & 0xff;
    monitor_id = (icp->un.echo.id >> 8) & 0xff;

    monitor = node->parent;

    krk_log(KRK_LOG_DEBUG, "m_id: %u, n_id: %u, m->id: %u, n->id: %u\n", 
            monitor_id, node_id, monitor->id, node->id);

    return ((monitor->id == monitor_id)
            && (node->id == node_id)) ? 1 : 0;
}

static void icmp_handle_same_addr_node(const struct krk_node *node)
{
    struct krk_node nodes[256];
    struct krk_monitor *monitor;
    int n, i;

    n = krk_monitor_get_nodes_by_addr(node->addr, nodes);
    for (i = 0; i < n; i++) {
        if (nodes[i].id != node->id) {
            monitor = nodes[i].parent;

            if (node == &nodes[i]) {
                continue;
            }

            if (!nodes[i].ready && 
                    !strcmp("icmp", monitor->checker->name)) {
                if (!nodes[i].down) {
                    nodes[i].down = 1;
                    krk_mointor_set_node_status(monitor, nodes[i].id, 1);
                } else {
                    nodes[i].down = 0;
                    krk_mointor_set_node_status(monitor, nodes[i].id, 0);
                }
                krk_monitor_notify(monitor, &nodes[i]);
            }
        }
    }
}

static void icmp_read_handler(int sock, short type, void *arg)
{
    struct krk_event *rev;
    struct krk_connection *conn;
    struct krk_node *node;
    struct krk_monitor *monitor;
    struct krk_icmphdr *icp;
#ifdef __BSD_VISIBLE
    struct ip *ip;
#else
    struct iphdr *ip;
#endif
    struct icmp_checker_data *icd;
    void *packet = NULL;
    int ret, packlen;
    socklen_t addrlen;

    krk_log(KRK_LOG_DEBUG, "read a icmp reply, type is %d\n", type);
    rev = arg;
    node = rev->data;
    conn = rev->conn;
    monitor = node->parent;
    icd = node->checker_data;

    if (type == EV_READ) {
        packlen = KRK_MAX_IP_LEN + KRK_MAX_ICMP_LEN + KRK_ICMP_DATA_LEN;
        packet = malloc(packlen);
        if (packet == NULL) {
            goto out;
        }

        addrlen = sizeof(struct sockaddr);
        ret = recvfrom(sock, packet, packlen, 0, 
                NULL, NULL);
        if (ret < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                krk_event_add(conn->rev);
                free(packet);
                return;
            }
        }

        /* recv ok */
        ip = packet;
#ifdef __BSD_VISIBLE
        if (ip->ip_hl < 5) {
#else
        if (ip->ihl < 5) {
#endif
            goto out;
        }

#ifdef __BSD_VISIBLE
        krk_log(KRK_LOG_DEBUG, "saddr: %x\n", ip->ip_src.s_addr);
        icp = packet + ip->ip_hl * 4;
#else
        krk_log(KRK_LOG_DEBUG, "saddr: %x\n", ip->saddr);
        icp = packet + ip->ihl * 4;
#endif
        /* we do not care about checksum */
        krk_log(KRK_LOG_DEBUG, "ret is %d, icp->id is %x, node->id is %x\n", 
                ret, icp->un.echo.id, node->id);

        if (icp->type == ICMP_ECHOREPLY) {
            if (icmp_match_packet(icp, node)) {
                krk_log(KRK_LOG_DEBUG, "got correct icmp reply\n");
                node->nr_fails = 0;
                if (node->down) {
                    node->down = 0;
                    krk_monitor_notify(monitor, node);
                    //icmp_handle_same_addr_node(node);
                }
            } else {
                krk_log(KRK_LOG_DEBUG, "id not match\n");
                free(packet);
                krk_event_add(conn->rev);

                return;
            }
        } else {
            krk_log(KRK_LOG_DEBUG, "not match a icmp reply\n");
            free(packet);
            krk_event_add(conn->rev);

            return;
        }
    } else if (type == EV_TIMEOUT) {
        krk_log(KRK_LOG_DEBUG, "icmp checker read timeout\n");
        node->nr_fails++;
        krk_log(KRK_LOG_DEBUG, "%s:%d, 0xdead-nr_fails %d\n", 
                __func__, __LINE__, node->nr_fails);
        if (node->nr_fails == monitor->threshold) {
            krk_log(KRK_LOG_DEBUG, "%s:%d, reach max threshold: %d\n", 
                    __func__, __LINE__, monitor->threshold);
            node->nr_fails = 0;
            if (!node->down) {
                krk_log(KRK_LOG_DEBUG, "%s:%d, mark node as down\n", 
                        __func__, __LINE__);
                node->down = 1;
                krk_monitor_notify(monitor, node);
                //icmp_handle_same_addr_node(node);
            }
        }
    }

out:
    if (packet) {
        free(packet);
    }

    krk_monitor_remove_node_connection(node, conn);
    krk_connection_destroy(conn);
}

static void icmp_write_handler(int sock, short type, void *arg)
{
    struct krk_event *wev;
    struct krk_connection *conn;
    struct krk_node *node;
    struct krk_monitor *monitor;
    struct krk_icmphdr *icp;
    struct icmp_checker_data *icd;
    void *packet = NULL;
    int ret;

    wev = arg;
    node = wev->data;
    conn = wev->conn;
    monitor = node->parent;
    icd = node->checker_data;

    if (type == EV_WRITE) {
        /* we've got a writable signal, send out the icmp packet */
        packet = malloc(8 + KRK_ICMP_DATA_LEN);
        if (packet == NULL) {
            goto failed;
        }

        memset(packet, 0, 8 + KRK_ICMP_DATA_LEN);

        icp = (struct krk_icmphdr *)packet;
        icp->type = ICMP_ECHO;
        icp->code = 0;
        icp->checksum = 0;
        icp->un.echo.sequence = htons(icd->sequence);
        icp->un.echo.id = monitor->id << 8;
        icp->un.echo.id |= node->id;

        icp->checksum = krk_in_cksum((unsigned short *)icp, 8 + KRK_ICMP_DATA_LEN, 0);

        /* schedule read handler */
        conn->rev->timeout = malloc(sizeof(struct timeval));
        if (!conn->rev->timeout) {
            goto failed;
        }

        conn->rev->timeout->tv_sec = monitor->timeout;
        conn->rev->timeout->tv_usec = 0;

        ret = sendto(sock, packet, 8 + KRK_ICMP_DATA_LEN, 0, 
                (struct sockaddr*)&node->inaddr, sizeof(struct sockaddr));
        if (ret < 0) {
            krk_log(KRK_LOG_DEBUG, "%s:%d, ret < 0\n", 
                    __func__, __LINE__);

            node->nr_fails++;

            krk_log(KRK_LOG_DEBUG, "%s:%d, 0xdead-nr_fails %d\n", 
                    __func__, __LINE__, node->nr_fails);
            if (node->nr_fails == monitor->threshold) {
                node->nr_fails = 0;
                if (!node->down) {
                    krk_log(KRK_LOG_DEBUG, "%s:%d, mark node as down\n", 
                            __func__, __LINE__);
                    node->down = 1;
                    krk_monitor_notify(monitor, node);
                    //icmp_handle_same_addr_node(node);
                }
            }

            goto failed;
        }

        icd->sequence++;

        krk_event_set_read(conn->sock, conn->rev);
        krk_event_add(conn->rev);
    } else if (type == EV_TIMEOUT) {
        krk_log(KRK_LOG_DEBUG, "write timeout!\n");

        node->nr_fails++;

        krk_log(KRK_LOG_DEBUG, "%s:%d, 0xdead-nr_fails %d\n", 
                __func__, __LINE__, node->nr_fails);
        if (node->nr_fails == monitor->threshold) {
            node->nr_fails = 0;
            if (!node->down) {
                krk_log(KRK_LOG_DEBUG, "%s:%d, mark node as down\n", 
                        __func__, __LINE__);
                node->down = 1;
                krk_monitor_notify(monitor, node);
            }
        }

        goto failed;
    }

out:
    if (packet)
        free(packet);

    return;

failed:
    krk_monitor_remove_node_connection(node, conn);
    krk_connection_destroy(conn);

    goto out;
}

static int icmp_init_node(struct krk_node *node)
{
    struct icmp_checker_data *icd;
    struct krk_node nodes[256];
    struct krk_monitor *monitor;
    unsigned short n, i;

    /**
     * for icmp checker, if we have 
     * more than one node with the 
     * same address, consider them as 
     * one.
     *
     * XXX: Temporarily disable this feature.
     */
#if 0
    n = krk_monitor_get_nodes_by_addr(node->addr, nodes);
    for (i = 0; i < n; i++) {
        monitor = nodes[i].parent;
        if (node == &nodes[i]) {
            continue;
        }

        if (nodes[i].ready && 
                !strcmp("icmp", monitor->checker->name)) {
            return KRK_OK;
        }
    }
#endif
    node->ready = 1;

    icd = malloc(sizeof(struct icmp_checker_data));
    if (icd == NULL) 
        return KRK_ERROR;

    memset(icd, 0, sizeof(struct icmp_checker_data));
    node->checker_data = icd;

    return KRK_OK;
}

static int icmp_cleanup_node(struct krk_node *node)
{
    struct icmp_checker_data *icd;

    node->ready = 0;
    icd = node->checker_data;

    free(icd);

    return KRK_OK;
}

static int icmp_process_node(struct krk_node *node, void *param)
{
    int sock;
    struct krk_connection *conn;
    struct krk_monitor *monitor;

    if (node->conn)
        return KRK_OK;

    sock = krk_socket_raw_create(IPPROTO_ICMP);
    if (sock < 0) {
        return KRK_ERROR;
    }

    conn = krk_connection_create(node->addr, 0, 0);
    if (!conn) {
        return KRK_ERROR;
    }

    conn->sock = sock;
    conn->rev->handler = icmp_read_handler;
    conn->wev->handler = icmp_write_handler;

    conn->rev->data = node;
    conn->wev->data = node;

    monitor = node->parent;

    conn->wev->timeout = malloc(sizeof(struct timeval));
    if (!conn->wev->timeout) {
        krk_connection_destroy(conn);
        return KRK_ERROR;
    }

    conn->wev->timeout->tv_sec = monitor->timeout;
    conn->wev->timeout->tv_usec = 0;

    krk_event_set_write(conn->sock, conn->wev);
    krk_event_add(conn->wev);

    krk_monitor_add_node_connection(node, conn);

    return KRK_OK;
}

