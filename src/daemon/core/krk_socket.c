/**
 * krk_socket.c - functions related to socket
 * 
 * Copyright (c) 2010 Yang Yang <paulyang.inf@gmail.com>
 *
 * This file contains the functions related to unix socket 
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <krk_core.h>
#include <krk_socket.h>
#include <krk_event.h>
#include <krk_connection.h>
#include <krk_config.h>
#include <krk_monitor.h>
#include <krk_log.h>

int krk_socket_tcp_create(int protocol)
{
    int sock;

    sock = socket(AF_INET, SOCK_STREAM, protocol);

    if (sock > 0) {
        fcntl(sock, F_SETFL, O_NONBLOCK);
    }

    return sock;
}

int krk_socket_close(int sock)
{
    return close(sock);
}

int krk_socket_raw_create(int protocol)
{
    int sock;

    sock = socket(AF_INET, SOCK_RAW, protocol);

    if (sock > 0) {
        fcntl(sock, F_SETFL, O_NONBLOCK);
    }

    return sock;
}

int krk_socket_tcp_connect(int sock, struct krk_node *node)
{
    int ret;

    if (0) {
    } else {
        ret = connect(sock, (struct sockaddr*)&node->inaddr, 
                sizeof(struct sockaddr));
    }

    return ret;
}

int krk_socket_read(struct krk_node *node) 
{
    return KRK_OK;
}

int krk_socket_write(struct krk_node *node)
{
    return KRK_OK;
}
