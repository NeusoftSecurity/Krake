/**
 * krk_connection.c - core connection
 * 
 * Copyright (c) 2010 Yang Yang <paulyang.inf@gmail.com>
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <krk_core.h>
#include <krk_event.h>
#include <krk_connection.h>

struct krk_connection* krk_connection_create(const char *name, size_t rbufsz, size_t wbufsz);
int krk_connection_destroy(struct krk_connection *conn);
int krk_connection_init(void);
int krk_all_connections_destroy(void);
int krk_connection_exit(void);


LIST_HEAD(krk_all_connections);
unsigned int krk_max_connections = 0;
unsigned int krk_nr_connections = 0;


/**
 * krk_connection_create - create a new connection
 * @name: name of the new connection
 * @rbufsz: size of read buffer, 0 for default
 * @wbufsz: size of write buffer, 0 for default
 *
 * 
 * return address of new connection for success;
 * NULL for failed.
 */
struct krk_connection* 
krk_connection_create(const char *name, size_t rbufsz, size_t wbufsz)
{
    struct krk_connection *conn;

    if (krk_nr_connections == krk_max_connections) {
        return NULL;
    }

    conn = malloc(sizeof(struct krk_connection));
    if (!conn) {
        return NULL;
    }

    memset(conn, 0, sizeof(struct krk_connection));

    /* create read/write event */
    conn->rev = krk_event_create(rbufsz);
    if (!conn->rev) {
        free(conn);
        return NULL;
    } else {
        conn->rev->conn = conn;
    }

    conn->wev = krk_event_create(wbufsz);
    if (!conn->wev) {
        (void)krk_event_destroy(conn->rev);
        free(conn);
        return NULL;
    } else {
        conn->wev->conn = conn;
    }

    if (name) {
        strncpy(conn->name, name, KRK_NAME_LEN);
        conn->name[KRK_NAME_LEN - 1] = 0;
    }

    list_add_tail(&conn->list, &krk_all_connections);

    krk_nr_connections++;
    
    conn->recv = krk_connection_recv;
    conn->send = krk_connection_send;

    return conn;
}

/**
 * krk_connection_destroy - destroy a connection
 * @conn: connection to destroy
 *
 * 
 * return 0 for success;
 * -1 for failed.
 */
int krk_connection_destroy(struct krk_connection *conn)
{
    if (!conn) {
        return KRK_ERROR;
    }

    krk_event_destroy(conn->rev);
    krk_event_destroy(conn->wev);

    close(conn->sock);

    list_del(&conn->list);

    free(conn);

    krk_nr_connections--;

    return KRK_OK;
}

/**
 * krk_all_connections_destroy - destroy all connections
 * @
 * 
 * return 0 for success;
 * -1 for failed.
 */
int krk_all_connections_destroy(void)
{
    struct list_head *p, *n;
    struct krk_connection *tmp;
    int ret = KRK_OK;

    list_for_each_safe(p, n, &krk_all_connections) {
        tmp = list_entry(p, struct krk_connection, list);
        if (krk_connection_destroy(tmp)) {
            ret = KRK_ERROR;
        }
    }

    return ret;
}

int krk_connection_init(void)
{
    INIT_LIST_HEAD(&krk_all_connections);

    krk_max_connections = 1024;

    return KRK_OK;
}

int krk_connection_exit(void)
{
    return krk_all_connections_destroy();
}

/**
 * krk_connection_ssl_init - init ssl for a connection
 * @
 * 
 * return KRK_OK for success;
 * KRK_ERROR for failed.
 */
int 
krk_connection_ssl_init(struct krk_connection *conn, struct krk_ssl *ssl)
{
    conn->ssl = krk_ssl_create_connection(conn->sock, ssl);
    if (conn->ssl == NULL) {
        return KRK_ERROR;
    }

    return KRK_OK;
}

/**
 * krk_connection_ssl_init - init ssl for a connection
 * @
 * 
 * return KRK_OK for success;
 * KRK_ERROR for failed.
 * KRK_AGAIN_* for hold on
 */
int 
krk_connection_ssl_handshake(struct krk_connection *conn)
{
    int ret;
    
    ret = krk_ssl_handshake(conn->ssl);

    return ret;
}

ssize_t 
krk_connection_recv(struct krk_connection *conn, u_char *buf, size_t size)
{
    return recv(conn->sock, buf, size, 0);
}

ssize_t 
krk_connection_send(struct krk_connection *conn, u_char *buf, size_t size)
{
    return send(conn->sock, buf, size, 0);
}

ssize_t 
krk_connection_ssl_recv(struct krk_connection *conn, u_char *buf, size_t size)
{
    return krk_ssl_recv(conn->ssl->ssl_connection, buf, size);
}

ssize_t 
krk_connection_ssl_send(struct krk_connection *conn, u_char *buf, size_t size)
{
    return krk_ssl_send(conn->ssl->ssl_connection, buf, size);
}
 
