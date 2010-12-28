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
struct krk_connection* krk_connection_create(const char *name, size_t rbufsz, size_t wbufsz)
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

	if (name)
		memcpy(conn->name, name, sizeof(conn->name) - 1);

	list_add_tail(&conn->list, &krk_all_connections);
	
	krk_nr_connections++;

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
		return -1;
	}

	krk_event_destroy(conn->rev);
	krk_event_destroy(conn->wev);

	close(conn->sock);

	free(conn);

	list_del(&conn->list);

	krk_nr_connections--;

	return 0;
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
	int ret = 0;

	list_for_each_safe(p, n, &krk_all_connections) {
		tmp = list_entry(p, struct krk_connection, list);
		if (krk_connection_destroy(tmp)) {
			ret = -1;
		}
	}

	return ret;
}

int krk_connection_init(void)
{
	INIT_LIST_HEAD(&krk_all_connections);

	krk_max_connections = 1024;

	return 0;
}

int krk_connection_exit(void)
{
	return krk_all_connections_destroy();
}
