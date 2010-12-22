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
#include <krk_connection.h>

struct krk_connection* krk_connection_create(const char *name);
int krk_connection_destroy(struct krk_connection *conn);
int krk_connection_init(void);


/*TODO: add a list head to recorde all connections 
 * 
 * a list head is something like: 
 *         krk_list_head krk_all_connections;
 *
 * and i need a couple of functions to operate the list.
 */

/**
 * krk_connection_create - create a new connection
 * 
 * @name: name of the new connection
 *
 * 
 * return address of new connection for success;
 * NULL for failed.
 */
struct krk_connection* krk_connection_create(const char *name)
{
	struct krk_connection *conn;

	conn = malloc(sizeof(struct krk_connection));
	if (!conn) {
		return NULL;
	}

	memset(conn, 0, sizeof(struct krk_connection));
	
	/* create read/write event */
	conn->rev = krk_event_create();
	if (!conn->rev) {
		free(conn);
		return NULL;
	} else {
		conn->rev->conn = conn;
	}

	conn->wev = krk_event_create();
	if (!conn->wev) {
		(void)krk_event_destroy(conn->rev);
		free(conn);
		return NULL;
	} else {
		conn->wev->conn = conn;
	}

	memcpy(conn->name, name, sizeof(conn->name) - 1);

	return conn;
}

/**
 * krk_connection_destroy - destroy a connection
 * 
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

	return 0;
}

int krk_connection_init(void)
{
	return 0;
}
