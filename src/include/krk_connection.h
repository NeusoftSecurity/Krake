/**
 * krk_connection.h - core connection header
 * 
 * Copyright (c) 2010 Yang Yang <paulyang.inf@gmail.com>
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef __KRK_CONNECTION_H__
#define __KRK_CONNECTION_H__

#include <krk_event.h>


struct krk_connection {
	char name[32];

	struct krk_event *rev;
	struct krk_event *wev;

	int sock;
};

extern struct krk_connection* krk_connection_create(const char *name);
extern int krk_connection_destroy(struct krk_connection *conn);
extern int krk_connection_init(void);

#endif
