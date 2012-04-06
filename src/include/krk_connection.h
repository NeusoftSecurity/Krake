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

#include <krk_core.h>
#include <krk_list.h>

struct krk_connection {
    char name[KRK_NAME_LEN];

    struct krk_event *rev;
    struct krk_event *wev;

    struct list_head list;
    struct list_head node;

    int sock;
};

extern struct krk_connection* krk_connection_create(const char *name, 
        size_t rbufsz, size_t wbufsz);
extern int krk_connection_destroy(struct krk_connection *conn);
extern int krk_connection_init(void);
extern int krk_all_connections_destroy(void);
extern int krk_connection_exit(void);

#endif
