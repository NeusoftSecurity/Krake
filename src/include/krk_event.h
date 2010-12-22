/**
 * krk_socket.h - Krake socket
 * 
 * Copyright (c) 2010 Yang Yang <paulyang.inf@gmail.com>
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef __KRK_EVENT_H__
#define __KRK_EVENT_H__

#include <event.h>

typedef void (*ev_handler)(int sock, short type, void *arg);


struct krk_connection;

struct krk_event {
	struct event *ev;
	struct timeval *timeout;
	ev_handler handler;
	struct krk_connection *conn;
};


extern int krk_event_init(void);
extern void krk_event_loop(void);
extern int krk_event_add(struct krk_event *event);
extern int krk_event_del(struct krk_event *event);
extern struct krk_event* krk_event_create(void);
extern int krk_event_destroy(struct krk_event* event);
extern void krk_event_set(int sock, struct krk_event *event, short type);
extern void krk_event_set_read(int sock, struct krk_event *event);
extern void krk_event_set_write(int sock, struct krk_event *event);

#endif
