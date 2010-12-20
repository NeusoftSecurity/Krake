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

extern int krk_event_init(void);
extern void krk_event_loop(void);

int (*ev_handler)();

struct krk_event {
	struct event *ev;
	struct timeval *w_timeout;
	int sock;
};

#endif
