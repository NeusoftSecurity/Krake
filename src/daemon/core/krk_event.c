/**
 * krk_event.c - core event
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
#include <krk_socket.h>

int krk_event_init(void);
void krk_event_loop(void);
int krk_event_add(struct krk_event *event, const struct timeval *timeout);
int krk_event_del(struct krk_event *event);
void krk_event_set(struct krk_event *event, short type, 
		void (*handler)(int, short, void*), void* arg);

static struct krk_event *local_event;


/**
 * krk_event_new - create a new event
 * 
 * @sock socket with this event;
 *
 * return address of new event on success;
 * NULL for failed.
 */
struct krk_event* krk_event_new(int sock)
{
	struct krk_event* event;

	event = malloc(sizeof(struct krk_event));
	if (!event) {
		return NULL;
	}

	event->sock = sock;

	event->ev = malloc(sizeof(struct event));
	if (!event->ev) {
		return NULL;
	}

	return event;
}

/**
 * krk_event_init - init events
 * @
 *
 * init the unix socket that used with krakectrl.
 * return 0 on success
 */
int krk_event_init(void)
{
	/**
	 * 0) init krk_event 
	 * 1) create a unix socket and listen on it
	 * 2) register read/write event to epoll
	 * 3) other related works
	 */
	int local_sock;

	event_init();

	local_sock = krk_open_local_socket();
	if (local_sock < 0) {
		return -1;
	}

	local_event = krk_event_new(local_sock);
	if (!local_event) {
		return -1;
	}

	krk_event_set(local_event, EV_READ, krk_local_accept, local_event);

	krk_event_add(local_event, NULL);

	return 0;
}

int krk_event_add(struct krk_event *event, const struct timeval *timeout)
{
	return event_add(event->ev, timeout);
}

int krk_event_del(struct krk_event *event)
{
	return event_del(event->ev);
}

void krk_event_set(struct krk_event *event, short type, 
		void (*handler)(int, short, void*), void* arg)
{
	event_set(event->ev, event->sock, type, handler, arg);
}

void krk_event_loop(void)
{
	event_dispatch();
}

