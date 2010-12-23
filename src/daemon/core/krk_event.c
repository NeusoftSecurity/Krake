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
int krk_event_add(struct krk_event *event);
int krk_event_del(struct krk_event *event);
struct krk_event* krk_event_create(void);
int krk_event_destroy(struct krk_event* event);
void krk_event_set(int sock, struct krk_event *event, short type);
void krk_event_set_read(int sock, struct krk_event *event);
void krk_event_set_write(int sock, struct krk_event *event);


/**
 * krk_event_create - create a new event
 * @
 *
 * return address of new event on success;
 * NULL for failed.
 */
struct krk_event* krk_event_create(void)
{
	struct krk_event* event;

	event = malloc(sizeof(struct krk_event));
	if (!event) {
		return NULL;
	}

	memset(event, 0, sizeof(struct krk_event));

	event->ev = malloc(sizeof(struct event));
	if (!event->ev) {
		free(event);
		return NULL;
	}

	return event;
}

/**
 * krk_event_destroy - destroy an event
 * 
 * @event: event to destroy
 *
 *
 * return 0 on success;
 * -1 for failed.
 */
int krk_event_destroy(struct krk_event* event)
{
	if (!event) {
		/*TODO: add error log */
		return -1;
	}

	(void)krk_event_del(event);

	if (event->ev) {
		free(event->ev);
	}

	if (event->timeout) {
		free(event->timeout);
	}

	free(event);

	return 0;
}

/**
 * krk_event_init - init events
 * @
 *
 * return 0 on success
 */
int krk_event_init(void)
{
	event_init();

	return 0;
}

/**
 * krk_event_exit - exit events
 * @
 *
 * return 0 on success
 */
int krk_event_exit(void)
{
	return 0;
}

int krk_event_add(struct krk_event *event)
{
	return event_add(event->ev, event->timeout);
}

int krk_event_del(struct krk_event *event)
{
	return event_del(event->ev);
}

void krk_event_set(int sock, struct krk_event *event, short type)
{
	event_set(event->ev, sock, type, event->handler, (void*)event);
}

void krk_event_set_read(int sock, struct krk_event *event)
{
	krk_event_set(sock, event, EV_READ);
}

void krk_event_set_write(int sock, struct krk_event *event)
{
	krk_event_set(sock, event, EV_WRITE);
}

void krk_event_loop(void)
{
	event_dispatch();
}

