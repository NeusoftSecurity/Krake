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
#include <krk_buffer.h>
#include <krk_log.h>

int krk_event_init(void);
void krk_event_loop(void);
int krk_event_add(struct krk_event *event);
int krk_event_del(struct krk_event *event);
struct krk_event* krk_event_create(size_t bufsz);
int krk_event_destroy(struct krk_event* event);
void krk_event_set(int sock, struct krk_event *event, short type);
void krk_event_set_timer(struct krk_event *tmout);
void krk_event_set_read(int sock, struct krk_event *event);
void krk_event_set_write(int sock, struct krk_event *event);

/* the global event_base */
static struct event_base *krk_event_base = NULL;

/**
 * krk_event_create - create a new event
 * @
 *
 * return address of new event on success;
 * NULL for failed.
 */
struct krk_event* krk_event_create(size_t bufsz)
{
    struct krk_event* event;

    event = malloc(sizeof(struct krk_event));
    if (!event) {
        return NULL;
    }

    memset(event, 0, sizeof(struct krk_event));

    event->buf = krk_buffer_create(bufsz);
    if (!event->buf) {
        free(event);
        return NULL;
    }

    memset(event->buf, 0, bufsz);

    return event;
}

/**
 * krk_event_destroy - destroy an event
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

    if (event->ev) {
        event_free(event->ev);
    }

    if (event->timeout) {
        free(event->timeout);
    }

    if (event->buf) {
        krk_buffer_destroy(event->buf);
        event->buf = NULL;
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
    krk_event_base = event_base_new();
    if (krk_event_base == NULL) {
        return KRK_ERROR;
    }

    return KRK_OK;
}

/**
 * krk_event_exit - exit events
 * @
 *
 * return 0 on success
 */
int krk_event_exit(void)
{
    event_base_free(krk_event_base);

    return KRK_OK;
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
    /* set here means delete the old one and assign a new one */
    if (event->ev) {
        event_free(event->ev);
    }

    event->ev = event_new(krk_event_base, sock, type, event->handler, (void*)event);
    if (event->ev == NULL) {
        krk_log(KRK_LOG_DEBUG, "ev-%p: event_new failed in %s\n", event, __func__);
        /* FIXME: do some thing here */
    }
}

void krk_event_set_timer(struct krk_event *tmout)
{
    if (tmout->ev) {
        event_free(tmout->ev);
    }

    tmout->ev = evtimer_new(krk_event_base, tmout->handler, (void*)tmout);
    if (tmout->ev == NULL) {
        krk_log(KRK_LOG_DEBUG, "ev-%p: event_new failed in %s\n", tmout, __func__);
        /* FIXME: do some thing here */
    }
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
    /* FIXME: use EVLOOP_NO_EXIT_ON_EMPTY as the flag in higher version libevent */
    event_base_loop(krk_event_base, 0);
}

