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

int krk_events_init(void);
void krk_events_loop(void);

/**
 * krk_events_init - init events
 * @
 *
 * init the unix socket that used with krakectrl.
 * return 0 on success
 */
int krk_events_init(void)
{
	/**
	 * 0) init krk_event 
	 * 1) create a unix socket and listen on it
	 * 2) register read/write event to epoll
	 * 3) other related works
	 */
	return 0;
}

void krk_events_loop(void)
{
	while(1);
}
