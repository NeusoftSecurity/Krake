/**
 * krk_socket.c - functions related to socket
 * 
 * Copyright (c) 2010 Yang Yang <paulyang.inf@gmail.com>
 *
 * This file contains the functions related to socket, such as
 * event process, 
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

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
	return 0;
}

void krk_events_loop(void)
{
	while(1);
}
