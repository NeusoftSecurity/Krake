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

#ifndef __KRK_SOCKET_H__
#define __KRK_SOCKET_H__

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>

extern int krk_open_local_socket(void);
extern void krk_local_accept(int sock, short type, void *arg);

#endif
