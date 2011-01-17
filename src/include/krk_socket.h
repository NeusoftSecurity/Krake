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


#define LOCAL_SOCK_PATH "/tmp/krake.sock"
#define LOCAL_SOCK_BACKLOG 5

extern int krk_local_socket_init(void);
extern int krk_local_socket_exit(void);

extern int krk_socket_tcp_create(int protocol);
extern int krk_socket_close(int sock);

#endif
