/**
 * krk_ssl.h - Krake Secure Socket Layer support
 * 
 * Copyright (c) 2012 Yang Yang <paulyang.inf@gmail.com>
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */


#ifndef __KRK_SSL_H__
#define __KRK_SSL_H__

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/engine.h>
#include <openssl/evp.h>

typedef SSL krk_ssl_socket;

struct krk_ssl {
    SSL_CTX *ctx;
};

struct krk_ssl_connection {
    krk_ssl_socket *ssl_connection;

    int handshaked:1;
    int inited:1;
};

extern int krk_ssl_init(void);
extern int krk_ssl_exit(void);
extern struct krk_ssl* krk_ssl_new_ctx(void);
extern int krk_ssl_init_ctx(struct krk_ssl *ssl);

extern struct krk_ssl_connection * 
krk_ssl_create_connection(int sock, struct krk_ssl *ssl);

ssize_t 
krk_ssl_recv(krk_ssl_socket *ssl, u_char *buf, size_t size);
ssize_t 
krk_ssl_send(krk_ssl_socket *ssl, u_char *buf, size_t size);

#endif
