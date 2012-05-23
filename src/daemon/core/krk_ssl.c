/**
 * krk_ssl.c - Krake Secure Socket Layer support
 * 
 * Copyright (c) 2012 Yang Yang <paulyang.inf@gmail.com>
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
#include <krk_core.h>
#include <krk_log.h>
#include <krk_ssl.h>

int krk_ssl_init(void)
{
    OPENSSL_config(NULL);

    SSL_library_init();
    SSL_load_error_strings();

    OpenSSL_add_all_algorithms();

    return KRK_OK;
}

int krk_ssl_exit(void)
{
    EVP_cleanup();

    return KRK_OK;
}

struct krk_ssl* krk_ssl_new_ctx(void)
{
    struct krk_ssl *ssl;

    ssl = malloc(sizeof(struct krk_ssl));
    if (ssl == NULL) {
        return NULL;
    }

    ssl->ctx = SSL_CTX_new(SSLv23_method());
    if (ssl->ctx == NULL) {
        free(ssl);
        return NULL;
    }

    return ssl;
}

void krk_ssl_free_ctx(struct krk_ssl *ssl)
{
    if (!ssl) 
        return;

    SSL_CTX_free(ssl->ctx);
    free(ssl);
}

static void
krk_ssl_info_callback(const SSL *ssl, int where, int ret)
{
    return;
}

/**
 *
 * Follow Nginx's setup
 *
 */
int krk_ssl_init_ctx(struct krk_ssl *ssl)
{
    SSL_CTX_set_options(ssl->ctx, SSL_OP_MICROSOFT_SESS_ID_BUG);
    SSL_CTX_set_options(ssl->ctx, SSL_OP_NETSCAPE_CHALLENGE_BUG);

    SSL_CTX_set_options(ssl->ctx, SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG);
    SSL_CTX_set_options(ssl->ctx, SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER);

    SSL_CTX_set_options(ssl->ctx, SSL_OP_MSIE_SSLV2_RSA_PADDING);

    SSL_CTX_set_options(ssl->ctx, SSL_OP_SSLEAY_080_CLIENT_DH_BUG);
    SSL_CTX_set_options(ssl->ctx, SSL_OP_TLS_D5_BUG);
    SSL_CTX_set_options(ssl->ctx, SSL_OP_TLS_BLOCK_PADDING_BUG);

    SSL_CTX_set_options(ssl->ctx, SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS);
    SSL_CTX_set_options(ssl->ctx, SSL_OP_SINGLE_DH_USE);

    SSL_CTX_set_read_ahead(ssl->ctx, 1);

    SSL_CTX_set_info_callback(ssl->ctx, krk_ssl_info_callback);

    return KRK_OK;
}

struct krk_ssl_connection * 
krk_ssl_create_connection(int sock, struct krk_ssl *ssl)
{
    struct krk_ssl_connection *sc;

    sc = malloc(sizeof(struct krk_ssl_connection));
    if (sc == NULL) {
        return NULL;
    }

    sc->ssl_connection = SSL_new(ssl->ctx);
    if (sc->ssl_connection == NULL) {
        free(sc);
        return NULL;
    }
    
    if (SSL_set_fd(sc->ssl_connection, sock) == 0) {
        free(sc);
        return NULL;
    }

    SSL_set_connect_state(sc->ssl_connection);

    sc->inited = 1;

    return sc;
}

void krk_ssl_destroy_connection(struct krk_ssl_connection *sc)
{
    if (sc->inited) {
        if (sc->handshaked) {
            SSL_shutdown(sc->ssl_connection);
        }

        SSL_free(sc->ssl_connection);
    }

    free(sc);
}

void krk_ssl_clear_error(void)
{
    while (ERR_peek_error()) {
    }

    ERR_clear_error();
}

int krk_ssl_handshake(struct krk_ssl_connection *sc)
{
    int ret, sslerr;

    krk_ssl_clear_error();

    krk_log(KRK_LOG_DEBUG, "ssl handshake, connection: %p\n", sc->ssl_connection);

    ret = SSL_do_handshake(sc->ssl_connection);

    if (ret == 1) {
        sc->handshaked = 1;

        /* initial handshake done, disable renegotiation (CVE-2009-3555) */
        if (sc->ssl_connection->s3) {
            sc->ssl_connection->s3->flags |= SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS;
        }

        return KRK_OK;
    }

    /* error happened */
    sslerr = SSL_get_error(sc->ssl_connection, ret);
    if (sslerr == SSL_ERROR_WANT_READ) {
        //c->read->handler = ngx_ssl_handshake_handler;
        //c->write->handler = ngx_ssl_handshake_handler;

        /*
        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            return NGX_ERROR;
        } 
        */

        return KRK_AGAIN_READ;
    } 

    if (sslerr == SSL_ERROR_WANT_WRITE) {
        /* 
        c->write->ready = 0; 
        c->read->handler = ngx_ssl_handshake_handler;
        c->write->handler = ngx_ssl_handshake_handler;

        if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
            return NGX_ERROR;
        }
        */

        return KRK_AGAIN_WRITE;
    }

    return KRK_ERROR;
}

ssize_t 
krk_ssl_recv(krk_ssl_socket *ssl, u_char *buf, size_t size)
{
    return SSL_read(ssl, buf, size);
}

ssize_t 
krk_ssl_send(krk_ssl_socket *ssl, u_char *buf, size_t size)
{
    return SSL_write(ssl, buf, size);
}
 
