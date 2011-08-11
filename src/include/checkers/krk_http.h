/**
 * krk_http.h - Krake http checker
 * 
 * Copyright (c) 2011 Yang Yang <paulyang.inf@gmail.com>
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef __KRK_HTTP_H__
#define __KRK_HTTP_H__

extern struct krk_checker http_checker;

#define KRK_MAX_IP_LEN 60
#define KRK_MAX_HTTP_LEN 1024

#define KRK_MAX_HTTP_SEND 512
#define KRK_MAX_HTTP_EXPECTED 1024

#define HTTP_PARSE_SEND 0
#define HTTP_PARSE_EXPECTED 1

/* maybe this is useless */
struct http_checker_data {
	char send[KRK_MAX_HTTP_SEND];
	char expected[KRK_MAX_HTTP_EXPECTED];
};

struct http_checker_param {
	char send[KRK_MAX_HTTP_SEND]; /* request line */
	unsigned int send_len;
	char expected[KRK_MAX_HTTP_EXPECTED];
	unsigned int expected_len;
	char username[64];
	char password[64];

	char ssl;
};

#endif
