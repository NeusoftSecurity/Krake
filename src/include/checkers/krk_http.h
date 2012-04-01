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
#define KRK_MAX_HTTP_SEND_FILE 128
#define KRK_MAX_HTTP_EXPECTED 1024
#define KRK_MAX_HTTP_EXPECTED_FILE 128

#define HTTP_CONTENT_STRING "Content-Length: "
#define HTTP_DEFAULT_REQUEST "GET / HTTP/1.1\r\nConnection: close\r\n\r\n"

/* http specific command */
#define HTTP_PARSE_SEND 0
#define HTTP_PARSE_EXPECTED 1
#define HTTP_PARSE_EXPECTED_FILE 2
#define HTTP_PARSE_SEND_FILE 3


/* maybe this is useless */
struct http_checker_data {
	char send[KRK_MAX_HTTP_SEND];
	char expected[KRK_MAX_HTTP_EXPECTED];
};

struct http_checker_param {
	char send[KRK_MAX_HTTP_SEND]; /* request line */
	unsigned int send_len;
	char send_file[KRK_MAX_HTTP_SEND_FILE];
	unsigned int send_file_len;
	char expected[KRK_MAX_HTTP_EXPECTED];
	unsigned int expected_len;
	char expected_file[KRK_MAX_HTTP_EXPECTED_FILE];
	unsigned int expected_file_len;
	char username[64];
	char password[64];

	char ssl;
	char send_in_file;
	char expected_in_file;
};

struct http_response_header {
	unsigned int code;
	char *header_start, *header_last, *body_start; /* include last two \r\n */
	unsigned int body_len;
};

#endif
