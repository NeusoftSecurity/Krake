/**
 * krk_checker.h - Krake checker
 * 
 * Copyright (c) 2011 Yang Yang <paulyang.inf@gmail.com>
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef __KRK_CHECKER_H__
#define __KRK_CHECKER_H__


#define KRK_CHECKER_ICMP 1
#define KRK_CHECKER_TCP 2
#define KRK_CHECKER_HTTP 3
#define KRK_CHECKER_FTP 4

typedef int (*checker_handler)(void *, void *);

struct krk_checker {
	char *name;
	unsigned int id;

	checker_handler handler;
};

extern int krk_checker_register(struct krk_checker *checker);
extern void krk_checker_unregister(struct krk_checker *checker);

#endif

