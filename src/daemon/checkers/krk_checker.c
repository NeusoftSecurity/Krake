/**
 * krk_checker.c - Krake checker
 * 
 * Copyright (c) 2011 Yang Yang <paulyang.inf@gmail.com>
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <krk_checker.h>

struct krk_checker checkers[] = {
	{"icmp", KRK_CHECKER_ICMP},
	{"tcp", KRK_CHECKER_TCP},
	{"http", KRK_CHECKER_HTTP},
	{"ftp", KRK_CHECKER_FTP},
};


