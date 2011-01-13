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

#include <krk_core.h>
#include <krk_monitor.h>
#include <checkers/krk_checker.h>
#include <checkers/krk_tcp.h>

struct krk_checker *krk_all_checkers[] = {
	&tcp_checker,
	NULL
};

struct krk_checker* krk_checker_find(char *name)
{
	int i = 0;
	struct krk_checker **tmp;

	tmp = krk_all_checkers;

	while (tmp[i]) {
		if (!strcmp(name, tmp[i]->name)) {
			return tmp[i];
		}
	};

	return NULL;
}
