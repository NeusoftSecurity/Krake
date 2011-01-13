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


LIST_HEAD(krk_all_checkers);
unsigned int krk_nr_checkers = 0;

int krk_checker_register(struct krk_checker *checker)
{
	return KRK_OK;
}

void krk_checker_unregister(struct krk_checker *checker)
{
}
