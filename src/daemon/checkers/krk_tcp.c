/**
 * krk_tcp.c - Krake tcp checker
 * 
 * Copyright (c) 2011 Yang Yang <paulyang.inf@gmail.com>
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <checkers/krk_checker.h>
#include <checkers/krk_tcp.h>


static int tcp_parse_param(struct krk_monitor *monitor, 
		char *param, unsigned int param_len);
static int tcp_init_node(struct krk_node *node);
static int tcp_process_node(struct krk_node *node, void *param);

struct krk_checker tcp_checker = {
	"tcp",
	KRK_CHECKER_TCP,
	tcp_parse_param,
	tcp_init_node,
	tcp_process_node,
};

static int tcp_parse_param(struct krk_monitor *monitor, 
		char *param, unsigned int param_len)
{
	return KRK_OK;
}

static int tcp_init_node(struct krk_node *node)
{
	return KRK_OK;
}

static int tcp_process_node(struct krk_node *node, void *param)
{
	return KRK_OK;
}


