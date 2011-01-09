/**
 * krk_monitor.c - Krake monitor
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

struct krk_monitor* krk_monitor_find(char *name);
struct krk_monitor* krk_monitor_create(char *name);
int krk_monitor_destroy(struct krk_monitor *monitor);
int krk_monitor_init(void);
int krk_all_monitors_destroy(void);
int krk_monitor_exit(void);
int krk_monitor_add_node(struct krk_monitor *monitor, 
		struct krk_node *node);
int krk_monitor_remove_node(struct krk_monitor *monitor, 
		struct krk_node *node);
void krk_monitor_enable(struct krk_monitor *monitor);
void krk_monitor_disable(struct krk_monitor *monitor);

LIST_HEAD(krk_all_monitors);
unsigned int krk_max_monitors = 0;
unsigned int krk_nr_monitors = 0;

/**
 * krk_monitor_find - find a monitor by name
 * @name: name of monitor to find.
 *
 *
 */
struct krk_monitor* krk_monitor_find(char *name)
{
	struct krk_monitor *tmp;
	struct list_head *p, *n;

	list_for_each_safe(p, n, &krk_all_monitors) {
		tmp = list_entry(p, struct krk_monitor, list);
		if (!strcmp(name, tmp->name)) {
			return tmp;
		}
	}

	return NULL;
}

/**
 * krk_monitor_create - create a monitor
 * @name: name of monitor to create.
 *
 *
 * return address of new monitor  on success;
 * NULL means failed.
 */
struct krk_monitor* krk_monitor_create(char *name)
{	
	struct krk_monitor *monitor = NULL;

	if (!name) {
		return NULL;
	}

	monitor = krk_monitor_find(name);
	if (monitor != NULL) {
		return NULL;
	}

	if (krk_nr_monitors == krk_max_monitors) {
		return NULL;
	}

	monitor = malloc(sizeof(struct krk_monitor));
	if (!monitor) {
		return NULL;
	}

	memset(monitor, 0, sizeof(struct krk_monitor));
	INIT_LIST_HEAD(&monitor->node_list);

	strcpy(monitor->name, name);

	list_add_tail(&monitor->list, &krk_all_monitors);
	
	krk_nr_monitors++;

	return monitor;
}

int krk_monitor_destroy(struct krk_monitor *monitor)
{
	if (!monitor) {
		return KRK_ERROR;
	}

	/*TODO: destroy node_list */

	list_del(&monitor->list);
	
	free(monitor);

	krk_nr_monitors--;

	return KRK_OK;
}

int krk_all_monitors_destroy(void)
{
	struct list_head *p, *n;
	struct krk_monitor *tmp;
	int ret = KRK_OK;

	list_for_each_safe(p, n, &krk_all_monitors) {
		tmp = list_entry(p, struct krk_monitor, list);
		if (krk_monitor_destroy(tmp)) {
			ret = KRK_ERROR;
		}
	}

	return ret;
}

int krk_monitor_add_node(struct krk_monitor *monitor, 
		struct krk_node *node)
{
	int ret = KRK_OK;

	return ret;
}

int krk_monitor_remove_node(struct krk_monitor *monitor, 
		struct krk_node *node)
{
	int ret = KRK_OK;

	return ret;
}

void krk_monitor_enable(struct krk_monitor *monitor)
{
	monitor->flags |= KRK_MONITOR_FLAG_ENABLED;
}

void krk_monitor_disable(struct krk_monitor *monitor)
{
	monitor->flags &= ~KRK_MONITOR_FLAG_ENABLED;
}

int krk_monitor_init(void)
{
	INIT_LIST_HEAD(&krk_all_monitors);

	krk_max_monitors = 64;

	return KRK_OK;
}

int krk_monitor_exit(void)
{
	return krk_all_monitors_destroy();
}
