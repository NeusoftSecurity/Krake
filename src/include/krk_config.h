/**
 * krk_config.h - Krake configuration
 * 
 * Copyright (c) 2010 Yang Yang <paulyang.inf@gmail.com>
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef __KRK_CONFIG_H__
#define __KRK_CONFIG_H__

extern void krk_config_read(int sock, short type, void *arg);
extern void krk_config_write(int sock, short type, void *arg);

#define KRK_CONFIG_MAX_LEN 4096

#endif
