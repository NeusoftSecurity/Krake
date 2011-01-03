/**
 * krk_buffer.h - Krake buffer
 * 
 * Copyright (c) 2010 Yang Yang <paulyang.inf@gmail.com>
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef __KRK_BUFFER_H__
#define __KRK_BUFFER_H__


struct krk_buffer {
	char *pos;
	char *last;
	char *head;
	char *end;
};

extern struct krk_buffer* krk_buffer_create(size_t size);
extern void krk_buffer_destroy(struct krk_buffer *buf);

#endif

