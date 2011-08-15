/**
 * krk_buffer.c - Krake buffer
 * 
 * Copyright (c) 2010 Yang Yang <paulyang.inf@gmail.com>
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <krk_core.h>
#include <krk_buffer.h>

#define KRK_DEFAULT_BUFSZ 1024;

struct krk_buffer* krk_buffer_create(size_t size);
void krk_buffer_destroy(struct krk_buffer *buf);

struct krk_buffer* krk_buffer_create(size_t size)
{
	struct krk_buffer *buf;

	if (size == 0) {
		size = KRK_DEFAULT_BUFSZ;
	}

	buf = malloc(sizeof(struct krk_buffer));
	if (!buf) {
		return NULL;
	}
	
	buf->head = malloc(size);
	if (!buf->head) {
		free(buf);
		return NULL;
	}

	buf->end = buf->head + size;
	buf->pos = buf->last = buf->head;

	buf->size = size;

	return buf;
}

struct krk_buffer* krk_buffer_resize(struct krk_buffer *buf, size_t size)
{
	return NULL;
}

void krk_buffer_destroy(struct krk_buffer *buf)
{
	free(buf->head);
	free(buf);
}

