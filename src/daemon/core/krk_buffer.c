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

#include <krk_log.h>

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

    memset(buf, 0, sizeof(*buf));
    buf->head = malloc(size);
    if (!buf->head) {
        free(buf);
        return NULL;
    }

    memset(buf->head, 0, size);
    buf->end = buf->head + size;
    buf->pos = buf->last = buf->head;

    buf->size = size;

    return buf;
}

/**
 * krk_buffer_resize - resize a buffer's size, increment only.
 * @buf: old buffer.
 * @size: new size of @buf.
 * 
 * new buffer's pointer on success.
 * old buffer's pointer when size <= old buffer's size.
 * NULL on any kind of failures.
 */
struct krk_buffer* krk_buffer_resize(struct krk_buffer *buf, size_t size)
{
    struct krk_buffer *new_buf;

    if (size <= buf->size) {
        return buf;
    }

    new_buf = krk_buffer_create(size);
    if (!new_buf) {
        return NULL;
    }

    memcpy(new_buf->head, buf->head, buf->size);
    new_buf->pos += (buf->pos - buf->head);
    new_buf->last += (buf->last - buf->head);

    krk_log(KRK_LOG_DEBUG, "buf resized,  old: %p, new: %p, size: %d->%d\n", 
            buf->head, new_buf->head, buf->size, new_buf->size);

    krk_buffer_destroy(buf);

    return new_buf;
}

void krk_buffer_destroy(struct krk_buffer *buf)
{
    free(buf->head);
    free(buf);
}

