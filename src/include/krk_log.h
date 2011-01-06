/**
 * krk_log.h - Krake log
 * 
 * Copyright (c) 2011 Yang Yang <paulyang.inf@gmail.com>
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */


#ifndef __KRK_LOG_H__
#define __KRK_LOG_H__

#define KRK_LOG_FILE "/tmp/krake.log"

#define KRK_LOG_EMERG 0
#define KRK_LOG_NOTICE 1
#define KRK_LOG_INFO 2
#define KRK_LOG_DEBUG 3

extern int krk_log_init(void);
extern int krk_log_exit(void);

#endif
