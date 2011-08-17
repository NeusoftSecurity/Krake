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

#include <syslog.h>

#define KRK_LOG_FILE "/tmp/krake.log"

#define KRK_LOG_EMERG LOG_EMERG
#define KRK_LOG_ALERT LOG_ALERT
#define KRK_LOG_CRIT LOG_CRIT
#define KRK_LOG_ERR LOG_ERR
#define KRK_LOG_WARNING LOG_WARNING
#define KRK_LOG_NOTICE LOG_NOTICE
#define KRK_LOG_INFO LOG_INFO
#define KRK_LOG_DEBUG LOG_DEBUG

#define filelog_format "[%s][%s]krake: %s"
#define syslog_format "krake: %s"

#define KRK_SYSLOG_IDENT "krake"
#define KRK_SYSLOG_FACILITY LOG_LOCAL6
#define KRK_SYSLOG_LEVEL LOG_INFO

#define LOG_TYPE_FILE 0x1
#define LOG_TYPE_SYSLOG 0x2

#define LOG_TYPE_DEFAULT LOG_TYPE_FILE
#define LOG_LEVEL_DEFAULT KRK_LOG_NOTICE

#define KRK_MAX_LOG_SIZE 1024

extern int krk_log_init(void);
extern int krk_log_exit(void);

extern int krk_log_set_type(char *type, char *level);

extern void krk_log(int prio, const char *fmt, ...);

#endif
