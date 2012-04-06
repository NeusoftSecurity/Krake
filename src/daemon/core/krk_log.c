/**
 * krk_log.c - functions related to logging
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
#include <krk_log.h>

static FILE *log_fp;
static char log_type = LOG_TYPE_DEFAULT;
static char log_level = LOG_LEVEL_DEFAULT;

static char *krk_prio[] = {
    "emerg",
    "alert",
    "crit",
    "err",
    "warning",
    "notice",
    "info",
    "debug"
};

int krk_log_init(void)
{
    log_fp = fopen(KRK_LOG_FILE, "w");
    if (log_fp == NULL) {
        return KRK_ERROR;
    }

    openlog(KRK_SYSLOG_IDENT, 0, KRK_SYSLOG_FACILITY);

    return KRK_OK;
}

int krk_log_exit(void)
{
    fclose(log_fp);
    closelog();

    return KRK_OK;
}

/**
 * krk_log_set_type - set the log type.
 * @type: log type string, can be "file", "syslog" or "file,syslog" which indicates send
 *        log to both.
 * @level: log level string, see krk_prio array for the values.
 * 
 * 
 * This routine always returns KRK_OK.
 */
int krk_log_set_type(char *type, char *level)
{
    int i, j, len;

    log_type = 0;

    len = strlen(type);
    for (i = 0; i < len; i++) {
        if (i + strlen("file") <= len 
                && !memcmp(type + i, "file", strlen("file"))) {
            log_type |= LOG_TYPE_FILE;
        }

        if (i + strlen("syslog") <= len 
                && !memcmp(type + i, "syslog", strlen("syslog"))) {
            log_type |= LOG_TYPE_SYSLOG;
        }
    }

    len = strlen(level);
    for (j = 0; j < 8; j++) {
        if (strlen(level) == strlen(krk_prio[j])
                && !memcmp(level, krk_prio[j], strlen(krk_prio[j]))) {
            log_level = j;
            goto out;
        }
    }

out:
    if (log_type == 0) {
        log_type = LOG_TYPE_DEFAULT;
    }

    krk_log(KRK_LOG_NOTICE, "log settings changed, " 
            "log type: %d, log level: %d\n", log_type, log_level);

    return KRK_OK;
}

static char* weed(char *str)
{
    int i;

    for (i = 0; i < strlen(str); i++) {
        if (str[i] == '\n') {
            str[i] = '\0';
            break;
        }
    }

    return str;
}

/**
 * krk_log - send a log to syslogd/rsyslogd or a file.
 * @prio: log level, we use 0-7 prioity values same as syslog.
 * @fmt: format of a log string.
 * @...: variable used to build a log string.
 * 
 * no return value.
 *
 * This is the main log routine in krake.This routine can send logs to both
 * syslogd or a file, depend on the log_type variable which can be set by user.
 */
void krk_log(int prio, const char *fmt, ...)
{
    va_list arg_ptr;
    char new_fmt[KRK_MAX_LOG_SIZE];
    time_t t;

    if (prio > log_level) {
        return;
    }

    t = time(NULL);

    if (log_type & LOG_TYPE_FILE) {
        va_start(arg_ptr, fmt);
        snprintf(new_fmt, KRK_MAX_LOG_SIZE, filelog_format, 
                weed(ctime(&t)), krk_prio[prio], fmt);

        vfprintf(log_fp, new_fmt, arg_ptr);
        fflush(log_fp);

        va_end(arg_ptr);
    }

    if (log_type & LOG_TYPE_SYSLOG) {
        va_start(arg_ptr, fmt);
        vsyslog(prio, fmt, arg_ptr);
        va_end(arg_ptr);
    }
}
