/**
 * krk_icmp.h - Krake icmp checker
 * 
 * Copyright (c) 2011 Yang Yang <paulyang.inf@gmail.com>
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef __KRK_ICMP_H__
#define __KRK_ICMP_H__

extern struct krk_checker icmp_checker;

#define KRK_MAX_IP_LEN 60
#define KRK_MAX_ICMP_LEN 76
#define KRK_ICMP_DATA_LEN 20

struct icmp_checker_data {
    unsigned short id;
    unsigned short sequence;
};

#endif
