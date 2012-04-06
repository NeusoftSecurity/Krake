/**
 * krk_checker.c - Krake checker
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
#include <checkers/krk_checker.h>
#include <checkers/krk_tcp.h>
#include <checkers/krk_icmp.h>
#include <checkers/krk_http.h>

struct krk_checker *krk_all_checkers[] = {
    &tcp_checker,
    &icmp_checker,
    &http_checker,
    NULL
};

struct krk_checker* krk_checker_find(char *name)
{
    int i = 0;
    struct krk_checker **tmp;

    tmp = krk_all_checkers;

    while (tmp[i]) {
        if (!strcmp(name, tmp[i]->name)) {
            return tmp[i];
        }

        i++;
    };

    return NULL;
}

/**
 * krk_in_chsum
 *
 * copied from iputils package.
 * original at iputils/ping.c
 */
unsigned short krk_in_cksum(const unsigned short *addr, register int len, unsigned short csum)
{
    register int nleft = len; 
    const u_short *w = addr;
    register u_short answer;
    register int sum = csum;

    /*   
     *  Our algorithm is simple, using a 32 bit accumulator (sum),
     *  we add sequential 16 bit words to it, and at the end, fold
     *  back all the carry bits from the top 16 bits into the lower
     *  16 bits.
     */
    while (nleft > 1)  {
        sum += *w++;
        nleft -= 2;
    }    

    /* mop up an odd byte, if necessary */
    if (nleft == 1)
        sum += htons(*(u_char *)w << 8);

    /*   
     * add back carry outs from top 16 bits to low 16 bits
     */
    sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
    sum += (sum >> 16);         /* add carry */
    answer = ~sum;              /* truncate to 16 bits */
    return (answer);
}

