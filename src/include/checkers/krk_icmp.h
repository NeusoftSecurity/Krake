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

struct krk_icmphdr {
    unsigned char type;
    unsigned char code;
	unsigned short checksum;
	union {
        struct {
            unsigned short id;
            unsigned short	sequence;
        } echo;
        unsigned int	gateway;
        struct {
            unsigned short	unused;
            unsigned short	mtu;
        } frag;
    } un;
};

#define ICMP_ECHOREPLY		0	/* Echo Reply			*/
#define ICMP_DEST_UNREACH	3	/* Destination Unreachable	*/
#define ICMP_SOURCE_QUENCH	4	/* Source Quench		*/
#define ICMP_REDIRECT		5	/* Redirect (change route)	*/
#define ICMP_ECHO		8	/* Echo Request			*/
#define ICMP_TIME_EXCEEDED	11	/* Time Exceeded		*/
#define ICMP_PARAMETERPROB	12	/* Parameter Problem		*/
#define ICMP_TIMESTAMP		13	/* Timestamp Request		*/
#define ICMP_TIMESTAMPREPLY	14	/* Timestamp Reply		*/
#define ICMP_INFO_REQUEST	15	/* Information Request		*/
#define ICMP_INFO_REPLY		16	/* Information Reply		*/
#define ICMP_ADDRESS		17	/* Address Mask Request		*/
#define ICMP_ADDRESSREPLY	18	/* Address Mask Reply		*/
#define NR_ICMP_TYPES		18


#endif
