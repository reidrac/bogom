/* $Id: conf.h,v 1.4 2007/02/08 15:35:02 reidrac Exp reidrac $ */

/*
* conf.h, configuration reader and parser include
* Copyright (C) 2004-2007 Juan J. Martinez <jjm*at*usebox*dot*net>
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License Version 2 as
* published by the Free Software Foundation.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*
*/

#ifndef __BOGOM_CONF__
#define __BOGOM_CONF__

#define REQ_NONE	0
#define REQ_BOOL	1
#define REQ_STRING	2
#define REQ_QSTRING	3
#define REQ_LSTQSTRING	4

struct string_list
{
	char *s;
	struct string_list *n;
};

struct conftoken
{
	char *word;
	int required;
	char *str;
	int bool;
	struct string_list *sl;
};

int read_conf(const char *filename, struct conftoken *);

#endif

