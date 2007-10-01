/* $Id: conf.c,v 1.10 2007/02/08 15:35:02 reidrac Exp reidrac $ */

/*
* conf.c, configuration reader and parser
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

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<errno.h>
#include<ctype.h>

#include "libmilter/mfapi.h"
#include "conf.h"

#define new_string_list(x) do {\
		x=(struct string_list *) \
			malloc(sizeof(struct string_list));\
		x->n=NULL;\
	} while(0)

static char * pstrncpy(char *, const char *, size_t);
static int parse_string(char *p);
static int parse_qstring(char *p);
static int parse_bool(char *p);
static char * parse_conf(struct conftoken *conf, char *p);

static const char rcsid[]="$Id: conf.c,v 1.10 2007/02/08 15:35:02 reidrac Exp reidrac $";

/*
* strncpy alike function that parses scaped quotes
*/
static char *
pstrncpy(char *d, const char *s, size_t l)
{
	size_t i, j;

	for(i=0, j=0; i<l && s[i]; i++, j++)
	{
		if(s[i]=='\\' && i+1<l)
			if(s[i+1]=='\'' || s[i+1]=='\"')
				i++;
		d[j]=s[i];
	}

	d[j]=0;

	return d;
}

/*
* parses a string and returns its length
*/
static int
parse_string(char *p)
{
	char *t;

	for(t=p; *t && !isspace(*t); t++);

	return (int)(t-p);
}

/*
* parses a quoted string and returns its length
* on error:
*	-1	close quote expected
*	0	empty quotes
*/
static int
parse_qstring(char *p)
{
	char *t;
	char q=*p;

	for(t=++p; *t; t++)
	{
		if(*t==q)
			break;

		if(*t=='\\' && t[1]==q)
			t++;
	}

	if(*t!=q)
		return -1;

	if(t==p)
		return 0;

	return (int)(t-p);
}

/*
* parses a bool and returns 0/1
* all values ne 0 are true
*/
static int
parse_bool(char *p)
{
	if(!p[0] || !isspace(p[1]))
		return -1;

	if(*p=='0')
		return 0;
	else
		return 1;
}

/*
* parses one line each call
*/
static char *
parse_conf(struct conftoken *conf, char *p)
{
	int i, len;
	struct string_list *t;

	if(!p)
		return NULL;

	if(!p[0] || p[0]=='\n' || p[0]=='#')
		return NULL;

	while(isspace(*p))
		p++;

	len=parse_string(p);
	if(!len)
		return NULL;

	for(i=0; conf[i].word; i++)
		if(!strncmp(conf[i].word, p, strlen(conf[i].word))) 
		{
			p+=len;
			while(isspace(*p))
				p++;

			switch(conf[i].required)
			{
				case REQ_NONE:
					/* nothing required */
					break;

				case REQ_BOOL:
					len=parse_bool(p);
					if(len<0)
					{
						fprintf(stderr, 
							"bool expected\n");
						return p;
					}

					conf[i].bool=len;
					p++;
					break;

				case REQ_STRING:
					len=parse_string(p);
					if(!len)
					{
						fprintf(stderr, 
							"string expected\n");
						return p;
					}

					if(conf[i].str)
						free(conf[i].str);
					conf[i].str=(char *)malloc(len+1);
					if(!conf[i].str)
					{
						fprintf(stderr, "malloc\n");
						return p;
					}
					strncpy(conf[i].str, p, len);
					p+=len;
					break;

				case REQ_QSTRING:
					if(*p!='\"' && *p!='\'')
					{
						fprintf(stderr,
							"quoted string"
							" expected\n");
						return p;
					}

					len=parse_qstring(p);
					p++;

					if(len==-1)
					{
						fprintf(stderr, 
							"end quote expected\n");
						return p;
					}

					if(!len)
					{
						fprintf(stderr, 
							"empty quotes\n");
						return p;
					}

					if(conf[i].str)
						free(conf[i].str);
					conf[i].str=(char *)malloc(len+1);
					if(!conf[i].str)
					{
						fprintf(stderr, "malloc\n");
						return p;
					}
					pstrncpy(conf[i].str, p, len);
					p+=len+1;
					break;

				case REQ_LSTQSTRING:
					if(*p!='\"' && *p!='\'')
					{
						fprintf(stderr,
							"quoted string"
							" expected\n");
						return p;
					}

					len=parse_qstring(p);
					p++;

					if(len==-1)
					{
						fprintf(stderr, 
							"end quote expected\n");
						return p;
					}

					if(!len)
					{
						fprintf(stderr, 
							"empty quotes\n");
						return p;
					}

					if(!conf[i].sl)
					{
						new_string_list(conf[i].sl);
						if(!conf[i].sl)
						{
							fprintf(stderr,
								"malloc");
							return p;
						}
					}
					else
					{
						new_string_list(t);
						if(!t)
						{
							fprintf(stderr,
								"malloc");
							return p;
						}
						t->n=conf[i].sl;
						conf[i].sl=t;
					}

					conf[i].sl->s=(char *)malloc(len+1);
					if(!conf[i].sl->s)
					{
						fprintf(stderr, "malloc\n");
						return p;
					}
					pstrncpy(conf[i].sl->s, p, len);
					p+=len+1;
					break;
			}
			break;
		}

	if(conf[i].word)
	{
		while(isspace(*p))
			p++;

		if(!p[0])
			return NULL;
	
		fprintf(stderr, "parse error\n");
		return p;
	}

	fprintf(stderr, "unknown token\n");

	p[len]=0;
	return p;
}

/*
* reads and parses the configuration file
*/
int
read_conf(const char *filename, struct conftoken *conf)
{
	FILE *fd;
	char buffer[1024];
	char *ret;
	int line, i;

	fd=fopen(filename, "r");
	if(!fd)
		return 0;

	line=1;
	while(!feof(fd))
	{
		i=0;
		*buffer=0;
		do
		{
			if(i>1023)
			{
				fclose(fd);
				fprintf(stderr, "conf line %i is too long\n",
					 line);
				return 1;
			}

			fscanf(fd, "%c", &buffer[i]);

		} while(buffer[i++]!='\n' && !feof(fd));

		buffer[i]=0;

		ret=parse_conf(conf, buffer);
		if(ret)
		{
			fclose(fd);
			fprintf(stderr, "conf error at line %i, near: %s\n",
				line, ret);
			return 1;
		}

		line++;
	}

	fclose(fd);

	return 0;
}

/* EOF */
