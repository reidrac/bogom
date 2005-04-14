/* $Id: milter.c,v 1.24 2005/04/04 09:00:51 reidrac Exp reidrac $ */

/*
* bogom, simple sendmail milter to interface bogofilter
* Copyright (C) 2004, 2005 Juan J. Martinez <jjm*at*usebox*dot*net> 
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

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <syslog.h>
#include <regex.h>
#include <time.h>

#ifdef __sun__
#include <sys/stat.h>
#include <fcntl.h>
#endif

#include "libmilter/mfapi.h"
#include "conf.h"

/* defaults */
#ifndef DEF_USER
#define DEF_USER	"bogofilter"
#endif
#ifndef DEF_CONN
#define DEF_CONN	"unix:/var/spool/bogofilter/milter.sock"
#endif
#ifndef DEF_CONF
#define DEF_CONF	"/etc/bogom.conf"
#endif
#ifndef DEF_PIDFILE
#define DEF_PIDFILE	"/var/spool/bogofilter/bogom.pid"
#endif

struct mlfiPriv
{
	FILE *f;
	char *filename;
	char *subject;
	int eom;
	size_t bodylen;
};

sfsistat mlfi_connect(SMFICTX *, char *, _SOCK_ADDR *);
sfsistat mlfi_envfrom(SMFICTX *, char **);
sfsistat mlfi_envrcpt(SMFICTX *, char **);
sfsistat mlfi_header(SMFICTX *, char *, char *);
sfsistat mlfi_eoh(SMFICTX *);
sfsistat mlfi_body(SMFICTX *, unsigned char *, size_t);
sfsistat mlfi_eom(SMFICTX *);
sfsistat mlfi_abort(SMFICTX *);
sfsistat mlfi_close(SMFICTX *);
void mlfi_clean(SMFICTX *);
void usage(const char *);

#ifdef __sun__
int daemon(int, int);
#endif

struct smfiDesc smfilter=
{
	"bogom",	/* filter name */
	SMFI_VERSION,	/* version code -- do not change */
	SMFIF_ADDHDRS | SMFIF_CHGHDRS,	/* flags -- add and modify headers */
	mlfi_connect,	/* connection info filter */
	NULL,		/* SMTP HELO command filter */
	mlfi_envfrom,	/* envelope sender filter */
	mlfi_envrcpt,	/* envelope recipient filter */
	mlfi_header,	/* header filter */
	mlfi_eoh,	/* end of header */
	mlfi_body,	/* body block filter */
	mlfi_eom,	/* end of message */
	mlfi_abort,	/* message aborted */
	mlfi_close	/* connection cleanup */
};

struct re_list
{
	regex_t p;
	const char *pat;
	struct re_list *n;
};

#define new_re_list(x) do {\
		x=(struct re_list *) \
			malloc(sizeof(struct re_list));\
		x->n=NULL;\
	} while(0)

static const char 	rcsid[]="$Id: milter.c,v 1.24 2005/04/04 09:00:51 reidrac Exp reidrac $";

static int		mode=SMFIS_CONTINUE;
static int		train=0;
static int		verbose=0;
static int		debug=0;
static size_t		bodylimit=0;
static const char 	*bogo="/usr/local/bin/bogofilter";
static const char	*exclude=NULL;
static const char	*subj_tag=NULL;

static char		*reject=NULL;

static struct re_list	*re_c=NULL;	/* re connection */
static struct re_list	*re_f=NULL;	/* re envfrom */
static struct re_list	*re_r=NULL;	/* re envrcpt */

#ifdef __sun__
int
daemon(int nochdir, int noclose)
{
	int fd;

	switch(fork())
	{
		case 0:
			break;

		case -1:
			return -1;

		default:
			_exit(0);
	}

	if(setsid()==-1)
		return -1;

	if(!nochdir && chdir("/"))
		return -1;

	if(!noclose)
	{
		fd=open("/dev/null", O_RDWR, 0);
		if(fd==-1)
			return -1;

		dup2(fd, fileno(stdin));
		dup2(fd, fileno(stdout));
		dup2(fd, fileno(stderr));
	}

	return 0;
}
#endif

sfsistat 
mlfi_connect(SMFICTX *ctx, char *hostname, _SOCK_ADDR *hostaddr)
{
	struct mlfiPriv *priv;
	struct re_list *tre;	/* temporal iterator */

	const void *mysaddr=NULL;
	char host[INET6_ADDRSTRLEN];

	switch(hostaddr->sa_family)
	{
		default:
			syslog(LOG_ERR, "mlfi_connet: unsupported sa_family");
			break;

		case AF_INET:
			mysaddr=(const void *)&((struct sockaddr_in *)hostaddr)
				->sin_addr.s_addr;
			break;

		case AF_INET6:
			mysaddr=(const void *)&((struct sockaddr_in6 *)hostaddr)
				->sin6_addr;
			break;
	}

	if(!inet_ntop(hostaddr->sa_family, mysaddr, host, sizeof(host)))
	{
		syslog(LOG_ERR, "mlfi_connect: inet_ntop failed");
		strcpy(host, "*");
	}

	if(debug)
		syslog(LOG_DEBUG, "connection from %s [ %s ]", hostname, host);
	
	for(tre=re_c; tre; tre=tre->n)
	{
		if(!regexec(&tre->p, hostname, 0, NULL, 0))
		{
			if(verbose)
				syslog(LOG_INFO, 
				"accepted due pattern match (connect): %s", 
						tre->pat);

			return SMFIS_ACCEPT;
		}

		if(!regexec(&tre->p, host, 0, NULL, 0))
		{
			if(verbose)
				syslog(LOG_INFO, 
				"accepted due pattern match (connect): %s", 
						tre->pat);
			return SMFIS_ACCEPT;
		}
	}

	priv=(struct mlfiPriv *)malloc(sizeof(struct mlfiPriv));
	if(!priv)
	{
		syslog(LOG_ERR, "Unable to get memory: %s",
			strerror(errno));
		return SMFIS_TEMPFAIL;
	}

	priv->filename=NULL;
	priv->subject=NULL;
	priv->f=NULL;
	priv->eom=1;

	if(smfi_setpriv(ctx, priv)!=MI_SUCCESS)
	{
		syslog(LOG_ERR, "on mlfi_connect: smfi_setpriv");
		return SMFIS_ACCEPT;
	}

	return SMFIS_CONTINUE;
}

sfsistat 
mlfi_envfrom(SMFICTX *ctx, char **argv)
{
	struct re_list *tre;	/* temporal iterator */

	if(debug)
		syslog(LOG_DEBUG, "envfrom %s", argv[0]);

	for(tre=re_f; tre; tre=tre->n)
		if(!regexec(&tre->p, argv[0], 0, NULL, 0))
		{
			if(verbose)
				syslog(LOG_INFO, 
				"accepted due pattern match (envfrom): %s", 
						tre->pat);
			return SMFIS_ACCEPT;
		}

	return SMFIS_CONTINUE;
}

sfsistat 
mlfi_envrcpt(SMFICTX *ctx, char **argv)
{
	struct re_list *tre;	/* temporal iterator */

	if(debug)
		syslog(LOG_DEBUG, "envrcpt %s", argv[0]);

	for(tre=re_r; tre; tre=tre->n)
		if(!regexec(&tre->p, argv[0], 0, NULL, 0))
		{
			if(verbose)
				syslog(LOG_INFO, 
				"accepted due pattern match (envrcpt): %s", 
						tre->pat);
			return SMFIS_ACCEPT;
		}

	return SMFIS_CONTINUE;
}

sfsistat 
mlfi_header(SMFICTX *ctx, char *headerf, char *headerv)
{
	struct mlfiPriv *priv;
	int fd=-1;

	priv=(struct mlfiPriv *)smfi_getpriv(ctx);
	if(!priv)
	{
		syslog(LOG_ERR, "on mlfi_header: smfi_getpriv");
		return SMFIS_ACCEPT;
	}

	if(exclude && headerv)
		if(!strcasecmp(headerf, "Subject"))
			if(strstr(headerv, exclude))
			{
				if(verbose)
					syslog(LOG_INFO, 
						"exclude string found: '%s'", 
						headerv);
				mlfi_clean(ctx);
				return SMFIS_ACCEPT;
			}

	if(priv->eom)
	{
		priv->filename=strdup("/tmp/bogom-msg.XXXXXXXXXX");
		if(!priv->filename)
		{
			syslog(LOG_ERR, "Unable to get memory: %s",
				strerror(errno));
			return SMFIS_TEMPFAIL;
		}

		fd=mkstemp(priv->filename);
		if(fd==-1)
		{
			syslog(LOG_ERR, "Unable to create tmp file in /tmp: %s",
				strerror(errno));

			mlfi_clean(ctx);
			return SMFIS_TEMPFAIL;
		}

		priv->f=fdopen(fd, "w+");
		if(!priv->f)
		{
			syslog(LOG_ERR, "Unable to create tmp file in /tmp: %s",
				strerror(errno));

			if(fd!=-1)
				close(fd);

			mlfi_clean(ctx);
			return SMFIS_TEMPFAIL;
		}

		priv->eom=0;
		priv->bodylen=0;

		if(debug)
			syslog(LOG_DEBUG, "message begin...");
	}

	if(debug)
		syslog(LOG_DEBUG, "header %s [%s]", headerf, headerv);

	if(subj_tag && headerv)
		if(!strcasecmp(headerf, "Subject"))
		{
			if(priv->subject)
				syslog(LOG_INFO,
					"Subject header not unique");
			else
			{
				priv->subject=strdup(headerv);
				if(!priv->subject)
					syslog(LOG_ERR,
						"Unable to get memory (subject"
						" tag): %s",
						strerror(errno));
			}
		}

	if(fprintf(priv->f, "%s: %s\n", headerf, headerv)==EOF)
	{
		syslog(LOG_ERR, "failed to write into %s: %s", 
			priv->filename, strerror(errno));
		mlfi_clean(ctx);
		return SMFIS_TEMPFAIL;
	}

	return SMFIS_CONTINUE;
}

sfsistat 
mlfi_eoh(SMFICTX *ctx)
{
	struct mlfiPriv *priv;

	if(debug)
		syslog(LOG_DEBUG, "headers ok");

	priv=(struct mlfiPriv *)smfi_getpriv(ctx);
	if(!priv)
	{
		syslog(LOG_ERR, "on mlfi_eoh: smfi_getpriv");
		return SMFIS_ACCEPT;
	}

	if(fprintf(priv->f, "\n")==EOF)
	{
		syslog(LOG_ERR, "failed to write into %s: %s", 
			priv->filename, strerror(errno));
		mlfi_clean(ctx);
		return SMFIS_TEMPFAIL;
	}

	return SMFIS_CONTINUE;
}

sfsistat 
mlfi_body(SMFICTX *ctx, unsigned char *bodyp, size_t bodylen)
{
	struct mlfiPriv *priv;

	priv=(struct mlfiPriv *)smfi_getpriv(ctx);
	if(!priv)
	{
		syslog(LOG_ERR, "on mlfi_body: smfi_getpriv");
		return SMFIS_ACCEPT;
	}

	if(bodylimit)
	{
		if(bodylimit==priv->bodylen)
		{
			if(debug)
				syslog(LOG_DEBUG, "body_limit reached, "
						" %d bytes discarded", bodylen);

			bodylen=0;
		}
		else
			if(priv->bodylen+bodylen>bodylimit)
			{
				if(debug)
					syslog(LOG_DEBUG, "body_limit reached, "
						" %d bytes discarded",
					bodylen-(bodylimit-priv->bodylen));

				bodylen=bodylimit-priv->bodylen;
			}
	}

	if(bodylen>0)
	{
		if(fwrite(bodyp, bodylen, 1, priv->f)!=1)
		{
			syslog(LOG_ERR, "failed to write into %s: %s", 
				priv->filename, strerror(errno));
			mlfi_clean(ctx);
			return SMFIS_TEMPFAIL;
		}
		else
		{
			if(debug)
				syslog(LOG_DEBUG, "%d body bytes written", 
						bodylen);

			priv->bodylen+=bodylen;
		}
	}

	return SMFIS_CONTINUE;
}

sfsistat
mlfi_eom(SMFICTX *ctx)
{
	struct mlfiPriv *priv;
	int status, pid;
	char bogo_ops[5]="-\0";
	char *tmp_subj;

	if(debug)
		syslog(LOG_DEBUG, "...end of message");

	priv=(struct mlfiPriv *)smfi_getpriv(ctx);
	if(!priv)
	{
		syslog(LOG_ERR, "on mlfi_eom: smfi_getpriv");
		return SMFIS_ACCEPT;
	}

	fclose(priv->f);
	priv->f=NULL;

	pid=fork();

	if(pid==-1)
	{
		syslog(LOG_ERR, "unable to fork: %s", strerror(errno));
		mlfi_clean(ctx);
		return SMFIS_ACCEPT;
	}
	else 
		if(pid==0)
		{
			if(train)
				strcat(bogo_ops, "u");

			if(verbose)
				strcat(bogo_ops, "l");

			strcat(bogo_ops, "B");
				
			status=execl(bogo, "bogofilter", bogo_ops, 
				priv->filename, (char *)0);

			syslog(LOG_ERR, "unable to execl bogofilter: %s", 
				strerror(errno));
			exit(-1);
		}

	waitpid(pid, &status, 0);

	if(!WIFEXITED(status))
	{
		syslog(LOG_ERR, "bogofilter didn't exit normally");
		mlfi_clean(ctx);
		return SMFIS_CONTINUE;
	}

	switch(WEXITSTATUS(status))
	{
		case 3:
		case -1:
			syslog(LOG_ERR, "bogofilter reply: I/O error"); 
			mlfi_clean(ctx);
			return SMFIS_CONTINUE;
		case 0:
			smfi_insheader(ctx, 0, "X-Bogosity",
				"Yes, tests=bogofilter");

			if(subj_tag && priv->subject)
			{
				tmp_subj=(char *)calloc(sizeof(subj_tag)+
					sizeof(priv->subject)+2, sizeof(char));

				if(!tmp_subj)
					syslog(LOG_ERR, "Unable to get memory:"
						" %s", strerror(errno));
				else
				{
					sprintf(tmp_subj, "%s %s", subj_tag,
						priv->subject);

					/* truncate if needed and be nice 
						with RFC */
					if(strlen(tmp_subj)>998)
						tmp_subj[998]=0;

					if(smfi_chgheader(ctx, "Subject", 1,
						tmp_subj)==MI_SUCCESS && debug)
						syslog(LOG_DEBUG, "subject_tag"
							" added: '%s'", 
								tmp_subj);
					free(tmp_subj);
				}
			}

			if(verbose)
			{
				if(mode==SMFIS_CONTINUE)
					syslog(LOG_NOTICE, 
						"bogofilter reply: spam");
				else
					if(mode==SMFIS_REJECT)
						syslog(LOG_NOTICE, 
							"spam rejected");
					else
						syslog(LOG_NOTICE, 
							"spam discarded");
			}

			if(mode==SMFIS_REJECT && reject)
				smfi_setreply(ctx, "554", "5.7.1", reject);

			mlfi_clean(ctx);
			return mode;
		case 1:
			smfi_insheader(ctx, 0, "X-Bogosity",
				"No, tests=bogofilter");

			if(verbose)
				syslog(LOG_NOTICE, "bogofilter reply: ham");
			break;
		case 2:
			smfi_insheader(ctx, 0, "X-Bogosity",
				"Unsure, tests=bogofilter");
			if(verbose)
				syslog(LOG_NOTICE, "bogofilter reply: unsure");
			break;
		default:
			syslog(LOG_ERR, "bogofilter reply is unknown");
			break;
	}

	mlfi_clean(ctx);
	return SMFIS_CONTINUE;
}

sfsistat 
mlfi_abort(SMFICTX *ctx)
{
	if(debug)
		syslog(LOG_DEBUG, "message ABORTED");

	mlfi_clean(ctx);

	return SMFIS_CONTINUE;
}

sfsistat 
mlfi_close(SMFICTX *ctx)
{
	struct mlfiPriv *priv;

	priv=(struct mlfiPriv *)smfi_getpriv(ctx);
	if(!priv)
		return SMFIS_CONTINUE;

	if(!priv->eom)
		mlfi_clean(ctx);

	smfi_setpriv(ctx, NULL);
	free(priv);

	if(debug)
		syslog(LOG_DEBUG, "connection closed");

	return SMFIS_CONTINUE;
}

void 
mlfi_clean(SMFICTX *ctx)
{
	struct mlfiPriv *priv;

	if(debug)
		syslog(LOG_DEBUG, "cleaning message...");

	priv=(struct mlfiPriv *)smfi_getpriv(ctx);

	if(!priv)
		return;

	if(priv->f)
	{
		if(debug)
			syslog(LOG_DEBUG, "closing tmp file");
		fclose(priv->f);
		priv->f=NULL;
	}

	if(priv->filename)
	{
		if(debug)
			syslog(LOG_DEBUG, "removing tmp file");
		unlink(priv->filename);
		free(priv->filename);
		priv->filename=NULL;
	}

	if(priv->subject)
	{
		free(priv->subject);
		priv->subject=NULL;
	}

	priv->eom=1;

	if(debug)
		syslog(LOG_DEBUG, "...cleaning done");

	return;
}

void
usage(const char *argv0)
{
	fprintf(stderr, "usage: %s\t[-R | -D] [-t] [-v] [-u user] [-s conn]\n"
		"\t\t[-b bogo_path ] [ -x exclude_string ] "
 		"[ -c conf_file ]\n\t\t[ -l body_limit ] [ -p pidfile ] "
		"[ -d ]\n", argv0);

	return;
}

int
main(int argc, char *argv[])
{
	const char *user=DEF_USER;
	const char *conn=DEF_CONN;
	const char *pipe=NULL;
	const char *conffile=DEF_CONF;
	const char *pidfile=DEF_PIDFILE;

	FILE *pidfile_fd;
	int result;

	struct re_list *tre;
 	struct string_list *tsl, *tsl2;

 	/* configuration tokens */
 	struct conftoken conf[]=
 	{
 		{ "verbose", REQ_BOOL, NULL, -1, NULL },
 		{ "training", REQ_BOOL, NULL, -1, NULL },
 		{ "user", REQ_QSTRING, NULL, 0, NULL },
 		{ "connection", REQ_QSTRING, NULL, 0, NULL },
 		{ "exclude_string", REQ_QSTRING, NULL, 0, NULL },
 		{ "re_envfrom", REQ_LSTQSTRING, NULL, 0, NULL },
 		{ "bogofilter", REQ_QSTRING, NULL, 0, NULL },
 		{ "policy", REQ_STRING, NULL, 0, NULL },
 		{ "reject", REQ_QSTRING, NULL, 0, NULL },
 		{ "re_connection", REQ_LSTQSTRING, NULL, 0, NULL },
 		{ "re_envrcpt", REQ_LSTQSTRING, NULL, 0, NULL },
 		{ "body_limit", REQ_STRING, NULL, 0, NULL },
 		{ "pidfile", REQ_QSTRING, NULL, 0, NULL },
 		{ "subject_tag", REQ_QSTRING, NULL, 0, NULL },
 		{ NULL, 0, NULL, 0, NULL }
	};

	int opt;
	const char *opts="hu:p:b:RDtvx:w:c:l:ds:";

	struct passwd *pw=NULL;

	while((opt=getopt(argc, argv, opts))!=-1)
		switch(opt)
		{
			case 'h':
			default:
				usage(argv[0]);
				exit(1);
				break;

			case 'u':
				user=optarg;
				break;

			case 's':
				conn=optarg;
				break;	

			case 'b':
				bogo=optarg;
				break;	

			case 'R':
				mode=SMFIS_REJECT;
				break;

			case 'D':
				mode=SMFIS_DISCARD;
				break;

			case 't':
				train=1;
				break;

			case 'v':
				verbose=1;
				break;

			case 'x':
				exclude=optarg;
				break;	

			case 'c':
				conffile=optarg;
				break;	

			case 'l':
				bodylimit=(size_t)atol(optarg);
				break;	

			case 'd':
				debug=1;
				verbose=1;
				break;

			case 'p':
				pidfile=optarg;
				break;
		}

 	/* read configuration file */
 	if(!read_conf(conffile, conf))
 	{
 		if(conf[0].bool!=-1)
 			verbose=conf[0].bool;
 
 		if(conf[1].bool!=-1)
 			train=conf[1].bool;
 
 		if(conf[2].str)
 			user=conf[2].str;
 
 		if(conf[3].str)
 			conn=conf[3].str;
 
 		if(conf[4].str)
 			exclude=conf[4].str;
 
 		if(conf[5].sl)
 		{
 			for(tsl=conf[5].sl; tsl; tsl=tsl->n, free(tsl2))
 			{
				if(!re_f)
				{
					new_re_list(re_f);
					if(!re_f)
					{
						fprintf(stderr,
						"unable to get memory: %s\n", 
						strerror(errno));
						return 1;
					}
				}
				else
				{
					new_re_list(tre);
					if(!tre)
					{
						fprintf(stderr, 
						"unable to get memory: %s\n", 
						strerror(errno));
						return 1;
					}
					tre->n=re_f;
					re_f=tre;
				}
 
 				if(regcomp(&(re_f->p), tsl->s, REG_EXTENDED|
 					REG_ICASE|REG_NOSUB))
 				{
 					fprintf(stderr,"Bad pattern: %s\n",
 						tsl->s);
 					return 1;
 				}
 				re_f->pat=tsl->s;
 				tsl2=tsl;
 			}
 			conf[5].sl=NULL;
 		}
 
 		if(conf[6].str)
 			bogo=conf[6].str;
 
 		if(conf[7].str)
 		{
 			if(!strcmp(conf[7].str, "pass"))
 				mode=SMFIS_CONTINUE;
 			else
 			{
 				if(!strcmp(conf[7].str, "reject"))
 					mode=SMFIS_REJECT;
 				else
 				{
 					if(!strcmp(conf[7].str, "discard"))
 						mode=SMFIS_DISCARD;
 					else
 					{
 						fprintf(stderr, "conf error:"
 							" unknown policy\n");
 						return 1;
 					}
 				}
 			}
 		}

 		if(conf[8].str)
 			reject=conf[8].str;

 		if(conf[9].sl)
 		{
 			for(tsl=conf[9].sl; tsl; tsl=tsl->n, free(tsl2))
 			{
				if(!re_c)
				{
					new_re_list(re_c);
					if(!re_c)
					{
						fprintf(stderr,
						"unable to get memory: %s\n", 
						strerror(errno));
						return 1;
					}
				}
				else
				{
					new_re_list(tre);
					if(!tre)
					{
						fprintf(stderr, 
						"unable to get memory: %s\n", 
						strerror(errno));
						return 1;
					}
					tre->n=re_c;
					re_c=tre;
				}
 
 				if(regcomp(&(re_c->p), tsl->s, REG_EXTENDED|
 					REG_ICASE|REG_NOSUB))
 				{
 					fprintf(stderr,"Bad pattern: %s\n",
 						tsl->s);
 					return 1;
 				}
 				re_c->pat=tsl->s;
 				tsl2=tsl;
 			}
 			conf[9].sl=NULL;
 		}

 		if(conf[10].sl)
 		{
 			for(tsl=conf[10].sl; tsl; tsl=tsl->n, free(tsl2))
 			{
				if(!re_r)
				{
					new_re_list(re_r);
					if(!re_r)
					{
						fprintf(stderr,
						"unable to get memory: %s\n", 
						strerror(errno));
						return 1;
					}
				}
				else
				{
					new_re_list(tre);
					if(!tre)
					{
						fprintf(stderr, 
						"unable to get memory: %s\n", 
						strerror(errno));
						return 1;
					}
					tre->n=re_r;
					re_r=tre;
				}
 
 				if(regcomp(&(re_r->p), tsl->s, REG_EXTENDED|
 					REG_ICASE|REG_NOSUB))
 				{
 					fprintf(stderr,"Bad pattern: %s\n",
 						tsl->s);
 					return 1;
 				}
 				re_r->pat=tsl->s;
 				tsl2=tsl;
 			}
 			conf[10].sl=NULL;
 		}

		if(conf[11].str)
 		{
			bodylimit=atoi(conf[11].str);
			if(bodylimit<=0)
			{
				fprintf(stderr, "Warning: body_length value"
						"is invalid, ignored\n");
				bodylimit=0;
			}

			/* parse units */
			switch(conf[11].str[strlen(conf[11].str)-1])
			{
				default:
					/* nothing, use bytes */
					break;
				case 'k':
				case 'K':
					bodylimit*=1024;
					break;
				case 'm':
				case 'M':
					bodylimit*=1024*1024;
					break;
			}
 		}

 		if(conf[12].str)
 			pidfile=conf[12].str;

 		if(conf[13].str)
 			subj_tag=conf[13].str;
 	}
	else
		return 1; /* error reading configuration */

	if(access(pidfile, F_OK)!=-1)
	{
		fprintf(stderr, "pidfile '%s' exists, delete it if"
			" the milter is not already running\n", pidfile);
		return 1;
	}

	if(!strncmp(conn, "unix:", 5))
		pipe=conn+5;
	else
		if(!strncmp(conn, "local:", 6))
			pipe=conn+6;

	if(pipe)
		unlink(pipe);

	/* if we're root, drop privileges */
	if(!getuid())
	{
		/* ugly (and portable) setproctitle */
		if(argc>1)
			argv[1]=NULL;

		pw=getpwnam(user);
		if(!pw)
		{
			fprintf(stderr, "getpwnam %s failed: %s\n", user,
				strerror(errno));
			return 1;
		}
                if(setegid(pw->pw_gid) || setgid(pw->pw_gid))
		{
                        fprintf(stderr, "setgid failed: %s\n", strerror(errno));
			return 1;
		}
		if(setuid(pw->pw_uid) || seteuid(pw->pw_uid))
		{
			fprintf(stderr, "setuid failed: %s\n", strerror(errno));
			return 1;
		}
	}

	if(daemon(0, 0))
	{
		fprintf(stderr, "daemon failed: %s\n", strerror(errno));
		unlink(pidfile);
		return 1;
	}

	/* setup time to timezone */
	tzset();

	openlog("bogom", LOG_PID | LOG_NDELAY, LOG_DAEMON);

	pidfile_fd=fopen(pidfile, "w");
	if(!pidfile_fd)
	{
		syslog(LOG_ERR, "unable to open pidfile '%s': %s\n",
			pidfile, strerror(errno));
		return 1;
	}

	if(fprintf(pidfile_fd, "%li\n", (long)getpid())<=0 || 
		fclose(pidfile_fd)!=0)
	{
		syslog(LOG_ERR, "unable to write into pidfile '%s': %s\n", 
			pidfile, strerror(errno));
		unlink(pidfile);
		return 1;
	}

	if(smfi_setconn((char *)conn)==MI_FAILURE)
	{
		syslog(LOG_ERR, "smfi_setconn %s failed\n", conn);
		return 1;
	}

	if(smfi_register(smfilter)!=MI_SUCCESS)
	{
                syslog(LOG_ERR, "smfi_register failed\n");
		return 1;
        }

	syslog(LOG_INFO, "started %s", rcsid);

	result=smfi_main();

	unlink(pidfile);

	return result;
}

/* EOF */

