/* $Id: milter.c,v 1.5 2004/12/31 14:58:58 reidrac Exp reidrac $ */

/*
* bogom, simple sendmail milter to interface bogofilter
* Copyright (C) 2004 Juan J. Martinez <jjm*at*usebox*dot*net> 
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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <syslog.h>
#include <regex.h>

#include "libmilter/mfapi.h"
#include "conf.h"

#define DEF_USER	"bogofilter"
#define DEF_CONN	"unix:/var/spool/bogofilter/milter.sock"
#define DEF_CONF	"/etc/bogom.conf"

struct mlfiPriv
{
	FILE *f;
	char *filename;
	int eom;
};

sfsistat mlfi_connect(SMFICTX *, char *, _SOCK_ADDR *);
sfsistat mlfi_envfrom(SMFICTX *, char **);
sfsistat mlfi_header(SMFICTX *, char *, char *);
sfsistat mlfi_eoh(SMFICTX *);
sfsistat mlfi_body(SMFICTX *, unsigned char *, size_t);
sfsistat mlfi_eom(SMFICTX *);
sfsistat mlfi_close(SMFICTX *);
void mlfi_clean(SMFICTX *);
void usage(const char *);

struct smfiDesc smfilter=
{
	"bogom",	/* filter name */
	SMFI_VERSION,	/* version code -- do not change */
	SMFIF_ADDHDRS,	/* flags -- we add headers only */
	mlfi_connect,	/* connection info filter */
	NULL,		/* SMTP HELO command filter */
	mlfi_envfrom,	/* envelope sender filter */
	NULL,		/* envelope recipient filter */
	mlfi_header,	/* header filter */
	mlfi_eoh,	/* end of header */
	mlfi_body,	/* body block filter */
	mlfi_eom,	/* end of message */
	NULL,		/* message aborted */
	mlfi_close	/* connection cleanup */
};

struct re_list
{
	regex_t p;
	const char *pat;
	struct re_list *n;
};

#define new_re_list(x) \
	x=(struct re_list *) \
		malloc(sizeof(struct re_list));\
	x->n=NULL;

static const char 	rcsid[]="$Id: milter.c,v 1.5 2004/12/31 14:58:58 reidrac Exp reidrac $";

static int		mode=SMFIS_CONTINUE;
static int		train=0;
static int		verbose=0;
static const char 	*bogo="/usr/local/bin/bogofilter";
static const char	*exclude=NULL;

static struct re_list	*re=NULL;

sfsistat 
mlfi_connect(SMFICTX *ctx, char *hostname, _SOCK_ADDR *hostaddr)
{
	struct mlfiPriv *priv;

	priv=(struct mlfiPriv *)malloc(sizeof(struct mlfiPriv));
	if(!priv)
	{
		syslog(LOG_ERR, "Unable to get memory: %s",
			strerror(errno));
		return SMFIS_TEMPFAIL;
	}

	priv->filename=NULL;
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

	for(tre=re; tre; tre=tre->n)
		if(!regexec(&tre->p, argv[0], 0, NULL, 0))
		{
			if(verbose)
				syslog(LOG_INFO, 
					"accepted due pattern match: %s", 
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

	if(exclude)
	{
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

	if(fwrite(bodyp, bodylen, 1, priv->f)!=1)
	{
		syslog(LOG_ERR, "failed to write into %s: %s", 
			priv->filename, strerror(errno));
		mlfi_clean(ctx);
		return SMFIS_TEMPFAIL;
	}

	return SMFIS_CONTINUE;
}

sfsistat
mlfi_eom(SMFICTX *ctx)
{
	struct mlfiPriv *priv;
	int status, pid;
	char bogo_ops[5]="-\0";

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

	mlfi_clean(ctx);

	if(!WIFEXITED(status))
	{
		syslog(LOG_ERR, "bogofilter didn't exit normally");
		return SMFIS_CONTINUE;
	}

	switch(WEXITSTATUS(status))
	{
		case 3:
		case -1:
			syslog(LOG_ERR, "bogofilter reply: I/O error"); 
			return SMFIS_CONTINUE;
		case 0:
			smfi_insheader(ctx, 0, "X-Bogosity",
				"Yes, tests=bogofilter");

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

	return SMFIS_CONTINUE;
}

sfsistat 
mlfi_close(SMFICTX *ctx)
{
	struct mlfiPriv *priv;

	priv=(struct mlfiPriv *)smfi_getpriv(ctx);
	if(!priv)
	{
		syslog(LOG_ERR, "on mlfi_close: smfi_getpriv");
		return SMFIS_CONTINUE;
	}

	if(!priv->eom)
		mlfi_clean(ctx);

	smfi_setpriv(ctx, NULL);
	free(priv);

	return SMFIS_CONTINUE;
}

void 
mlfi_clean(SMFICTX *ctx)
{
	struct mlfiPriv *priv;

	priv=(struct mlfiPriv *)smfi_getpriv(ctx);

	if(!priv)
		return;

	if(priv->f)
	{
		fclose(priv->f);
		priv->f=NULL;
	}

	if(priv->filename)
	{
		unlink(priv->filename);
		free(priv->filename);
		priv->filename=NULL;
	}

	priv->eom=1;

	return;
}

void
usage(const char *argv0)
{
	fprintf(stderr, "usage: %s\t[-R | -D] [-t] [-v] [-u user] [-p pipe]\n"
		"\t\t[-b bogo_path ] [ -x exclude_string ] "
 		"[ -w re_whitelist ]\n\t\t[ -c conf_file ]\n", argv0);

	return;
}

int
main(int argc, char *argv[])
{
	const char *user=DEF_USER;
	const char *conn=DEF_CONN;
	const char *pipe=NULL;
	const char *conffile=DEF_CONF;

	struct re_list *tre;
 	struct string_list *tsl, *tsl2;

 	/* configuration tokens */
 	struct conftoken conf[]=
 	{
 		{ "verbose", REQ_BOOL, NULL, -1 },
 		{ "training", REQ_BOOL, NULL, -1 },
 		{ "user", REQ_QSTRING, NULL, 0 },
 		{ "connection", REQ_QSTRING, NULL, 0 },
 		{ "exclude_string", REQ_QSTRING, NULL, 0 },
 		{ "re_envfrom", REQ_LSTQSTRING, NULL, 0 },
 		{ "bogofilter", REQ_QSTRING, NULL, 0 },
 		{ "policy", REQ_STRING, NULL, 0 },
 		{ NULL, NULL, NULL, 0 }
	};

	int opt;
	const char *opts="hu:p:b:RDtvx:w:c:";

	struct passwd *pw=NULL;

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
				if(!re)
				{
					new_re_list(re);
					if(!re)
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
					tre->n=re;
					re=tre;
				}
 
 				if(regcomp(&(re->p), tsl->s, REG_EXTENDED|
 					REG_ICASE|REG_NOSUB))
 				{
 					fprintf(stderr,"Bad pattern: %s\n",
 						tsl->s);
 					return 1;
 				}
 				re->pat=tsl->s;
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
 	}

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

			case 'p':
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
			case 'w':
				if(!re)
				{
					new_re_list(re);
					if(!re)
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
					tre->n=re;
					re=tre;
				}

				if(regcomp(&(re->p), optarg, REG_EXTENDED|
					REG_ICASE|REG_NOSUB))
				{
					fprintf(stderr,"Bad pattern: %s\n",
						optarg);
					return 1;
				}
				re->pat=optarg;
				break;
			case 'c':
				conffile=optarg;
				break;	
		}

	if(!strncmp(conn, "unix:", 5))
		pipe=conn+5;
	else
		if(!strncmp(conn, "local:", 6))
			pipe=conn+6;

	if(pipe)
		unlink(pipe);

	openlog("bogom", LOG_PID | LOG_NDELAY, LOG_DAEMON);

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
		if(seteuid(pw->pw_uid) || setuid(pw->pw_uid))
		{
			fprintf(stderr, "setuid failed: %s\n", strerror(errno));
			return 1;
		}
	}

	if(smfi_setconn((char *)conn)==MI_FAILURE)
	{
		fprintf(stderr,"smfi_setconn %s failed\n", conn);
		return 1;
	}

	if(smfi_register(smfilter)!=MI_SUCCESS)
	{
                fprintf(stderr, "smfi_register failed\n");
		return 1;
        }

	if(daemon(0, 0))
	{
               	fprintf(stderr, "daemon failed: %s\n", strerror(errno));
		return 1;
	}

	syslog(LOG_INFO, "started %s", rcsid);

	return smfi_main();
}

/* EOF */

