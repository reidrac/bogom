/* $Id$ */

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
#include <sys/stat.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>
#include <pwd.h>
#include <syslog.h>
#include <signal.h>

#include "libmilter/mfapi.h"

#define DEF_USER	"bogofilter"
#define DEF_CONN	"unix:/var/spool/bogofilter/milter.sock"

struct mlfiPriv
{
	FILE *f;
	char *filename;
	int eom;
};

sfsistat mlfi_connect(SMFICTX *, char *, _SOCK_ADDR *);
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
	NULL,		/* envelope sender filter */
	NULL,		/* envelope recipient filter */
	mlfi_header,	/* header filter */
	mlfi_eoh,	/* end of header */
	mlfi_body,	/* body block filter */
	mlfi_eom,	/* end of message */
	NULL,		/* message aborted */
	mlfi_close	/* connection cleanup */
};

static const char 	rcsid[]="$Id$";

static int		mode=SMFIS_CONTINUE;
static int		train=0;
static int		verbose=0;
static const char 	*bogo="/usr/local/bin/bogofilter";

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
	fprintf(stderr, "usage: %s [-R | -D] [-t] [-v] [-u user] [-p pipe] "
		"[-b bogo_path ]\n", argv0);

	return;
}

int
main(int argc, char *argv[])
{
	const char *user=DEF_USER;
	const char *conn=DEF_CONN;
	const char *pipe=NULL;

	int opt;
	const char *opts="hu:p:b:RDtv";

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

