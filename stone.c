/*
 * stone.c	simple repeater
 * Copyright(C)1995-8 by Hiroaki Sengoku <sengoku@gcd.forus.or.jp>
 * Version 1.0	Jan 28, 1995
 * Version 1.1	Jun  7, 1995
 * Version 1.2	Aug 20, 1995
 * Version 1.3	Feb 16, 1996	relay UDP
 * Version 1.5	Nov 15, 1996	for Win32
 * Version 1.6	Jul  5, 1997	for SSL
 * Version 1.7	Aug 20, 1997	return packet of UDP
 * Version 1.8	Oct 18, 1997	pseudo parallel using SIGALRM
 * Version 2.0	Nov  3, 1997	http proxy & over http
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Emacs; see the file COPYING.  If not, write to
 * the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Usage: stone [-d] [-n] [-u <max>] [-f <n>] [-l]
 *              [-z <SSL>] <st> [-- <st>]...
 * <st> := <display> [<xhost>...]
 *        |<host>:<port> <sport> [<xhost>...]
 *        |<host>:<port> <shost>:<sport> [<xhost>...]
 *        |proxy <shost>:<sport> [<xhost>...]
 *        |<host>:<port>/http <request> [<hosts>...]
 *        |<host>:<port>/proxy <header> [<hosts>...]
 * <port>  := <port#>[/udp|/ssl]
 * <sport> := <port#>[/udp|/http|/ssl]
 * <xhost> := <host>[/<mask>]
 *
 *     Any packets received by <display> are passed to DISPLAY
 *     Any packets received by <sport> are passed to <host>:<port>
 *     as long as these packets are sent from <xhost>...
 *     if <xhost> are not given, any hosts are welcome.
 *
 * Make:
 * gcc -o stone stone.c
 * or
 * cl -DWINDOWS stone.c /MT wsock32.lib
 *
 * Using SSLeay
 * gcc -DUSE_SSL -I/usr/local/ssl/include -o stone stone.c \
 *               -L/usr/local/ssl/lib -lssl -lcrypto
 * or
 * cl -DWINDOWS -DUSE_SSL stone.c /MT wsock32.lib ssleay32.lib libeay32.lib
 */
#define VERSION	"2.0"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <ctype.h>
#include <stdarg.h>
#include <signal.h>
typedef void (*FuncPtr)(void*);
#ifdef WINDOWS
#define FD_SETSIZE	256
#include <process.h>
#include <winsock.h>
#include <time.h>
#define NO_SNPRINTF
#define NO_SYSLOG
#define NO_FORK
#define NO_SETHOSTENT
#define NO_ALRM
#define ValidSocket(sd)		((sd) != INVALID_SOCKET)
#undef EINTR
#define EINTR	WSAEINTR
#define bcopy(f,t,n)	memcpy(t,f,n)
#define bzero(b,n)	memset(b,0,n)
#define ASYNC(func,arg)	\
    if (_beginthread((FuncPtr)func,0,arg) < 0) {\
	message(LOG_ERR,"_beginthread error err=%d\n",errno);\
	func(arg);\
    }
#else	/* ! WINDOWS */
#ifdef OS2
#define INCL_DOSSEMAPHORES
#define INCL_DOSERRORS
#include <process.h>
#include <os2.h>
#define NO_ALRM
#define NO_SYSLOG
#define ASYNC(func,arg)	\
    if (_beginthread((FuncPtr)func,NULL,32768,arg) < 0) {\
	message(LOG_ERR,"_beginthread error err=%d\n",errno);\
	func(arg);\
    }
#else	/* ! OS2 */
#define ASYNC(func,arg)	func(arg)
#endif	/* ! WINDOWS */
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
typedef int SOCKET;
#define INVALID_SOCKET		-1
#define ValidSocket(sd)		((sd) >= 0)
#define closesocket(sd)		close(sd)
#endif
#define InvalidSocket(sd)	(!ValidSocket(sd))
#ifdef NO_SYSLOG
#define LOG_CRIT	2	/* critical conditions */
#define LOG_ERR		3	/* error conditions */
#define LOG_WARNING	4	/* warning conditions */
#define LOG_NOTICE	5	/* normal but signification condition */
#define LOG_INFO	6	/* informational */
#define LOG_DEBUG	7	/* debug-level messages */
#else	/* SYSLOG */
#include <syslog.h>
#endif
#ifndef EISCONN
#define EISCONN		56		/* Socket is already connected */
#endif
#ifndef EADDRINUSE
#define EADDRINUSE	48		/* Address already in use */
#endif

#define BACKLOG_MAX	5
#define XPORT		6000
#define BUFMAX		1024
#define STRMAX		30	/* > 16 */
#define NTRY_MAX	10
#define IDLE_MAX	(60 * 10)	/* 10 min */
#define CONN_TIMEOUT	60	/* 1 min */
#ifdef NO_ALRM
#define TICK_SELECT	10000	/* 0.01 sec */
#define SPIN_MAX	1000	/* 10 sec */
#else
#define TICK_SELECT	100000	/* 0.1 sec */
#define SPIN_MAX	10	/* 1 sec */
#define TICK_TIMER	10000	/* 0.01 sec */
#define RECURS_CNT	30	/* 0.3 sec */
#endif

#ifdef USE_SSL
#include <crypto.h>
#include <x509.h>
#include <ssl.h>
#include <err.h>
SSL_CTX *ssl_ctx;
char *keyfile, *certfile;
char ssl_file_path[1024];
int ssl_verbose_flag = 0;
int ssl_verify_flag = SSL_VERIFY_NONE;
char *cipher_list = NULL;
#if SSLEAY_VERSION_NUMBER >= 0x0800
#define SSLEAY8
#endif
#endif

typedef struct {
    struct in_addr addr;
    struct in_addr mask;
} XHost;

typedef struct _Stone {
    SOCKET sd;			/* socket descriptor to listen */
    struct sockaddr_in sin;	/* destination */
    int proto;			/* 2:UDP, 3:First, 4:Proxy */
    char *p;
    struct _Stone *next;
#ifdef USE_SSL
    SSL *ssl;			/* SSL handle */
#endif
    int nhosts;			/* # of hosts */
    XHost xhosts[0];		/* hosts permitted to connect */
} Stone;

typedef struct _Pair {
    struct _Pair *pair;
    struct _Pair *prev;
    struct _Pair *next;
#ifdef USE_SSL
    SSL *ssl;		/* SSL handle */
#endif
    time_t clock;
    SOCKET sd;		/* socket descriptor */
    int proto;		/* 2:UDP, 3:First, 4:Proxy */
    short start;	/* index of buf */
    short len;
    char buf[BUFMAX];
} Pair;

typedef struct _Conn {
    struct sockaddr_in sin;	/* destination */
    Pair *pair;
    int lock;
    struct _Conn *next;
} Conn;

typedef struct _Origin {
    SOCKET sd;			/* peer */
    Stone *stone;
    struct sockaddr_in sin;	/* origin */
    int lock;
    time_t clock;
    struct _Origin *next;
} Origin;

Stone *stones = NULL;
Pair pairs;
Conn conns;
Origin origins;
int OriginMax = 10;
fd_set rin, win, ein;
unsigned int Generation = 0;
int Recursion = 0;
#ifdef H_ERRNO
extern int h_errno;	
#endif

const state_mask =      0x00ff;
const proto_tcp	=       0x0100;	/* transmission control protocol */
const proto_udp =       0x0200;	/* user datagram protocol */
const proto_first_r =   0x0400;	/* first read packet */
const proto_first_w =   0x0800;	/* first written packet */
const proto_ssl_s =     0x1000;	/* SSL source */
const proto_ssl_d =     0x2000;	/*     destination */
const proto_ohttp_s =   0x4000;	/* over http source */
const proto_ohttp_d =   0x8000;	/*           destination */
const proto_source =   0x10000;	/* source flag */
const proto_proxy =    0x20000;	/* http proxy (destination only) */
const proto_ssl_acc =  0x40000;	/* SSL_accept interrupted */
const proto_ihead =    0x80000;	/* insert header (destination only) */
const proto_connect = 0x100000;	/* connection established */
const proto_close =   0x200000;	/* request to close */
const proto_ready_r = 0x400000;	/* ready to read */
const proto_ready_w = 0x800000;	/* ready to write */
#define proto_ssl	(proto_ssl_s|proto_ssl_d)
#define proto_ohttp	(proto_ohttp_s|proto_ohttp_d)
#define proto_src	(proto_tcp|proto_udp|proto_first_r|proto_first_w|\
			 proto_ssl_s|proto_ohttp_s|\
			 proto_source)
#define proto_dest	(proto_tcp|proto_udp|proto_first_r|proto_first_w|\
			 proto_ssl_d|proto_ohttp_d|\
			 proto_proxy|proto_ihead)
#define proto_all	(proto_src|proto_dest)

char *pkt_buf;		/* UDP packet buffer */
int pkt_len_max;	/* size of pkt_buf */
#define PKT_LEN_INI	1024	/* initial size */
int AddrFlag = 0;
#ifndef NO_SYSLOG
int Syslog = 0;
#endif
FILE *LogFp;
#ifndef NO_FORK
int NForks = 0;
pid_t *Pid;
#endif
int Debug = 0;		/* debugging level */
#ifdef WINDOWS
HANDLE PairMutex, ConnMutex, OrigMutex;
#endif
#ifdef OS2
HMTX PairMutex, ConnMutex, OrigMutex;
#endif

#ifdef NO_SNPRINTF
#define vsnprintf(str,len,fmt,ap)	vsprintf(str,fmt,ap)
#define snprintf(str,len,fmt,ap)	sprintf(str,fmt,ap)
#endif

char *strntime(str,len,clock)
char *str;
int len;
time_t *clock;
{
    char *p, *q;
    int i;
    p = ctime(clock);
    q = p + strlen(p);
    while (*p++ != ' ')	;
    while (*--q != ' ')	;
    i = 0;
    len--;
    while (p <= q && i < len) str[i++] = *p++;
    str[i] = '\0';
    return str;
}

void message(int pri, char *fmt, ...) {
    char str[BUFMAX];
    va_list ap;
#ifndef NO_SYSLOG
    if (Syslog) {
	va_start(ap,fmt);
	vsnprintf(str,BUFMAX,fmt,ap);
	va_end(ap);
	if (Recursion) syslog(pri,"(%d) %s",Recursion,str);
	else syslog(pri,"%s",str);
    } else {
#endif
	time_t clock;
	int i;
	time(&clock);
	strntime(str,BUFMAX,&clock);
	i = strlen(str);
#ifndef NO_FORK
	if (NForks) {
	    snprintf(&str[i],BUFMAX-i,"[%d] ",getpid());
	    i = strlen(str);
	}
#endif
	if (Recursion) {
	    snprintf(&str[i],BUFMAX-i,"(%d) ",Recursion);
	    i = strlen(str);
	}
	va_start(ap,fmt);
	vsnprintf(&str[i],BUFMAX-i-2,fmt,ap);
	va_end(ap);
	fprintf(LogFp,"%s\n",str);
#ifndef NO_SYSLOG
    }
#endif
}

char *addr2str(addr)
struct in_addr *addr;
{
    static char str[STRMAX];
    union {
	u_long	l;
	unsigned char	c[4];
    } u;
    struct hostent *ent;
    int ntry = NTRY_MAX;
    u.l = addr->s_addr;
    sprintf(str,"%d.%d.%d.%d",u.c[0],u.c[1],u.c[2],u.c[3]);
    if (!AddrFlag) {
#ifndef NO_SETHOSTENT
	sethostent(1);
#endif
	do {
	    ent = gethostbyaddr((char*)&addr->s_addr,
				sizeof(addr->s_addr),AF_INET);
	    if (ent) return ent->h_name;
	} while (h_errno == TRY_AGAIN && ntry-- > 0);
	message(LOG_ERR,"Unknown address err=%d: %s",h_errno,str);
    }
    return str;
}

char *port2str(port,flag,mask)
int port;	/* network byte order */
int flag;
int mask;
{
    static char str[STRMAX];
    char *proto;
    struct servent *ent;
    if (flag & proto_udp) {
	proto = "udp";
    } else {
	proto = "tcp";
    }
    str[0] = '\0';
    if (!AddrFlag) {
	ent = getservbyport(port,proto);
	if (ent) strncpy(str,ent->s_name,STRMAX-5);
    }
    if (str[0] == '\0') {
	sprintf(str,"%d",ntohs((unsigned short)port));
    }
    if (flag & proto_udp) {
	strcat(str,"/udp");
    } else if (flag & proto_ohttp & mask) {
	strcat(str,"/http");
    } else if (flag & proto_ssl & mask) {
	strcat(str,"/ssl");
    }
    return str;
}

int str2port(str,flag)	/* host byte order */
char *str;
int flag;
{
    struct servent *ent;
    char *proto;
    if (flag & proto_udp) {
	proto = "udp";
    } else {
	proto = "tcp";
    }
    ent = getservbyname(str,proto);
    if (ent) {
	return ntohs(ent->s_port);
    } else {
	return atoi(str);
    }
}

int isdigitaddr(name)
char *name;
{
    while(*name) {
	if (*name != '.' && !isdigit(*name)) return 0;	/* not digit */
	name++;
    }
    return 1;
}

#ifdef INET_ADDR
unsigned long inet_addr(name)	/* inet_addr(3) is too tolerant */
char *name;
{
    unsigned long ret;
    int d[4];
    int i;
    char c;
    if (sscanf(name,"%d.%d.%d.%d%c",&d[0],&d[1],&d[2],&d[3],&c) != 4)
	return -1;
    ret = 0;
    for (i=0; i < 4; i++) {
	if (d[i] < 0 || 255 < d[i]) return -1;
	ret <<= 8;
	ret |= d[i];
    }
    return htonl(ret);
}
#endif

int host2addr(name,addrp,familyp)
char *name;
struct in_addr *addrp;
short *familyp;
{
    struct hostent *hp;
    int ntry = NTRY_MAX;
    if (isdigitaddr(name)) {
	if ((addrp->s_addr=inet_addr(name)) != -1) {
	    if (familyp) *familyp = AF_INET;
	    return 1;
	}
    } else {
#ifndef NO_SETHOSTENT
	sethostent(1);
#endif
	do {
	    hp = gethostbyname(name);
	    if (hp) {
		bcopy(hp->h_addr,(char *)addrp,hp->h_length);
		if (familyp) *familyp = hp->h_addrtype;
		return 1;
	    }
	} while (h_errno == TRY_AGAIN && ntry-- > 0);
    }
    message(LOG_ERR,"Unknown host err=%d: %s",h_errno,name);
    return 0;
}

/* *addrp is permitted to connect to *stonep ? */
int checkXhost(stonep,addrp)
Stone *stonep;
struct in_addr *addrp;
{
    int i;
    if (!stonep->nhosts) return 1; /* any hosts can access */
    for (i=0; i < stonep->nhosts; i++) {
	if ((addrp->s_addr & stonep->xhosts[i].mask.s_addr)
	    == (stonep->xhosts[i].addr.s_addr & stonep->xhosts[i].mask.s_addr))
	    return 1;
    }
    return 0;
}

#ifdef NO_ALRM
#define utimer(usec)	/* */
#else
void utimer(usec)
int usec;
{
    struct itimerval val;
    static struct itimerval oval;
    switch(usec) {
      case -1:	/* resume */
	setitimer(ITIMER_REAL,&oval,NULL);
	break;
      case 0:	/* stop */
	val.it_interval.tv_sec = val.it_interval.tv_usec
	    = val.it_value.tv_sec = val.it_value.tv_usec = 0;
	setitimer(ITIMER_REAL,&val,&oval);
	break;
      default:	/* initialize & start */
	oval.it_interval.tv_sec = oval.it_interval.tv_usec
	    = oval.it_value.tv_sec = oval.it_value.tv_usec = 0;
	val.it_interval.tv_sec = val.it_interval.tv_usec
	    = val.it_value.tv_sec = 0;
	val.it_value.tv_usec = usec;
	setitimer(ITIMER_REAL,&val,NULL);	/* start timer */
    }
}
#endif

#ifdef WINDOWS
void waitMutex(h)
HANDLE h;
{
    DWORD ret;
    if (h) {
	ret = WaitForSingleObject(h,500);	/* 0.5 sec */
	if (ret == WAIT_FAILED) {
	    message(LOG_ERR,"Fail to wait mutex err=%d",GetLastError());
	} else if (ret == WAIT_TIMEOUT) {
	    message(LOG_WARNING,"timeout to wait mutex");
	}
    }
}

void freeMutex(h)
HANDLE h;
{
    if (h) {
	if (!ReleaseMutex(h)) {
	    message(LOG_ERR,"Fail to release mutex err=%d",GetLastError());
	}
    }
}
#else	/* ! WINDOWS */
#ifdef OS2
void waitMutex(h)
HMTX h;
{
    APIRET ret;
    if (h) {
	ret = DosRequestMutexSem(h,500);	/* 0.5 sec */
	if (ret == ERROR_TIMEOUT) {
	    message(LOG_WARNING,"timeout to wait mutex");
	} else if (ret) {
	    message(LOG_ERR,"Fail to request mutex err=%d",ret);
	}
    }
}

void freeMutex(h)
HMTX h;
{
    APIRET ret;
    if (h) {
	ret = DosReleaseMutexSem(h);
	if (ret) {
	    message(LOG_ERR,"Fail to release mutex err=%d",ret);
	}
    }
}
#else	/* ! OS2 & ! WINDOWS */
#define waitMutex(sem)	/* */
#define freeMutex(sem)	/* */
#endif
#endif

/* relay UDP */

void message_origin(origin)
Origin *origin;
{
    struct sockaddr_in name;
    SOCKET sd;
    int len, i;
    char str[BUFMAX];
    strntime(str,BUFMAX,&origin->clock);
    i = strlen(str);
    if (ValidSocket(origin->sd)) {
	len = sizeof(name);
	if (getsockname(origin->sd,(struct sockaddr*)&name,&len) < 0) {
#ifdef WINDOWS
	    errno = WSAGetLastError();
#endif
	    if (Debug > 3)
		message(LOG_DEBUG,"UDP %d: Can't get socket's name err=%d",
			origin->sd,errno);
	} else {
	    strncpy(&str[i],port2str(name.sin_port,proto_udp,0),BUFMAX-i);
	    i = strlen(str);
	    if (i < BUFMAX-2) str[i++] = ' ';
	}
    }
    if (i >= BUFMAX) i = BUFMAX-1;
    str[i] = '\0';
    if (origin->stone) sd = origin->stone->sd;
    else sd = INVALID_SOCKET;
    message(LOG_INFO,"UDP%3d:%3d %s%s:%s",
	    origin->sd,sd,str,
	    addr2str(&origin->sin.sin_addr),
	    port2str(&origin->sin.sin_port,proto_udp,proto_all));
}

/* enlarge packet buffer */
static void enlarge_buf(sd)
SOCKET sd;
{
    char *buf;
    buf = malloc(pkt_len_max << 1);
    if (buf) {
	pkt_len_max = (pkt_len_max << 1);
	free(pkt_buf);
	pkt_buf = buf;
	message(LOG_INFO,"UDP %d: Packet buffer is enlarged: %d bytes",
		sd,pkt_len_max);
    }
}

static int recvUDP(sd,from)
SOCKET sd;
struct sockaddr_in *from;
{
    struct sockaddr_in sin;
    int len, pkt_len;
    if (!from) from = &sin;
    len = sizeof(*from);
    pkt_len = recvfrom(sd,pkt_buf,pkt_len_max,0,
		       (struct sockaddr*)from,&len);
    if (Debug > 4) message(LOG_DEBUG,"UDP %d: %d bytes received from %s:%s",
			   sd,pkt_len,
			   addr2str(&from->sin_addr),
			   port2str(from->sin_port,proto_udp,proto_all));
    if (pkt_len > pkt_len_max) {
	message(LOG_NOTICE,"UDP %d: recvfrom failed: larger packet (%d bytes) "
		"arrived from %s:%s",
		sd,pkt_len,
		addr2str(&from->sin_addr),
		port2str(from->sin_port,proto_udp,0));
	enlarge_buf(sd);
	pkt_len = 0;		/* drop */
    }
    return pkt_len;
}   

static int sendUDP(sd,sinp,len)
SOCKET sd;
struct sockaddr_in *sinp;
int len;
{
    if (sendto(sd,pkt_buf,len,0,
	       (struct sockaddr*)sinp,sizeof(*sinp))
	!= len) {
#ifdef WINDOWS
	errno = WSAGetLastError();
#endif
	message(LOG_ERR,"UDP %d: sendto failed err=%d: to %s:%s",
		sd,errno,
		addr2str(&sinp->sin_addr),
		port2str(sinp->sin_port,proto_udp,0));
	return -1;
    }
    if (Debug > 4)
	message(LOG_DEBUG,"UDP %d: %d bytes sent to %s:%s",
		sd,len,
		addr2str(&sinp->sin_addr),
		port2str(sinp->sin_port,proto_udp,0));
    return len;
}

static Origin *getOrigins(addr,port)
struct in_addr *addr;
int port;	/* network byte order */
{
    Origin *origin;
    for (origin=origins.next; origin != NULL; origin=origin->next) {
	if (InvalidSocket(origin->sd)) continue;
	if (origin->sin.sin_addr.s_addr == addr->s_addr
	    && origin->sin.sin_port == port) {
	    origin->lock = 1;	/* lock origin */
	    return origin;
	}
    }
    return NULL;
}

void docloseUDP(origin)
Origin *origin;
{
    if (Debug > 2) message(LOG_DEBUG,"UDP %d: close",origin->sd);
    if (ValidSocket(origin->sd)) {
	FD_CLR(origin->sd,&rin);
	FD_CLR(origin->sd,&ein);
    }
    origin->lock = -1;	/* request to close */
}

void asyncOrg(origin)
Origin *origin;
{
    int len;
    utimer(TICK_TIMER);
    len = recvUDP(origin->sd,NULL);
    if (Debug > 4)
	message(LOG_DEBUG,"UDP %d: send %d bytes to %d",
		origin->sd,len,origin->stone->sd);
    if (len > 0) sendUDP(origin->stone->sd,&origin->sin,len);
    utimer(0);
    time(&origin->clock);
    if (len > 0) {
	FD_SET(origin->sd,&ein);
	FD_SET(origin->sd,&rin);
    } else if (len < 0) {
	docloseUDP(origin);
    }
}

int scanUDP(rop,eop)
fd_set *rop, *eop;
{
    Origin *origin, *prev, *old;
    int n = 0;
    unsigned int g = Generation;
    prev = &origins;
    for (origin=origins.next; origin != NULL;
	 prev=origin, origin=origin->next) {
	if (InvalidSocket(origin->sd) || origin->lock > 0) {
	    old = origin;
	    waitMutex(OrigMutex);
	    if (prev->next == origin) {
		origin = prev;
		origin->next = old->next;	/* remove `old' from list */
		if (InvalidSocket(old->sd)) {
		    free(old);
		} else {
		    old->lock = 0;
		    old->next = origins.next;	/* insert old on top */
		    origins.next = old;
		}
	    }
	    freeMutex(OrigMutex);
	    goto next;
	}
	if (origin->lock < 0) {
	    if (!FD_ISSET(origin->sd,&rin) &&
		!FD_ISSET(origin->sd,&ein)) {
		closesocket(origin->sd);
		origin->sd = INVALID_SOCKET;
	    } else {
		FD_CLR(origin->sd,&rin);
		FD_CLR(origin->sd,&ein);
	    }
	    goto next;
	}
	if (FD_ISSET(origin->sd,eop)) {
	    message(LOG_ERR,"UDP %d: exception",origin->sd);
	    message_origin(origin);
	    docloseUDP(origin);
	} else if (FD_ISSET(origin->sd,rop)) {
	    FD_CLR(origin->sd,&ein);
	    FD_CLR(origin->sd,&rin);
	    ASYNC(asyncOrg,origin);
	} else {
	    if (++n >= OriginMax) docloseUDP(origin);
	}
      next:
	if (g != Generation) return 0;
    }
    return 1;
}

/* *stonep repeat UDP connection */
Origin *doUDP(stonep)
Stone *stonep;
{
    struct sockaddr_in from;
    SOCKET dsd;
    int len;
    Origin *origin;
    if ((len=recvUDP(stonep->sd,&from)) <= 0) return NULL;	/* drop */
    if (!checkXhost(stonep,&from.sin_addr)) {
	message(LOG_WARNING,"stone %d: recv UDP denied: from %s:%s",
		stonep->sd,
		addr2str(&from.sin_addr),
		port2str(from.sin_port,stonep->proto,proto_src));
	return NULL;
    }
    origin = getOrigins(&from.sin_addr,from.sin_port);
    if (origin) {
	dsd = origin->sd;
	if (Debug > 5)
	    message(LOG_DEBUG,"UDP %d: reuse %d to send",stonep->sd,dsd);
    } else if (InvalidSocket(dsd=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP))) {
#ifdef WINDOWS
	errno = WSAGetLastError();
#endif
	message(LOG_ERR,"UDP: can't create datagram socket err=%d.",
		errno);
	return NULL;
    }
    if (Debug > 4)
	message(LOG_DEBUG,"UDP %d: send %d bytes to %d",stonep->sd,len,dsd);
    if (sendUDP(dsd,&stonep->sin,len) <= 0) {
	if (origin) docloseUDP(origin);
	else closesocket(dsd);
	return NULL;
    }
    if (!origin) {
	origin = malloc(sizeof(Origin));
	if (!origin) {
	    message(LOG_ERR,"UDP %d: Out of memory, closing socket",dsd);
	    return NULL;
	}
	origin->sd = dsd;
	origin->stone = stonep;
	bcopy(&from,&origin->sin,sizeof(origin->sin));
	origin->lock = 0;
	waitMutex(OrigMutex);
	origin->next = origins.next;	/* insert origin */
	origins.next = origin;
	freeMutex(OrigMutex);
    }
    return origin;
}

void asyncUDP(stone)
Stone *stone;
{
    Origin *origin;
    utimer(TICK_TIMER);
    origin = doUDP(stone);
    utimer(0);
    if (origin) {
	time(&origin->clock);
	FD_SET(origin->sd,&rin);
	FD_SET(origin->sd,&ein);
    }
}

/* relay TCP */

void message_pair(pair)
Pair *pair;
{
    struct sockaddr_in name;
    SOCKET sd;
    int len, i;
    char str[BUFMAX];
    strntime(str,BUFMAX,&pair->clock);
    i = strlen(str);
    if (ValidSocket(pair->sd)) {
	len = sizeof(name);
	if (getsockname(pair->sd,(struct sockaddr*)&name,&len) < 0) {
#ifdef WINDOWS
	    errno = WSAGetLastError();
#endif
	    if (Debug > 3)
		message(LOG_DEBUG,"TCP %d: Can't get socket's name err=%d",
			pair->sd,errno);
	} else {
	    strncpy(&str[i],port2str(name.sin_port,pair->proto,0),BUFMAX-i);
	    i = strlen(str);
	    if (i < BUFMAX-2) str[i++] = ' ';
	}
	len = sizeof(name);
	if (getpeername(pair->sd,(struct sockaddr*)&name,&len) < 0) {
#ifdef WINDOWS
	    errno = WSAGetLastError();
#endif
	    if (Debug > 3)
		message(LOG_DEBUG,"TCP %d: Can't get peer's name err=%d",
			pair->sd,errno);
	} else {
	    strncpy(&str[i],addr2str(&name.sin_addr),BUFMAX-i);
	    i = strlen(str);
	    if (i < BUFMAX-2) str[i++] = ':';
	    strncpy(&str[i],port2str(name.sin_port,pair->proto,proto_all),
		    BUFMAX-i);
	    i = strlen(str);
	}
    }
    if (i >= BUFMAX) i = BUFMAX-1;
    str[i] = '\0';
    if (pair->pair) sd = pair->pair->sd;
    else sd = INVALID_SOCKET;
    message(LOG_INFO,"TCP%3d:%3d %08x %s",pair->sd,sd,pair->proto,str);
}

#ifdef USE_SSL
static void printSSLinfo(ssl)
SSL *ssl;
{
    X509 *peer;
    char *p = SSL_get_cipher(ssl);
    if (p == NULL) p = "<NULL>";
    message(LOG_INFO,"[SSL cipher=%s]",p);
    peer = SSL_get_peer_certificate(ssl);
    if (peer) {
#ifdef SSLEAY8
	p = X509_NAME_oneline(X509_get_subject_name(peer),NULL,0);
#else
	p = X509_NAME_oneline(X509_get_subject_name(peer));
#endif
	if (p) message(LOG_INFO,"[SSL subject=%s]",p);
	free(p);
#ifdef SSLEAY8
	p = X509_NAME_oneline(X509_get_issuer_name(peer),NULL,0);
#else
	p = X509_NAME_oneline(X509_get_issuer_name(peer));
#endif
	if (p) message(LOG_INFO,"[SSL issuer=%s]",p);
	free(p);
	X509_free(peer);
    }
}

int trySSL_accept(pair)
Pair *pair;
{
    int ret;
    unsigned long err;
#ifdef SSLEAY8
    if (pair->proto & proto_ssl_acc) {
	if (SSL_want_nothing(pair->ssl)) {
	    pair->proto &= ~proto_ssl_acc;
	    return 1;
	}
    }
#endif
    ret = SSL_accept(pair->ssl);
#ifdef SSLEAY8
    if (Debug > 4)
	message(LOG_DEBUG,"TCP %d: SSL_accept ret=%d, state=%x, "
		"finished=%x, in_init=%x/%x",
		pair->sd,ret,
		SSL_state(pair->ssl),
		SSL_is_init_finished(pair->ssl),
		SSL_in_init(pair->ssl),
		SSL_in_accept_init(pair->ssl));
#endif
    if (ret < 0) {
	err = ERR_get_error();
	if (err) {
	    message(LOG_ERR,"TCP %d: SSL_accept error err=%d",pair->sd,err);
	    if (ssl_verbose_flag)
		message(LOG_INFO,"TCP %d: %s",
			pair->sd,ERR_error_string(err,NULL));
	    message_pair(pair);
	    SSL_free(pair->ssl);
	    pair->ssl = NULL;
	    return -1;
	}
	if (Debug > 4)
	    message(LOG_DEBUG,"TCP %d: SSL_accept interrupted",pair->sd);
	pair->proto |= proto_ssl_acc;
	return 0;	/* EINTR */
    }
#ifdef SSLEAY8
    if (SSL_in_accept_init(pair->ssl)) {
	message(LOG_NOTICE,"TCP %d: SSL_accept unexpected EOF",pair->sd);
	message_pair(pair);
	return -1;	/* unexpected EOF */
    }
#endif
    pair->proto &= ~proto_ssl_acc;
    pair->proto |= proto_connect;
    return 1;
}

int doSSL_accept(pair)
Pair *pair;
{
    int ret;
    pair->ssl = SSL_new(ssl_ctx);
    SSL_set_fd(pair->ssl,pair->sd);
    if (!SSL_use_RSAPrivateKey_file(pair->ssl,keyfile,X509_FILETYPE_PEM)) {
	message(LOG_ERR,"SSL_use_RSAPrivateKey_file(%s) error",keyfile);
	if (ssl_verbose_flag)
	    message(LOG_INFO,"%s",ERR_error_string(ERR_get_error(),NULL));
	SSL_free(pair->ssl);
	pair->ssl = NULL;
	return -1;
    }
    if (!SSL_use_certificate_file(pair->ssl,certfile,X509_FILETYPE_PEM)) {
	message(LOG_ERR,"SSL_use_certificate_file(%s) error",certfile);
	if (ssl_verbose_flag)
	    message(LOG_INFO,"%s",ERR_error_string(ERR_get_error(),NULL));
	SSL_free(pair->ssl);
	pair->ssl = NULL;
	return -1;
    }
    if (cipher_list) SSL_set_cipher_list(pair->ssl,cipher_list);
    SSL_set_verify(pair->ssl,ssl_verify_flag,NULL);
    ret = trySSL_accept(pair);
    return ret;
}

int doSSL_connect(pair)
Pair *pair;
{
    unsigned long err;
    if (!(pair->proto & state_mask)) {
	pair->ssl = SSL_new(ssl_ctx);
	SSL_set_fd(pair->ssl,pair->sd);
	if (cipher_list) SSL_set_cipher_list(pair->ssl,cipher_list);	    
	SSL_set_verify(pair->ssl,ssl_verify_flag,NULL);
    }
#ifdef SSLEAY8
    else {
	if (SSL_want_nothing(pair->ssl)) {
	    pair->proto |= proto_connect;
	    return 1;
	}
    }
#endif
    if (SSL_connect(pair->ssl) < 0) {
	err = ERR_get_error();
	if (err) {
	    message(LOG_ERR,"TCP %d: SSL_connect error err=%d",pair->sd,err);
	    if (ssl_verbose_flag)
		message(LOG_INFO,"TCP %d: %s",
			pair->sd,ERR_error_string(err,NULL));
	    message_pair(pair);
	    SSL_free(pair->ssl);
	    pair->ssl = NULL;
	    return -1;
	}
	if (Debug > 4)
	    message(LOG_DEBUG,"TCP %d: SSL_connect interrupted",pair->sd);
	return 0;	/* EINTR */
    }
    return 1;
}
#endif	/* USE_SSL */

/* close pair */
void doclose(pair)
Pair *pair;
{
    if (pair == NULL) return;
    if (pair->pair != NULL) {
	pair->pair->pair = NULL;
	if (ValidSocket(pair->pair->sd) &&
	    !(pair->pair->proto & proto_close)) {
	    if (pair->pair->proto & proto_connect) {
		if (Debug > 2) message(LOG_DEBUG,"TCP %d: shutdown %d",
				       pair->sd,pair->pair->sd);
		shutdown(pair->pair->sd,2);
	    } else {	/* not yet connected */
		pair->pair->proto |= proto_close;	/* request to close */
#ifdef USE_SSL
		if (pair->pair->ssl) {
		    SSL_free(pair->pair->ssl);
		    pair->pair->ssl = NULL;
		}
#endif
	    }
	}
	pair->pair = NULL;
    }
#ifdef USE_SSL
    if (pair->ssl) {
	SSL_free(pair->ssl);
	pair->ssl = NULL;
    }
#endif
    if (ValidSocket(pair->sd) && !(pair->proto & proto_close)) {
	if (Debug > 2)
	    message(LOG_DEBUG,"TCP %d: close",pair->sd);
	FD_CLR(pair->sd,&rin);
	FD_CLR(pair->sd,&win);
	FD_CLR(pair->sd,&ein);
	pair->proto |= proto_close;	/* request to close */
    }
}

/* pair connect to destination */
int doconnect(pair,sinp)
Pair *pair;
struct sockaddr_in *sinp;	/* connect to */
{
    int ret;
    if (!(pair->proto & state_mask)) {
	if (connect(pair->sd,(struct sockaddr*)sinp,
		    sizeof(*sinp)) < 0) {
#ifdef WINDOWS
	    errno = WSAGetLastError();
#endif
	    if (errno == EINTR) {
		if (Debug > 4)
		    message(LOG_DEBUG,"TCP %d: connect interrupted",pair->sd);
		return 0;
	    } else if (errno == EISCONN || errno == EADDRINUSE) {
		if (Debug > 4) {	/* SunOS's bug ? */
		    message(LOG_INFO,"TCP %d: connect bug err=%d",
			    pair->sd,errno);
		    message_pair(pair);
		}
	    } else {
		message(LOG_ERR,"TCP %d: can't connect err=%d: to %s:%s",
			pair->sd,
			errno,
			addr2str(&sinp->sin_addr),
			port2str(sinp->sin_port,pair->proto,proto_all));
		return -1;
	    }
	}
	if (Debug > 2)
	    message(LOG_DEBUG,"TCP %d: established to %d",
		    pair->pair->sd,pair->sd);
    }
    ret = 1;
#ifdef USE_SSL
    if (pair->proto & proto_ssl) {
	ret = doSSL_connect(pair);
	if (ret == 0) {	/* EINTR */
	    pair->proto = ((pair->proto & ~state_mask) | 1);
	} else if (ret > 0) {
	    pair->proto &= ~state_mask;
	}
    }
#endif
    if (ret > 0) pair->proto |= proto_connect;
    return ret;
}

void message_conn(conn)
Conn *conn;
{
    SOCKET sd = INVALID_SOCKET;
    int proto = 0;
    int i = 0;
    char str[BUFMAX];
    if (conn->pair) {
	strntime(str,BUFMAX,&conn->pair->clock);
	i = strlen(str);
	proto = conn->pair->proto;
	if (conn->pair->pair) sd = conn->pair->pair->sd;
    }
    strncpy(&str[i],addr2str(&conn->sin.sin_addr),BUFMAX-i);
    i = strlen(str);
    if (i < BUFMAX-2) str[i++] = ':';
    strncpy(&str[i],port2str(conn->sin.sin_port,proto,proto_all),BUFMAX-i);
    i = strlen(str);
    if (i >= BUFMAX) i = BUFMAX-1;
    str[i] = '\0';
    message(LOG_INFO,"Conn %d: %08x %s",sd,proto,str);
}

/* request pair to connect to destination */
int reqconn(pair,sinp)
Pair *pair;
struct sockaddr_in *sinp;	/* connect to */
{
    Conn *conn;
    if (pair->proto & proto_proxy) {
	FD_SET(pair->pair->sd,&rin);	/* must read request header */
	return 0;
    }
    conn = malloc(sizeof(Conn));
    if (!conn) {
	message(LOG_ERR,"TCP %d: out of memory",pair->pair->sd);
	return -1;
    }
    time(&pair->clock);
    conn->pair = pair;
    conn->sin = *sinp;
    conn->lock = 0;
    waitMutex(ConnMutex);
    conn->next = conns.next;
    conns.next = conn;
    freeMutex(ConnMutex);
    return 0;
}

void asyncConn(conn)
Conn *conn;
{
    int ret;
    time_t clock;
    time(&clock);
    utimer(TICK_TIMER);
#ifdef USE_SSL
    if (conn->pair->pair->proto & proto_ssl_acc)
	ret = trySSL_accept(conn->pair->pair);	/* accept not completed */
    else ret = 1;
    if (ret > 0)
#endif
	ret = doconnect(conn->pair,&conn->sin);
    utimer(0);
    if (ret == 0) {	/* EINTR */
	if (clock - conn->pair->clock < CONN_TIMEOUT) {
	    conn->lock = 0;	/* unlock conn */
	    return;
	}
	message(LOG_ERR,"TCP %d: connect timeout to %s:%s",
		conn->pair->pair->sd,
		addr2str(&conn->sin.sin_addr),
		port2str(conn->sin.sin_port,conn->pair->proto,proto_all));
	ret = -1;
    }
    if (ret < 0) {	/* fail to connect */
	doclose(conn->pair->pair);
	doclose(conn->pair);
    } else {	/* success to connect */
	if (conn->pair->len > 0) {
	    FD_SET(conn->pair->sd,&win);
	} else {
	    FD_SET(conn->pair->pair->sd,&rin);
	}
	if (!(conn->pair->pair->proto & proto_ohttp))
	    FD_SET(conn->pair->sd,&rin);
	FD_SET(conn->pair->pair->sd,&ein);
	FD_SET(conn->pair->sd,&ein);
    }
    conn->pair = NULL;
    conn->lock = -1;
}

/* scan conn request */
int scanConns() {
    Conn *conn, *pconn;
    unsigned int g = Generation;
    pconn = &conns;
    for (conn=conns.next; conn != NULL; conn=conn->next) {
	if (conn->pair == NULL ||
	    conn->pair->pair == NULL ||
	    (conn->pair->proto & proto_close) ||
	    (conn->pair->pair->proto & proto_close)) {
	    waitMutex(ConnMutex);
	    if (pconn->next == conn) {
		pconn->next = conn->next;	/* remove conn */
		free(conn);
		conn = pconn;
	    }
	    freeMutex(ConnMutex);
	} else if (conn->lock == 0) {
	    conn->lock = 1;		/* lock conn */
	    if (Debug > 4) message_conn(conn);
	    ASYNC(asyncConn,conn);
	}
	pconn = conn;
	if (g != Generation) return 0;
    }
    return 1;
}

/* *stonep accept connection */
Pair *doaccept(stonep)
Stone *stonep;
{
    struct sockaddr_in from;
    SOCKET nsd;
    int len;
    Pair *pair1, *pair2;
    int ret;
    nsd = INVALID_SOCKET;
    pair1 = pair2 = NULL;
    len = sizeof(from);
    nsd = accept(stonep->sd,(struct sockaddr*)&from,&len);
    if (InvalidSocket(nsd)) {
#ifdef WINDOWS
	errno = WSAGetLastError();
#endif
	if (errno == EINTR) {
	    if (Debug > 4)
		message(LOG_DEBUG,"stone %d: accept interrupted",stonep->sd);
	    return NULL;
	}
	message(LOG_ERR,"stone %d: accept error err=%d.",stonep->sd,errno);
	return NULL;
    }
    if (!checkXhost(stonep,&from.sin_addr)) {
	message(LOG_WARNING,"stone %d: access denied: from %s:%s",
		stonep->sd,
		addr2str(&from.sin_addr),
		port2str(from.sin_port,stonep->proto,proto_src));
	closesocket(nsd);
	return NULL;
    }
    if (Debug > 1) {
	message(LOG_DEBUG,"stone %d: accepted TCP %d from %s:%s",
		stonep->sd,
		nsd,
		addr2str(&from.sin_addr),
		port2str(from.sin_port,stonep->proto,proto_src));
    }
    pair1 = malloc(sizeof(Pair));
    pair2 = malloc(sizeof(Pair));
    if (!pair1 || !pair2) {
	message(LOG_ERR,"stone %d: out of memory, closing TCP %d",
		stonep->sd,nsd);
      error:
	closesocket(nsd);
	if (pair1) free(pair1);
	if (pair2) free(pair2);
	return NULL;
    }
    pair1->sd = nsd;
    pair1->proto = ((stonep->proto & proto_src) |
		    proto_first_r | proto_first_w | proto_source);
    pair1->start = 0;
    time(&pair1->clock);
    pair1->pair = pair2;
    pair2->sd = socket(PF_INET,SOCK_STREAM,0);
    if (InvalidSocket(pair2->sd)) {
#ifdef WINDOWS
	errno = WSAGetLastError();
#endif
	message(LOG_ERR,"TCP %d: can't create socket err=%d.",pair1->sd,errno);
	goto error;
    }
    pair2->proto = ((stonep->proto & proto_dest) |
		    proto_first_r | proto_first_w);
    pair2->start = 0;
    time(&pair2->clock);
    pair2->pair = pair1;
    pair1->len = pair2->len = 0;
    ret = 1;
#ifdef USE_SSL
    pair1->ssl = pair2->ssl = NULL;
    if (stonep->proto & proto_ssl_s) {
	ret = doSSL_accept(pair1);
	if (ret < 0) {
	    closesocket(nsd);
	    free(pair1);
	    free(pair2);
	    return NULL;
	}
    }
#endif
    if (ret > 0) pair1->proto |= proto_connect;
    return pair1;
}

void asyncAccept(stone)
Stone *stone;
{
    Pair *pair;
    utimer(TICK_TIMER);
    pair = doaccept(stone);
    utimer(0);
    if (pair == NULL) return;
    if (reqconn(pair->pair,&stone->sin) < 0) {
	if (ValidSocket(pair->pair->sd)) closesocket(pair->pair->sd);
	if (ValidSocket(pair->sd)) closesocket(pair->sd);
	doclose(pair->pair);
	free(pair->pair);
	doclose(pair);
	free(pair);
	return;
    }
    pair->next = pair->pair;	/* link pair each other */
    pair->pair->prev = pair;
    waitMutex(PairMutex);
    pair->pair->next = pairs.next;	/* insert pair */
    if (pairs.next != NULL) pairs.next->prev = pair->pair;
    pair->prev = &pairs;
    pairs.next = pair;
    freeMutex(PairMutex);
    if (Debug > 4) {
	message(LOG_DEBUG,"TCP %d: pair %d inserted",pair->sd,pair->pair->sd);
	message_pair(pair);
    }
    if (pair->pair->proto & proto_ihead) {
	sprintf(pair->pair->buf,"%s\r%c",stone->p,'\n');
	pair->pair->start = strlen(pair->pair->buf);
    }
    if (pair->pair->proto & proto_ohttp) {
	sprintf(pair->pair->buf,
		"%s\r%c"
		"\r%c",
		stone->p,'\n','\n');
	pair->pair->len = strlen(pair->pair->buf);
    }
}

/* scan close request */
int scanClose() {
    Pair *pair, *old;
    for (pair=pairs.next; pair != NULL; pair=pair->next) {
	if (InvalidSocket(pair->sd)) {
	    old = pair;
	    waitMutex(PairMutex);
	    pair = pair->prev;
	    pair->next = old->next;	/* remove `old' from list */
	    if (pair->next != NULL) pair->next->prev = pair;
	    if (old->pair != NULL) old->pair->pair = NULL;
	    freeMutex(PairMutex);
	    free(old);
	} else if (pair->proto & proto_close) {
	    if (!FD_ISSET(pair->sd,&rin) &&
		!FD_ISSET(pair->sd,&win) &&
		!FD_ISSET(pair->sd,&ein)) {
		closesocket(pair->sd);
		pair->sd = INVALID_SOCKET;
	    } else {
		FD_CLR(pair->sd,&rin);
		FD_CLR(pair->sd,&win);
		FD_CLR(pair->sd,&ein);
	    }
	}
    }
    return 1;
}

void message_buf(pair,len,str)	/* dump for debug */
Pair *pair;
int len;
char *str;
{
    int i, j, k, l;
    char buf[BUFMAX];
    k = 0;
    for (i=pair->start; i < pair->start+len; i += j) {
	l = 0;
	buf[l++] = ' ';
	for (j=0; k <= j/10 && i+j < pair->start+len && l < BUFMAX-10;
	     j++) {
	    if (' ' <= pair->buf[i+j]
		&& pair->buf[i+j] <= '~')
		buf[l++] = pair->buf[i+j];
	    else {
		sprintf(&buf[l],"<%02x>",pair->buf[i+j]);
		l += strlen(&buf[l]);
		if (pair->buf[i+j] == '\n') {
		    k = 0;
		    j++;
		    break;
		}
		if (pair->buf[i+j] != '\t' && pair->buf[i+j] != '\r' &&
		    pair->buf[i+j] != '\033')
		    k++;
	    }
	}
	if (k > j/10) {
	    j = l = 0;
	    for (j=0; j < 16 && i+j < pair->start+len; j++) {
		if (' ' <= pair->buf[i+j]
		    && pair->buf[i+j] <= '~')
		    sprintf(&buf[l]," %c ",pair->buf[i+j]);
		else {
		    sprintf(&buf[l]," %02x",
			    (unsigned char)pair->buf[i+j]);
		    if (pair->buf[i+j] == '\n') k = 0; else k++;
		}
		l += strlen(&buf[l]);
	    }
	}
	buf[l] = '\0';
	if (pair->proto & proto_source) {
	    message(LOG_DEBUG,"%s%d<%d%s",str,pair->sd,pair->pair->sd,buf);
	} else {
	    message(LOG_DEBUG,"%s%d>%d%s",str,pair->pair->sd,pair->sd,buf);
	}
    }
}

int dowrite(pair)	/* write from buf from pair->start */
Pair *pair;
{
    int len;
    if (Debug > 5) message(LOG_DEBUG,"TCP %d: write ...",pair->sd);
#ifdef USE_SSL
    if (pair->ssl) {
	len = SSL_write(pair->ssl,&pair->buf[pair->start],pair->len);
	if (len < 0) {
	    unsigned long err;
	    err = ERR_get_error();
	    if (!err) {
		if (Debug > 4)
		    message(LOG_DEBUG,"TCP %d: SSL_write interrupted",
			    pair->sd);
		return 0;	/* EINTR */
	    }
	    message(LOG_ERR,"TCP %d: SSL_write error err=%d, closing",
		    pair->sd,err);
	    message_pair(pair);
	    return len;	/* error */
	}
	if (ssl_verbose_flag &&
	    (pair->proto & proto_first_r) &&
	    (pair->proto & proto_first_w)) printSSLinfo(pair->ssl);
    } else {
#endif
	len = send(pair->sd,&pair->buf[pair->start],pair->len,0);
	if (len < 0) {
#ifdef WINDOWS
	    errno = WSAGetLastError();
#endif
	    if (errno == EINTR) {
		if (Debug > 4)
		    message(LOG_DEBUG,"TCP %d: write interrupted",pair->sd);
		return 0;
	    }
	    message(LOG_ERR,"TCP %d: write error err=%d, closing",
		    pair->sd,errno);
	    message_pair(pair);
	    return len;	/* error */
	}
#ifdef USE_SSL
    }
#endif
    if (Debug > 4) message(LOG_DEBUG,"TCP %d: %d bytes written",pair->sd,len);
    if (Debug > 7 || ((pair->proto & proto_first_w) && Debug > 3))
	message_buf(pair,len,"");
    time(&pair->clock);
    if (pair->len <= len) {
	pair->start = 0;
    } else {
	pair->start += len;
	message(LOG_NOTICE,
		"TCP %d: write %d bytes, but only %d bytes written",
		pair->sd,pair->len,len);
	message_pair(pair);
    }
    pair->len -= len;
    return len;
}

int doread(pair)	/* read into buf from pair->pair->start */
Pair *pair;
{
    int len;
    char buf[BUFMAX];
    if (Debug > 5) message(LOG_DEBUG,"TCP %d: read ...",pair->sd);
    if (pair->pair == NULL) {	/* no pair, no more read */
#ifdef USE_SSL
	if (pair->ssl)
	    len = SSL_read(pair->ssl,buf,BUFMAX);
	else
#endif
	    len = recv(pair->sd,buf,BUFMAX,0);
	if (Debug > 4) message(LOG_DEBUG,"TCP %d: read %d bytes",pair->sd,len);
	if (len == 0) return -1;	/* EOF */
	if (len > 0) {
	    message(LOG_ERR,"TCP %d: no pair, closing",pair->sd);
	    message_pair(pair);
	    len = -1;
	}
	return len;
    }
#ifdef USE_SSL
    if (pair->ssl) {
	len = SSL_read(pair->ssl,&pair->pair->buf[pair->pair->start],
		       BUFMAX - pair->pair->start);
	if (len < 0) {
	    unsigned long err;
	    err = ERR_get_error();
	    if (!err) {
		if (Debug > 4)
		    message(LOG_DEBUG,"TCP %d: SSL_read interrupted",pair->sd);
		return 0;	/* EINTR */
	    }
	    message(LOG_ERR,"TCP %d: SSL_read error err=%d, closing",
		    pair->sd,err);
	    message_pair(pair);
	    return len;	/* error */
	}
	if (ssl_verbose_flag &&
	    (pair->proto & proto_first_r) &&
	    (pair->proto & proto_first_w)) printSSLinfo(pair->ssl);
    } else {
#endif
	len = recv(pair->sd,&pair->pair->buf[pair->pair->start],
		   BUFMAX - pair->pair->start,0);
	if (len < 0) {
#ifdef WINDOWS
	    errno = WSAGetLastError();
#endif
	    if (errno == EINTR) {
		if (Debug > 4)
		    message(LOG_DEBUG,"TCP %d: read interrupted",pair->sd);
		return 0;	/* EINTR */
	    }
	    message(LOG_ERR,"TCP %d: read error err=%d, closing",
		    pair->sd,errno);
	    message_pair(pair);
	    return len;	/* error */
	}
#ifdef USE_SSL
    }
#endif
    if (len == 0) return -1;	/* EOF */
    pair->pair->len = len;
    if (Debug > 4)
	message(LOG_DEBUG,"TCP %d: read %d bytes to %d",
		pair->sd,pair->pair->len,pair->pair->sd);
    time(&pair->clock);
    return pair->pair->len;
}

/* http */

#define PROTO_LEN_MAX	10
#define HOST_LEN_MAX	256
char *parseHost(name,host,portp)
char *name;
char *host;
int *portp;	/* host byte order */
{
    char *p = name;
    char buf[PROTO_LEN_MAX];
    int i;
    for (i=0; i < HOST_LEN_MAX-1; i++) {
	if (p[i] == '/' || p[i] == ':' || p[i] == ' ' || p[i] == '\n') break;
	host[i] = p[i];
    }
    host[i] = '\0';
    p = &p[i];
    if (*p == ':') {
	p++;
	for (i=0; i < PROTO_LEN_MAX-1; i++) {
	    if (p[i] == '/' || p[i] == ' ' || p[i] == '\n') break;
	    buf[i] = p[i];
	}
	buf[i] = '\0';
	*portp = str2port(buf,proto_tcp);
	p = &p[i];
    }
    return p;
}

char *parseURL(url,protop,host,portp)
char *url;
int *protop;	/* 2:UDP, 3:First, 4:Proxy */
char *host;
int *portp;	/* host byte order */
{
    char *p = url;
    char buf[PROTO_LEN_MAX];
    int i;
    for (i=0; i < PROTO_LEN_MAX-1; i++) {
	if (p[i] == ':') break;
	buf[i] = p[i];
    }
    buf[i] = '\0';
    if (!strcmp(buf,"http")) {
	*portp = 80;
    } else {
	message(LOG_NOTICE,"Unknown protocol: %s",buf);
	*portp = 80;	/* default */
    }
    p = &p[i+1];
    if (p[0] != '/' ||  p[1] != '/') {
	message(LOG_ERR,"Unknown URL format: %s:%c%c",buf,p[0],p[1]);
	return NULL;
    }
    p += 2;
    return parseHost(p,host,portp);
}

#define CONNECT_METHOD	"CONNECT "
int doproxy(pair)
Pair *pair;
{
    struct sockaddr_in sin;
    char buf[BUFMAX];
    char *p = pair->buf;
    char *q = &pair->buf[pair->len];
    char *name;
    int port = 443;	/* host byte order */
    int http_flag = 1;
    int i;
    for (i=0; i < BUFMAX-1; i++) {
	if (p[i] == '\r' || p[i] == '\n') break;
	buf[i] = p[i];
    }
    buf[i] = '\0';
    message(LOG_INFO,": %s",buf);
    i = strlen(CONNECT_METHOD);
    if (!strncmp(buf,CONNECT_METHOD,i)) {
	name = p + i;
	parseHost(&buf[i],buf,&port);
	http_flag = 0;
    } else {
	while (*p != ' ' && p < q) p++;
	while (*p == ' ' && p < q) p++;
	name = p;
	p = parseURL(name,&pair->proto,buf,&port);
	if (!p || p >= q) return -1;
    }
    bzero((char *)&sin,sizeof(sin)); /* clear sin struct */
    sin.sin_family = AF_INET;
    sin.sin_port = htons((u_short)port);
    if (!host2addr(buf,&sin.sin_addr,&sin.sin_family)) {
	return -1;
    }
    if (http_flag) {
	if (*p != '/') *--p = '/';
	i = name - pair->buf;	/* "GET " */
	bcopy(pair->buf,p-i,i);
	pair->len = q - p + i;
	pair->start = p - i - pair->buf;
	if (Debug > 1) {
	    message(LOG_DEBUG,"proxy %d -> http://%s:%d",
		    pair->pair->sd,buf,port);
	}
    } else {
	pair->pair->proto |= proto_ohttp;	/* remove header */
    }
    pair->proto &= ~proto_proxy;
    return reqconn(pair,&sin);
}

int insheader(pair)	/* insert header */
Pair *pair;
{
    char buf[BUFMAX];
    int i;
    for (i=0; i < pair->len; i++) {
	if (pair->buf[pair->start+i] == '\n') break;
    }
    if (i >= pair->len) return -1;
    i++;
    bcopy(&pair->buf[pair->start],buf,i);	/* save leading header */
    bcopy(pair->buf,pair->buf+i,pair->start);	/* insert */
    bcopy(buf,pair->buf,i);			/* restore */
    pair->len += pair->start;
    pair->start = 0;
    return pair->len;
}

int rmheader(pair)	/* remove header */
Pair *pair;
{
    char *p;
    char *q = &pair->buf[pair->start+pair->len];
    int state = (pair->proto & state_mask);
    if (Debug > 3) message_buf(pair,pair->len,"rm");
    for (p=&pair->buf[pair->start]; p < q; p++) {
	if (*p == '\r') continue;
	if (*p == '\n') {
	    state++;
	    if (state >= 2) {
		p++;
		break;	/* end of header */
	    }
	} else {
	    state = 0;
	}
    }
    if (state < 2) {
	pair->proto = ((pair->proto & ~state_mask) | state);
	return -1;	/* header will continue... */
    }
    pair->len = q - p;	/* remove header */
    pair->start = p - pair->buf;
    pair->proto &= ~state_mask;
    return pair->len;
}

int first_read(pair)
Pair *pair;
{
    int len = pair->pair->len;
    pair->proto &= ~proto_first_r;
    if (pair->pair->proto & proto_proxy) {	/* proxy */
	if (doproxy(pair->pair) < 0) {
	    doclose(pair->pair);
	    doclose(pair);
	    return -1;
	}
    }
    if (pair->proto & proto_ohttp) {	/* over http */
	len = rmheader(pair->pair);
	if (len < 0) {
	    FD_SET(pair->sd,&rin);	/* read header more */
	    pair->proto |= proto_first_r;
	} else {
	    if (pair->proto & proto_ohttp_s) {
		pair->start = 0;
		sprintf(pair->buf,
			"HTTP/1.0 200 OK\r%c\r%c",
			'\n','\n');
		pair->len = strlen(pair->buf);
		FD_SET(pair->sd,&win);	/* return header */
	    }
	    if (len == 0)
		FD_SET(pair->sd,&rin); /* read more */
	}
    }
    return len;
}

void asyncRead(pair)
Pair *pair;
{
    int len;
    utimer(TICK_TIMER);
    len = doread(pair);
    utimer(0);
    FD_SET(pair->sd,&ein);
    if (pair->proto & proto_ready_w) {
	FD_SET(pair->sd,&win);
	pair->proto &= ~proto_ready_w;
    }
    if (len < 0) {
	doclose(pair);	/* EOF or error */
    } else if (len > 0) {
	if (pair->proto & proto_first_r) len = first_read(pair);
	if (len > 0 &&
	    ValidSocket(pair->pair->sd) &&
	    !(pair->proto & proto_close))
	    FD_SET(pair->pair->sd,&win);
    } else {		/* EINTR */
	FD_SET(pair->sd,&rin);
    }
}

void asyncWrite(pair)
Pair *pair;
{
    int len;
    utimer(TICK_TIMER);
    len = dowrite(pair);
    utimer(0);
    FD_SET(pair->sd,&ein);
    if (pair->proto & proto_ready_r) {
	FD_SET(pair->sd,&rin);
	pair->proto &= ~proto_ready_r;
    }
    if (len < 0) {
	doclose(pair);	/* if error, close */
    } else if (pair->len <= 0) {	/* all written */
	if (pair->proto & proto_first_w) pair->proto &= ~proto_first_w;
	if (pair->pair != NULL && ValidSocket(pair->pair->sd) &&
	    !(pair->proto & proto_close))
	    FD_SET(pair->pair->sd,&rin);
    } else {		/* EINTR */
	FD_SET(pair->sd,&win);
    }
}

int scanPairs(rop,wop,eop)
fd_set *rop, *wop, *eop;
{
    Pair *pair;
    unsigned int g = Generation;
    if (Debug > 8) message(LOG_DEBUG,"scanPairs ...");
    for (pair=pairs.next; pair != NULL; pair=pair->next) {
	if (ValidSocket(pair->sd) && !(pair->proto & proto_close)) {
	    if (FD_ISSET(pair->sd,eop)) {
		message(LOG_ERR,"TCP %d: exception",pair->sd);
		message_pair(pair);
		doclose(pair);
	    } else if (FD_ISSET(pair->sd,rop)) {	/* read */
		FD_CLR(pair->sd,&ein);
		FD_CLR(pair->sd,&rin);
		if (FD_ISSET(pair->sd,&win)) pair->proto |= proto_ready_w;
		else pair->proto &= ~proto_ready_w;
		FD_CLR(pair->sd,&win);
		ASYNC(asyncRead,pair);
	    } else if (FD_ISSET(pair->sd,wop)) {	/* write */
		if (pair->proto & proto_ihead) {	/* insert header */
		    if (insheader(pair) >= 0) pair->proto &= ~proto_ihead;
		}
		FD_CLR(pair->sd,&ein);
		FD_CLR(pair->sd,&win);
		if (FD_ISSET(pair->sd,&rin)) pair->proto |= proto_ready_r;
		else pair->proto &= ~proto_ready_r;
		FD_CLR(pair->sd,&rin);
		ASYNC(asyncWrite,pair);
	    } else {
/*		time_t clock;
		if (time(&clock), clock - pair->clock > IDLE_MAX) {
		    message(LOG_NOTICE,"TCP %d: idle time exceeds",pair->sd);
		    message_pair(pair);	
		}	*/
	    }
	}
	if (g != Generation) return 0;
    }
    return 1;
}

/* stone */

int scanStones(rop,eop)
fd_set *rop, *eop;
{
    Stone *stone;
    unsigned int g = Generation;
    for (stone=stones; stone != NULL; stone=stone->next) {
	if (FD_ISSET(stone->sd,eop)) {
	    FD_CLR(stone->sd,&ein);
	    message(LOG_ERR,"stone %d: exception",stone->sd);
	} else if (FD_ISSET(stone->sd,rop)) {
	    if (stone->proto & proto_udp) {
		ASYNC(asyncUDP,stone);
	    } else {
		ASYNC(asyncAccept,stone);
	    }
	}
	if (g != Generation) return 0;
    }
    return 1;
}

void repeater() {
    int ret;
    fd_set rout, wout, eout;
    struct timeval tv, *timeout;
    static int spin = 0;
    rout = rin;
    wout = win;
    eout = ein;
    if (Recursion > 0 || conns.next || spin > 0) {
	if (spin > 0) spin--;
	timeout = &tv;
	timeout->tv_sec = 0;
	timeout->tv_usec = TICK_SELECT;
    } else timeout = NULL;		/* block indefinitely */
    ret = select(FD_SETSIZE,&rout,&wout,&eout,timeout);
    Generation++;
    if (ret > 0) {
	spin = SPIN_MAX;
	(void)(scanStones(&rout,&eout) > 0 &&
	       scanPairs(&rout,&wout,&eout) > 0 &&
	       scanUDP(&rout,&eout) > 0);
    } else if (ret < 0) {
#ifdef WINDOWS
	errno = WSAGetLastError();
#endif
	if (errno != EINTR) {
	    message(LOG_ERR,"select error err=%d",errno);
	    exit(1);
	}
    }
    scanConns();
    scanClose();
}

/* make stone */
Stone *mkstone(dhost,dport,host,port,nhosts,hosts,proto)
char *dhost;	/* destination hostname */
int dport;	/* destination port (host byte order) */
char *host;	/* listening host */
int port;	/* listening port (host byte order) */
int nhosts;	/* # of hosts to permit */
char *hosts[];	/* hosts to permit */
int proto;	/* UDP/TCP/SSL */
{
    Stone *stonep;
    struct sockaddr_in sin;
    char xhost[256], *p;
    int i;
    stonep = calloc(1,sizeof(Stone)+sizeof(XHost)*nhosts);
    if (!stonep) {
	message(LOG_ERR,"Out of memory.");
	exit(1);
    }
    stonep->p = NULL;
    stonep->nhosts = nhosts;
    bzero((char *)&sin,sizeof(sin)); /* clear sin struct */
    sin.sin_family = AF_INET;
    sin.sin_port = htons((u_short)port);/* convert to network byte order */
    if (host) {
	if (!host2addr(host,&sin.sin_addr,&sin.sin_family)) {
	    exit(1);
	}
    }
    if (!(proto & proto_proxy)) {
	if (!host2addr(dhost,&stonep->sin.sin_addr,&stonep->sin.sin_family)) {
	    exit(1);
	}
	stonep->sin.sin_port = htons((u_short)dport);
    }
    stonep->proto = proto;
    if (proto & proto_udp) {
	stonep->sd = socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);	/* UDP */
    } else {
	stonep->sd = socket(AF_INET,SOCK_STREAM,0);		/* TCP */
    }
    if (InvalidSocket(stonep->sd)) {
#ifdef WINDOWS
	errno = WSAGetLastError();
#endif
	message(LOG_ERR,"Can't get socket err=%d.",errno);
	exit(1);
    }
    if (bind(stonep->sd,(struct sockaddr*)&sin,sizeof(sin)) < 0) {
#ifdef WINDOWS
	errno = WSAGetLastError();
#endif
	message(LOG_ERR,"Can't bind err=%d.",errno);
	exit(1);
    }
    for (i=0; i < nhosts; i++) {
	strcpy(xhost,hosts[i]);
	p = strchr(xhost,'/');
	if (p != NULL) {
	    *p++ = '\0';
	    if (!host2addr(p,&stonep->xhosts[i].mask,NULL)) {
		exit(1);
	    }
	} else {
	    stonep->xhosts[i].mask.s_addr = (u_long)~0;
	}
	if (!host2addr(xhost,&stonep->xhosts[i].addr,NULL)) {
	    exit(1);
	}
	if (Debug > 1) {
	    strcpy(xhost,addr2str(&stonep->xhosts[i].addr));
	    if (proto & proto_proxy) {
		message(LOG_DEBUG,
			"stone %d: permit %s (mask %x) to connecting to proxy",
			stonep->sd,
			xhost,
			ntohl((unsigned long)stonep->xhosts[i].mask.s_addr));
	    } else {
		message(LOG_DEBUG,"permit %s (mask %x) to connecting to %s:%s",
			xhost,
			ntohl((unsigned long)stonep->xhosts[i].mask.s_addr),
			addr2str(&stonep->sin.sin_addr),
			port2str(stonep->sin.sin_port,
				 stonep->proto,proto_dest));
	    }
	}
    }
    if (!(proto & proto_udp)) {	/* TCP */
	if (listen(stonep->sd,BACKLOG_MAX) < 0) {
#ifdef WINDOWS
	    errno = WSAGetLastError();
#endif
	    message(LOG_ERR,"Can't listen err=%d.",errno);
	    exit(1);
	}
    }
    strcpy(xhost,port2str(sin.sin_port,stonep->proto,proto_src));
    if (proto & proto_proxy) {
	message(LOG_INFO,"stone %d: proxy <- %s",
		stonep->sd,
		xhost);
    } else {
	message(LOG_INFO,"stone %d: %s:%s <- %s",
		stonep->sd,
		addr2str(&stonep->sin.sin_addr),
		port2str(stonep->sin.sin_port,stonep->proto,proto_dest),
		xhost);
    }
    return stonep;
}

/* main */

void help(com)
char *com;
{
    fprintf(stderr,
	    "stone %s "
	    "Copyright(C)1998 by Hiroaki Sengoku <sengoku@gcd.forus.or.jp>\n"
#ifdef USE_SSL
	    "with cryptographic routines %d.%d.%d"
#if SSLEAY_VERSION_NUMBER % 0x10 > 0
	    "%c"
#endif
	    " written by Eric Young <eay@mincom.oz.au>\n"
#endif
	    "Usage: %s <opt>... <stone> [-- <stone>]...\n"
	    "opt:  -d                ; increase debug level\n"
	    "      -n                ; numerical address\n"
	    "      -u <max>          ; # of UDP sessions\n"
#ifndef NO_FORK
	    "      -f <n>            ; # of child processes\n"
#endif
#ifndef NO_SYSLOG
	    "      -l                ; use syslog\n"
#endif
	    "      -L <file>         ; write log to <file>\n"
#ifdef USE_SSL
	    "      -z <SSL>          ; SSLeay option\n"
#endif
	    "stone: <display> [<hosts>...]\n"
	    "       <host>:<port> <port> [<hosts>...]\n"
	    "       proxy <port> [<hosts>...]\n"
	    "       <host>:<port>/http <Request-Line> [<hosts>...]\n"
	    "       <host>:<port>/proxy <header> [<hosts>...]\n"
	    "port:  <port#>[/udp|/http"
#ifdef USE_SSL
	    "|/ssl"
#endif
	    "]\n",
	    VERSION,
#ifdef USE_SSL
	    SSLEAY_VERSION_NUMBER / 0x1000,
	    SSLEAY_VERSION_NUMBER % 0x1000 / 0x100,
	    SSLEAY_VERSION_NUMBER % 0x100 / 0x10,
#if SSLEAY_VERSION_NUMBER % 0x10 > 0
	    SSLEAY_VERSION_NUMBER % 0x10 - 1 + 'a',
#endif
#endif
	    com);
    exit(1);
}

int getdist(p,portp,protop)
char *p;
int *portp;	/* host byte order */
int *protop;
{
    char *port_str, *proto_str, *top;
    top = p;
    port_str = proto_str = NULL;
    while (*p) {
	if (*p == ':') {
	    *p++ = '\0';
	    port_str = p;
	} else if (*p == '/') {
	    *p++ = '\0';
	    proto_str = p;
	}
	p++;
    }
    if (!proto_str) {
	*protop = proto_tcp;	/* default */
    } else if (!strcmp(proto_str,"udp")) {
	*protop = proto_udp;
    } else if (!strcmp(proto_str,"tcp")) {
	*protop = proto_tcp;
    } else if (!strcmp(proto_str,"http")) {
	*protop = proto_ohttp;
    } else if (!strcmp(proto_str,"proxy")) {
	*protop = proto_ihead;
#ifdef USE_SSL
    } else if (!strcmp(proto_str,"ssl")) {
	*protop = proto_ssl;
#endif
    } else return -1;	/* error */
    if (port_str) {
	*portp = str2port(port_str,*protop);
	return 1;
    } else {
	if (!strcmp(top,"proxy")) {
	    *protop |= proto_proxy;
	    *portp = 0;
	    return 1;
	}
	*portp = str2port(top,*protop);
	return 0;	/* no hostname */
    }
}

void message_pairs() {	/* dump for debug */
    Pair *pair;
    for (pair=pairs.next; pair != NULL; pair=pair->next) message_pair(pair);
}

void message_origins() {	/* dump for debug */
    Origin *origin;
    for (origin=origins.next; origin != NULL; origin=origin->next)
	message_origin(origin);
}

void message_conns() {	/* dump for debug */
    Conn *conn;
    for (conn=conns.next; conn != NULL; conn=conn->next)
	message_conn(conn);
}

#ifndef WINDOWS
static void handler(sig,code)
int sig, code;
{
    static unsigned int g = 0;
    static int cnt = 0;
    int i;
    switch(sig) {
#ifndef NO_ALRM
      case SIGALRM:
	if (Debug > 8) message(LOG_DEBUG,"SIGALRM. (cnt,g,G)=(%d,%d,%d)",
			       cnt,g,Generation);
	utimer(0);
	signal(SIGALRM,handler);
	if (Generation == g) {
	    if (cnt < RECURS_CNT) {
		cnt++;
		if (cnt == RECURS_CNT) message(LOG_NOTICE,"recursion");
	    }
	    if (cnt >= RECURS_CNT) {
		{
		    sigset_t set;
		    sigemptyset(&set);
		    sigaddset(&set,SIGALRM);
		    sigprocmask(SIG_UNBLOCK,&set,NULL);
		}
		i = cnt;
		cnt = 0;
		Recursion++;
		repeater();	/* call recursively */
		Recursion--;
		cnt = i;
	    }
	} else {
	    cnt = 0;
	}
	g = Generation;
	utimer(TICK_TIMER);
	break;
#endif
      case SIGHUP:
	if (Debug > 4) message(LOG_DEBUG,"SIGHUP.");
	message_pairs();
	message_origins();
	message_conns();
	signal(SIGHUP,handler);
	break;
      case SIGTERM:
#ifdef IGN_SIGTERM
	Debug = 0;
	message(LOG_INFO,"SIGTERM. clear Debug level");
	signal(SIGTERM,handler);
	break;
#endif
      case SIGINT:
#ifndef NO_FORK
	for (i=0; i < NForks; i++) kill(Pid[i],sig);
#endif
	exit(1);
      case SIGUSR1:
	Debug++;
	message(LOG_INFO,"SIGUSR1. increase Debug level to %d",Debug);
	signal(SIGUSR1,handler);
	break;
      case SIGUSR2:
	if (Debug > 0) Debug--;
	message(LOG_INFO,"SIGUSR2. decrease Debug level to %d",Debug);
	signal(SIGUSR2,handler);
	break;
      case SIGPIPE:
	message(LOG_INFO,"SIGPIPE.");
	signal(SIGPIPE,handler);
	break;
      default:
	message(LOG_INFO,"signal %d. Debug level: %d",sig,Debug);
    }
}
#endif

char *argstr(p)
char *p;
{
    char *ret = malloc(strlen(p));
    char c, *q;
    if (ret == NULL) {
	message(LOG_ERR,"Out of memory.");
	exit(1);
    }
    q = ret;
    while ((c = *p++)) {
	if (c == '\\') {
	    switch(c = *p++) {
	      case 'n':  c = '\n';  break;
	      case 'r':  c = '\r';  break;
	      case 't':  c = '\t';  break;
	      case '\0':
		c = '\\';
		p--;
	    }
	}
	*q++ = c;
    }
    *q = '\0';
    return ret;
}

int main(argc,argv)
int argc;
char *argv[];
{
    Stone *stone;
    int i, j, k;
    char display[256], *p;
    char *disphost, *host, *shost;
    int dispport, port, sport;
    int proto, sproto, dproto, dispproto;
    char *argend = argv[argc-1] + strlen(argv[argc-1]);
#ifdef WINDOWS
    WSADATA WSAData;
#endif
    proto = sproto = dproto = dispproto = proto_tcp;	/* default: TCP */
    disphost = NULL;
    p = getenv("DISPLAY");
    if (p) {
	if (*p == ':') {
	    sprintf(display,"localhost%s",p);
	} else {
	    strcpy(display,p);
	}
	i = 0;
	for (p=display; *p; p++) {
	    if (*p == ':') i = 1;
	    else if (i && *p == '.') {
		*p = '\0';
		break;
	    }
	}
	if (getdist(display,&dispport,&dispproto) > 0) {
	    disphost = display;
	    dispport += XPORT;
	} else {
	    fprintf(stderr,"Illegal DISPLAY: %s\n",p);
	}
    }
    setbuf(stderr,NULL);
    LogFp = stderr;
#ifdef USE_SSL
#ifdef SSLEAY8
    SSLeay_add_ssl_algorithms();
#endif
    SSL_load_error_strings();
    sprintf(ssl_file_path,"%s/stone.pem",	/* default */
	    X509_get_default_cert_dir());
    keyfile = certfile = ssl_file_path;
#endif
    for (i=1; i < argc; i++) {
	p = argv[i];
	if (*p == '-') {
	    p++;
	    while(*p) switch(*p++) {
	      case 'd':
		Debug++;
		break;
#ifndef NO_SYSLOG
	      case 'l':
		Syslog = 1;
		break;
#endif
	      case 'L':
		LogFp = fopen(argv[++i],"a");
		if (LogFp == NULL) {
		    fprintf(stderr,"Can't create log file err=%d: %s\n",
			    errno,argv[i]);
		    exit(1);
		}
		setbuf(LogFp,NULL);
		break;
	      case 'n':
		AddrFlag = 1;
		break;
	      case 'u':
		OriginMax = atoi(argv[++i]);
		break;
#ifndef NO_FORK
	      case 'f':
		NForks = atoi(argv[++i]);
		break;
#endif
#ifdef USE_SSL
	      case 'z':
		if (++i >= argc) help(argv[0]);
		if (!strncmp(argv[i],"cert=",5)) {
		    certfile = strdup(argv[i]+5);
		} else if (!strncmp(argv[i],"key=",4)) {
		    keyfile = strdup(argv[i]+4);
		} else if (!strncmp(argv[i],"verify=",7)) {
		    ssl_verify_flag = atoi(argv[i]+7);
		} else if (!strcmp(argv[i],"certrequired")) {
		    if (!ssl_verify_flag) ssl_verify_flag++;
		} else if (!strcmp(argv[i],"secure")) {
		    if (!ssl_verify_flag) ssl_verify_flag++;
		} else if (!strncmp(argv[i],"cipher=",7)) {
		    cipher_list = strdup(argv[i]+7);
		} else if (!strcmp(argv[i],"verbose")) {
		    ssl_verbose_flag++;
		} else {
		    fprintf(stderr,"Invalid SSL Option: %s\n",argv[i]);
		    help(argv[0]);
		}
		break;
#endif
	      default:
		fprintf(stderr,"Invalid Option: %s\n",argv[i]);
		help(argv[0]);
	    }
	} else break;
    }
#ifndef NO_SYSLOG
    if (Syslog) {
	char str[STRMAX];
	sprintf(str,"stone[%d]",getpid());
	openlog(str,0,LOG_DAEMON);
    }
#endif
    message(LOG_INFO,"start (%s) [%d]",VERSION,getpid());
    if (Debug > 0) {
	message(LOG_DEBUG,"Debug level: %d",Debug);
    }
#ifdef WINDOWS
    if (WSAStartup(MAKEWORD(1,1),&WSAData)) {
	message(LOG_ERR,"Can't find winsock.");
	exit(1);
    }
    atexit((void(_CRTAPI1 *)(void))WSACleanup);
#endif
#ifdef USE_SSL
#ifdef SSLEAY8
    ssl_ctx = SSL_CTX_new(SSLv23_method());
#else
    ssl_ctx = SSL_CTX_new();
#endif
    if (!cipher_list) cipher_list = getenv("SSL_CIPHER");
#endif
    if (argc - i < 1) help(argv[0]);
    for (; i < argc; i++) {
	j = getdist(argv[i],&port,&dproto);
	if (j > 0) {	/* with hostname */
	    host = argv[i++];
	    if (argc <= i) help(argv[0]);
	    j = getdist(argv[i],&sport,&sproto);
	    if (j > 0) {
		shost = argv[i];
	    } else if (j == 0) {
		shost = NULL;
	    } else help(argv[0]);
	} else if (j == 0 && disphost != NULL) {
	    shost = NULL;	/* without hostname i.e. Display Number */
	    sport = port+XPORT;
	    host = disphost;
	    port = dispport;
	    dproto = dispproto;
	} else help(argv[0]);
	i++;
	j = 0;
	k = i;
	for (; i < argc; i++, j++) if (!strcmp(argv[i],"--")) break;
	if ((dproto & proto_udp) || (sproto & proto_udp)) {
	    proto = proto_udp;
	} else {
	    proto = proto_tcp;
	    if (sproto & proto_ohttp) proto |= proto_ohttp_s;
	    if (sproto & proto_ssl) proto |= proto_ssl_s;
	    if (dproto & proto_proxy) proto |= proto_proxy;
	    if (dproto & proto_ohttp) {
		proto |= proto_ohttp_d;
		goto extra_arg;
	    } else if (dproto & proto_ihead) {
		proto |= proto_ihead;
	      extra_arg:
		p = argv[k++];
		j--;
		if (k > argc || j < 0) help(argv[0]);
	    }
	    if (dproto & proto_ssl) proto |= proto_ssl_d;
	}
	stone = mkstone(host,port,shost,sport,j,&argv[k],proto);
	if (proto & proto_ohttp_d) {
	    stone->p = argstr(p);
	} else if (proto & proto_ihead) {
	    stone->p = argstr(p);
	}
	stone->next = stones;
	stones = stone;
    }
    if (!(pkt_buf=malloc(pkt_len_max=PKT_LEN_INI))) {
	message(LOG_ERR,"Out of memory.");
	exit(1);
    }
    for (p=argv[1]; p < argend; p++) *p = '\0';
    pairs.next = NULL;
    conns.next = NULL;
    origins.next = NULL;
    FD_ZERO(&rin);
    FD_ZERO(&win);
    FD_ZERO(&ein);
    for (stone=stones; stone != NULL; stone=stone->next) {
	FD_SET(stone->sd,&rin);
	FD_SET(stone->sd,&ein);
    }
#ifndef WINDOWS
#ifndef NO_ALRM
    signal(SIGALRM,handler);
#endif
    signal(SIGHUP,handler);
    signal(SIGTERM,handler);
    signal(SIGINT,handler);
    signal(SIGPIPE,handler);
    signal(SIGUSR1,handler);
    signal(SIGUSR2,handler);
#endif
#ifndef NO_FORK
    Pid = malloc(sizeof(pid_t) * NForks);
    if (!Pid) {
	message(LOG_ERR,"Out of memory.");
	exit(1);
    }
    for (i=0; i < NForks; i++) {
	Pid[i] = fork();
	if (!Pid[i]) break;
    }
    NForks = i;
#endif
#ifndef NO_SYSLOG
    if (Syslog) {
	char str[STRMAX];
	closelog();
	sprintf(str,"stone[%d]",getpid());
	openlog(str,0,LOG_DAEMON);
    }
#endif
#ifdef WINDOWS
    PairMutex = ConnMutex = OrigMutex = NULL;
    if (!(PairMutex=CreateMutex(NULL,FALSE,NULL)) ||
	!(ConnMutex=CreateMutex(NULL,FALSE,NULL)) ||
	!(OrigMutex=CreateMutex(NULL,FALSE,NULL))) {
	message(LOG_ERR,"Can't create Mutex err=%d",GetLastError());
    }
#endif
#ifdef OS2
    PairMutex = ConnMutex = OrigMutex = NULLHANDLE;
    if ((j=DosCreateMutexSem(NULL,&PairMutex,0,FALSE)) ||
	(j=DosCreateMutexSem(NULL,&ConnMutex,0,FALSE)) ||
	(j=DosCreateMutexSem(NULL,&OrigMutex,0,FALSE))) {
	message(LOG_ERR,"Can't create Mutex err=%d",j);
    }
#endif
    for (;;) repeater();
    return 0;
}
