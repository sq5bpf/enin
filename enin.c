/*
	enin - Enumerate IPX Nodes
	Enin is a program to discover all ipx nodes on a network. 
	Please see the file README for further details.

	Written by Jacek Lipkowski <sq5bpf@acid.ch.pw.edu.pl>


        This program is free software; you can redistribute it and/or
        modify it under the terms of the GNU General Public License
        as published by the Free Software Foundation; either version 2
        of the License, or (at your option) any later version.

        This program is distributed in the hope that it will be useful,
        but WITHOUT ANY WARRANTY; without even the implied warranty of
        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
        GNU General Public License for more details.

        You should have received a copy of the GNU General Public License
        along with this program; if not, write to the Free Software Foundation
        Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
        http://www.gnu.org/copyleft/gpl.html

*/

#include <stdio.h>
#include <sys/types.h>
#include <netipx/ipx.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <errno.h>
#include<unistd.h>
#include<signal.h>
#include<string.h>


/* default timeout in seconds*/
#define DEFAULT_TIMEOUT 2

#define VERSION "1.0"

int s;
struct sockaddr_ipx sipx;
int len = sizeof (sipx);

/*parameters*/
int parsediag=0;
int ident=0;
int hexdump=0;
int singlenet=0;
int timeout=DEFAULT_TIMEOUT;


/* some signatures */

/* don't know how vlm answers */
unsigned char netx_sig[9] =    "\x01\x01\x40\x01\x04\x00\x02\x03\x09"; 
unsigned char netware3x_sig[8] = "\x01\x00\x40\x03\x03\x00\x01\x06";
unsigned char netware5x_sig[8] = "\x01\x00\x40\x01\x03\x00\x01\x06";
unsigned char msclient_sig[8] = "\x01\x01\x40\x02\x03\x00\x02\x03";
unsigned char novclient_sig[9] = "\x01\x00\x40\x01\x04\x00\x02\x03\x09";
unsigned char jetdirect_sig[8] = "\x01\x00\x48\x01\x02\x00\x02\x43";
unsigned char smctigerswitch_sig[6] = "\x01\x00\x00\x00\x01\x00";


int
opensock ()
{
  int result;
  int f;
  f = socket (AF_IPX, SOCK_DGRAM, AF_IPX);
  if (f < 0)
    {
      perror ("IPX: socket: ");
      exit (-1);
    }
  sipx.sipx_family = AF_IPX;
  sipx.sipx_network = 0;
  sipx.sipx_port = 0;
  sipx.sipx_type = 17;



  result = bind (f, (struct sockaddr *) &sipx, sizeof (sipx));
  if (result < 0)
    {
      perror ("IPX: bind: ");
      exit (-1);
    }

  return (f);
}

sendping (int sock, unsigned long net)
{
  char msg[] = "\x00"; /* no exclusion list */

  sipx.sipx_network = htonl (net);

  sipx.sipx_port = htons (0x456);
  sipx.sipx_node[0] = 0xff;
  sipx.sipx_node[1] = 0xff;
  sipx.sipx_node[2] = 0xff;
  sipx.sipx_node[3] = 0xff;
  sipx.sipx_node[4] = 0xff;
  sipx.sipx_node[5] = 0xff;

  sendto (s, msg, sizeof (msg), 0, (struct sockaddr *) &sipx, sizeof (sipx));

}

sighand (int sign)
{
  close (s);
}

/* parse the diagnostic response */
analdiag(unsigned char *buf,int len)
{
int compcnt=0;
int ptr=0;
int i,n;
int nnets;

if (len>1) printf("IPX version: %i.%i\n",buf[0],buf[1]);
if (len>3) printf("SPX diagnostic socket 0x%2.2x%2.2x\n",buf[2],buf[3]);
if (len>4) {
/* there is a component count */
compcnt=buf[4];
printf("%i components:\n",compcnt);
ptr=5;

for (i=0;i<compcnt;i++) {
printf("%i:",i); 

switch (buf[ptr])
{

/* simple components */
case 0: printf(" IPX/SPX\n");
break;

case 1: printf(" Router drivers\n");
break;

case 2: printf(" LAN drivers\n");
break;

case 3: printf(" Shells\n");
break;

case 4: printf(" VAPs\n");
break;

case 9: printf(" DOS Application\n");
break;

case 5: if (buf[ptr]==5) printf(" Router:\n");
case 6: if (buf[ptr]==6) printf(" File Server/Router:\n");
case 7: if (buf[ptr]==7) printf(" Nondedicated IPX/SPX:\n");

/*netparser*/

if (ptr<len) { ptr++; } else {printf(" packet too short\n"); break; }
nnets=buf[ptr];
printf ("\t%i nets:\n",nnets);
for (n=0;n<nnets;n++)
{
if (ptr<len) { ptr++; } else {printf(" \tpacket too short\n"); break; }
printf("\t");
switch (buf[ptr])
{
case 0: printf("Lan board           "); break;
case 1: printf("Virtual board       "); break;
case 2: printf("Redirected remote line "); break;
default: printf("type %i        ",buf[ptr]); break;

}
if ((ptr+9)<len) { ptr++; } else {printf("\tpacket tooo short\n"); break; }
printf("\t%2.2x%2.2x%2.2x%2.2x|%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x\n",
buf[ptr],buf[ptr+1],buf[ptr+2],buf[ptr+3],
buf[ptr+4],buf[ptr+5],buf[ptr+6],buf[ptr+7],buf[ptr+8],buf[ptr+9]);
ptr=ptr+9;

}

break;

default: printf(" UNKNOWN type %2.2x (if you know what it is contact sq5bpf@acid.ch.pw.edu.pl)\n",buf[ptr]);
break;

}

ptr++;
if (ptr>len) {printf (" packet too short\n"); break; }

}

}

printf("\n");

}

/* receive the ping responses and do stuff with them */
rxipx (int sock)
{
  int ll;
  int ok;
  int res;

/* this might not be ethernet, so might as well set it to a larger size */
  unsigned char buf[8192]; 

  bzero (&buf, sizeof (buf));

  res =
    recvfrom (sock, &buf, sizeof (buf), 0, (struct sockaddr *) &sipx, &len);

/* 0x456 is the ipx ping socket */
  if ((res > 1) && (htons (sipx.sipx_port) == 0x456))
    {
      ok = 1;
      printf ("%08X:%02X%02X%02X%02X%02X%02X",
	      (u_int32_t) htonl (sipx.sipx_network),
	      sipx.sipx_node[0], sipx.sipx_node[1],
	      sipx.sipx_node[2], sipx.sipx_node[3],
	      sipx.sipx_node[4], sipx.sipx_node[5]);

/* try to identify the ipx stack on this machine, this is unreliable at best. 
 * if you have any other signatures send them to sq5bpf@acid.ch.pw.edu.pl */

if (ident) {
ok=0;
      if ((res == sizeof (smctigerswitch_sig))
	  && (memcmp (&buf, &smctigerswitch_sig, sizeof (smctigerswitch_sig)) == 0))
	{
	  printf (" SMC Tigerswitch");
	  ok = 1;
	}

      if ((res == sizeof (jetdirect_sig))
	  && (memcmp (&buf, &jetdirect_sig, sizeof (jetdirect_sig)) == 0))
	{
	  printf (" HP Jetdirect");
	  ok = 1;
	}

      if ((res == sizeof (msclient_sig))
	  && (memcmp (&buf, &msclient_sig, sizeof (msclient_sig)) == 0))
	{
	  printf (" ms netware client");
	  ok = 1;
	}

      if ((res == sizeof (novclient_sig))
	  && (memcmp (&buf, &novclient_sig, sizeof (novclient_sig)) == 0))
	{
	  printf (" novell netware client");
	  ok = 1;
	}

      if ((res == sizeof (netx_sig))
	  && (memcmp (&buf, &netx_sig, sizeof (netx_sig)) == 0))
	{
	  printf (" netx");
	  ok = 1;
	}

      if ((res > sizeof (netware3x_sig))
	  && (memcmp (&buf, &netware3x_sig, sizeof (netware3x_sig)) == 0))
	{
	  printf (" netware 3.x");
	  ok = 1;
	}

      if ((res > sizeof (netware5x_sig))
	  && (memcmp (&buf, &netware5x_sig, sizeof (netware5x_sig)) == 0))
	{
	  printf (" netware 4.x/5.x");
	  ok = 1;
	}
}

/* hexdump the packet */
      if ((!ok)|(hexdump))
	for (ll = 0; ll < res; ll++)
	  printf (" %2.2x", (unsigned char) buf[ll]);
      printf ("\n");

/* parse the packet */
if (parsediag) analdiag((unsigned char *)&buf,res);

    }

  return (res);
}

help()
{
printf("ENIN version %s (c) Jacek Lipkowski <sq5bpf@acid.ch.pw.edu.pl>\n",VERSION);
printf("usage:\n");
printf("--help: help\n-h    : hexdump\n-i    : try to identify machine\n-p    : parse diagnostic message\n-a    : equivalent to -h -p -i\n");
printf("-n NET: ping only single net\n-t sec: how much to wait for responses in seconds (default: 2)\n");
exit(0);
}

/* ping a single network */
pingnet(unsigned long net)
{

	  s = opensock ();
	  printf ("################### NETWORK %8.8x ####################\n", net);
	  sendping (s, net);
	  signal (SIGALRM,(void *) sighand);
	  alarm (timeout);
	  while (rxipx (s) > 0)
	    {
	      alarm (timeout);
	    }
	  close (s);
}


main (int argc, char **argv)
{
  int n = 0;
  FILE *f;
  char rbuf[1024];
  unsigned long net;
int i;
int ok;

/* ok, i should learn how to use getopt :) */
for (i=1;i<argc;i++)
{
ok=0;
if (strcmp(argv[i],"--help")==0) { help(); ok=1; }
if (strcmp(argv[i],"-h")==0) { hexdump=1; ok=1; }
if (strcmp(argv[i],"-i")==0) { ident=1; ok=1; }
if (strcmp(argv[i],"-p")==0) { parsediag=1; ok=1; }
if (strcmp(argv[i],"-a")==0) { parsediag=1; ident=1; hexdump=1; ok=1; }
if (strcmp(argv[i],"-n")==0) { singlenet=1; i++;
	  net = strtol (argv[i], (char **) NULL, 16);
ok=1; }

if (strcmp(argv[i],"-t")==0) { i++;
timeout=atoi(argv[i]);
ok=1; }

if (!ok) help();

}

if (singlenet)
{
pingnet(net);


}
else

{
  f = fopen ("/proc/net/ipx_route", "r");
  if (!f)
    {
      perror ("fopen /proc/net/ipx_route");
fprintf(stderr,"Is ipx loaded\n");
      exit (1);
    }
  while (!feof (f))
    {
      if (fgets ((char *)&rbuf, sizeof (rbuf), f) && n)
	{
	  net = strtol (&rbuf, (char **) NULL, 16);
pingnet(net);
	}
      n++;
    }
}
exit(0);
}
