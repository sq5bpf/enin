# ENIN - Enumerate IPX nodes

This software was originally released in 2001, and lost in the depths
of the internet a few years later. I'm re-releasing it in 2018, hope 
someone will find it useful. --sq5bpf


### Description:

This is a program for discovering all IPX nodes on a network. 
It works by sending an ipx ping packet to all nodes on a network.
In addition to printing the ipx network and node address it is able
to: print the hexdump of the packet (-h option), try to identify the
ipx stack on the node (-i option - please note that this is unreliable 
at best), and parse the diagnostic response (-p option) giving the 
ipx version, the spx diagnostic socket, a list of installed components,
a list of interfaces in case of routers etc. By default the program 
uses all networks in /proc/net/ipx_route. If you want to limit the query 
to a single network use the -n option (like -n 12abc, -n 0 is always
the local network).

### Instalation:

The usual:
make
make install

Please note that IPX must be installed and configured, for further 
information refer to the IPX-HOWTO, it is advised to run ipxd or other
software which updates the ipx routing table. 
Note: the original ipxripd 0.7 package has to be patched to work with
glibc. Various people have published patched versions which work with
reacent header files, search on github for ipxripd for example.

For starters try enin -a and see if it discovers anything.

Usage: enin [options]
Avaliable options:
--help: help
-h    : hexdump of the ping response
-i    : try to identify the node (unreliable at best), you will get a 
        hexdump of the response if identification fails
-p    : parse diagnostic message
-a    : equivalent to -h -p -i
-n NET: ping only single net
-t sec: how much to wait for responses in seconds (default: 2)

### Examples:

Show all nodes, parse the responses, and try to  identify what machines are
present:

enin -i -p 

Show all nodes on network 0x1DEAD, give all information, wait 10 seconds 
for the responses:

enin -a -n 1dead -t 10


### Bugs:

I should've used getopt for the option parsing. I should ping the network 
a few times, because some packets may be lost. Everything should probably 
be more documented (in a manpage). It only works on linux, since i don't 
have other platforms supporting IPX avaliable. There should be an option 
to use the SPX diagnostic socket for something (but I couldn't find any
documentation).


### Feedback:

Comments, questions, ports and other patches, and bug reports are welcome.
Please send them to Jacek Lipkowski <sq5bpf@lipkowski.org>. You might
want to check if there is a newer version avaliable at:
https://github.com/sq5bpf/enin

### Credits:

This program was written following the documentation at www.protocols.com,
later i found a book by Novell Press titled "NetWare Lan Analysis", which
contains somewhat more detailed documentation (the meaning of the type field 
is documented), even later on i found the meaning of component 9 
(DOS Application) at some netware site. Various parts were cut'n'pasted 
from ipxrcv.c and ipxsend.c from the ncpfs package.

### License:

enin is distributed under the GNU Public License v2, a copy of which
should have been provided with this archive as LICENSE.

