
			    Simple Repeater

			   stone version 2.0

		  Copyright(c)1998 by Hiroaki Sengoku
			sengoku@gcd.forus.or.jp


  Stone is a TCP/IP packet repeater in the application layer.  It
repeats TCP and UDP packets from inside to outside of a firewall, or
from outside to inside.

  Stone has following features:

1.  Stone supports Win32.
	Formerly, UNIX machines are used as firewalls, but recently
	WindowsNT machines are used, too.  You can easily run Stone on
	WindowsNT and Windows95.  Of course, available on Linux,
	FreeBSD, BSD/OS, SunOS, Solaris, HP-UX and so on.

2.  Simple.
	Stone's source code is only 2000 lines long (written in C
	language), so you can minimize the risk of security
	holes.

3.  Stone supports SSLeay.
	Using SSLeay developed by Eric Young, Stone can encrypt/decrypt
	packets.

4.  Stone is a http proxy.
	Stone can also be a tiny http proxy.


HOWTO USE

	stone [-d] [-n] [-u <max>] [-f <n>] [-l] [-z <SSL>]
	      <st> [-- <st>]...

	If the ``-d'' flag is used, then increase the debug level.  The
	``-z'' is the flag for SSL encryption.  If the ``-n'' is used,
	IP addresses and service port numbers are shown instead of host
	names and service names.  If the ``-u <max>'' flag (``<max>'' is
	integer) is used, the program memorize ``<max>'' sources
	simultaneously where UDP packets are sent.  If the ``-f <n>''
	flag (``<n>'' is integer) is used, the program spawn ``<n>''
	child processes.  If the ``-l'' flag is used, the program sends
	error messages to the syslog instead of stderr.

	``<st>'' is one of the following.  Multiple ``<st>'' can be
	designated, separated by ``--''.

	(1)	<host>:<port> <sport> [<xhost>...]
	(2)	<host>:<port> <shost>:<sport> [<xhost>...]
	(3)	<display> [<xhost>...]
	(4)	proxy <sport> [<xhost>...]
	(5)	<host>:<port>/http <request> [<hosts>...]
	(6)	<host>:<port>/proxy <header> [<hosts>...]

	The program repeats the connection on port ``<sport>'' to the
	other machine ``<host>'' port ``<port>''.  If the machine, on
	which the program runs, has two or more interfaces, type (2) can
	be used to repeat the connection on the specified interface
	``<shost>''.

	Type (3) is the abbreviating notation.  The program repeats the
	connection on display number ``<display>'' to the X server
	designated by the environment variable ``DISPLAY''.

	Type (4) is a http proxy.  Specify the machine, on which the
	program runs, and port ``<sport>'' in the http proxy settings of
	your WWW browser.

	Type (5) repeats packets over http request.  ``<request>'' is
	the request specified in HTTP 1.0.

	Type (6) repeats http request with ``<header>'' in the top of
	request headers.

	If the ``<xhost>'' are used, only machines ``<xhost>'' can
	connect to the program.

	If the ``<xhost>/<mask>'' are used, only machines on specified
	networks are permitted to connect to the program.  In the case
	of class C network 192.168.1.0, for example, use
	``192.168.1.0/255.255.255.0''.

	If the ``<sport>/udp'' is used, repeats UDP packets instead of
	TCP packets.

	If the ``<port>/ssl'' is used, repeats packets with encryption.

	If the ``<sport>/ssl'' is used, repeats packets with decryption.

	If the ``<sport>/http'' is used, repeats packets over http.


EXAMPLES
	outer: a machine in the outside of the firewall
	inner: a machine in the inside of the firewall
	fwall: the firewall on which the stone is executed

	stone 7 outer
		Repeats the X protocol to the machine designated by the
		environmental variable ``DISPLAY''.  Run X clients under
		``DISPLAY=inner:7'' on ``outer''.

	stone outer:telnet 10023
		Repeats the telnet protocol to ``outer''.
		Run ``telnet fwall 10023'' on ``inner''.

	stone outer:domain/udp domain/udp
		Repeats the DNS query to ``outer''.
		Run ``nslookup - fwall'' on ``inner''.

	stone outer:ntp/udp ntp/udp
		Repeats the NTP to ``outer''.
		Run ``ntpdate fwall'' on ``inner''.

	stone localhost:http 443/ssl
		Make WWW server that supports ``https''.
		Access ``https://fwall/'' using a WWW browser.

	stone localhost:telnet 10023/ssl
		Make telnet server that supports SSL.
		Run ``SSLtelnet -z ssl fwall 10023'' on ``inner''.

	stone proxy 8080
		http proxy.

	Where fwall is a http proxy (port 8080):

	stone fwall:8080/http 10023 'GET http://outer:8023 HTTP/1.0'
	stone localhost:telnet 8023/http
		Run stones on ``inner'' and ``outer'' respectively.
		Repeats packets over http.

	stone fwall:8080/proxy 9080 'Proxy-Authorization: Basic c2VuZ29rdTpoaXJvYWtp'
		for browser that does not support proxy authorization.


COPYRIGHT

	All rights about this program ``stone'' are reserved by the
	original author, Hiroaki Sengoku.  The program is free software;
	you can redistribute it and/or modify it under the terms of the
	GNU General Public License (GPL).


NO WARRANTY

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY.


					 Hiroaki Sengoku @ Kawasaki City
#2939						 sengoku@gcd.forus.or.jp
<A HREF="http://www.yajima.kuis.kyoto-u.ac.jp/staffs/sengoku/">info.</A>
