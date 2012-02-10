#1. Name
Squeeza - SQL Injection without the pain of syringes
#2. Authors
Marco Slaviero < marco(at)sensepost(dot)com >  
Haroon Meer
#3. License, version & release date
License : GPLv2  
Version : v0.22  
Release Date : 2008/08/24
#4. Description
squeeza is a tool helps exploits SQL injection vulnerabilities in broken
web applications. Its functionality is split into creating data on the
database (by executing commands, copying in files, issuing new SQL queries)
and extracting that data through various channels (dns, timing, http error
messages)  
Currently, it supports the following databases:  

 - Microsoft SQL Server   
 - MySQL (only when multi-queries are enable, which is not too common)  
squeeza is not a tool for finding injection points. That recipe
generally starts with 1 x analyst.
#5. Usage
##5.1 Installation
Installation is easy. Untar the archive into an appropriate spot.
>  $tar xvzf squeeza-0.21.tar.gz

Thereafter, edit the configuration file. By default, this is called
'squeeza.config' and resides in the same directory as the rest of the
scripts.  
Off the bat, you'll want to edit at least the following configuration
items:

 - host  
 - url  
 - querystring  
 - method  
 - sql\_prefix  
 - sql\_postfix  
 - dns\_domain  
The default mode is command mode, and the default channel is dns.
##5.2 Data Flow Model
As already mentioned, squeeza splits the creation of data at the server
away from the extraction of that data off the server (within certain
constraints). Data is created by a /mode/, and extracted via a /channel/.
By doing so, it is possible to mix 'n match modes with channels, which we
think is pretty nifty/flexible.  

Currently supported modes:  

 - command mode : supports commands execution on the database server  
 - copy mode : supports copying of files from the database server to the local machine  
 - sql mode : supports the execution of arbitrary sql queries  

Currently supported channels:  

 - dns channel : extracts data via dns
 - timing channel : extracts data by timing bits in the output  
 - http error message : extracts data through http error messages, similarly to Sec-1's automagic sql injector  

Although we've striven for complete separation of modes and channels, we
haven't completely succeeded as of yet (our SQL-fu is not strong). The
following matrix shows the level of support for each mode and channel
combination.

	                            Channel
	             .-------------------------------------.	
	             |    DNS    |  Timing   | HTTP Errors |
	  .----------+-----------+-----------+-------------|
	M | Command || Supported | Supported | Supported   |
	o | Copy    || Supported | Supported | Supported   |
	d | SQL     || Supported | Supported | Unsupported |
	e |         ||           |           |             |
	  `------------------------------------------------`
	
Obviously, you'll also be limited by the capabilities of the database
connection. If xp_cmdshell is removed or otherwise unavailable, squeeza
isn't going to magically make it reappear.

##5.3 Command Set
The following commands are hooked into the basic squeeza shell. (Each
module will probably further expose its own commands.) squeeza commands are
always prefixed by a '!'.  

 !help - print help for the shell and any loaded modules  
 !quit - take a guess...  
 !set  - use this to set or view shell variables  

 The mssql module has the following commands:  

 !channel - use to view or set the current channel  
 !cmd - switch to command mode  
 !copy - switch to copy mode  
 !sql - switch to sql mode  

##5.4 Example Usage
Starting squeeza:

> $./squeeza.rb


> Squeeza tha cheeza v0.21
> (c) {marco|haroon}@sensepost.com 2007
 
> sp-sq> 


This presents you with a basic shell from which to control squeeza. All
squeeza commands are prefixed by a '!'. Anything else is sent through to
the underlying module; this generally causes action to occur. E.g. The 
default mode is command mode. When typing in  

> sp-sq> dir c:\

The command 'dir c:\' is sent to the server, and its output is returned via
your channel of choice. To switch to HTTP error-based copy mode, and copy
the file c:\sp.jpeg to local file sp.copied, the following command sequence
would work  

> sp-sq> !channel http
> sp-sq> !copy
> sp-sq> c:\sp.jpeg sp.copied

To then extract a list of database tables via timing, one could use  

> sp-sq> !channel time
> sp-sq> !sql
> sp-sq> !ret tables

##5.5 Using command mode
Switch to command mode at any time by using the '!cmd' command.  

This mode enables the execution of commands on the server. Type in the
command of choice, and squeeza will execute it and return its results.  

Beware that if you attempt to execute a file that triggers a handler, then
squeeza will timeout waiting for a response. E.g. if you execute  
c:\some.jpeg, the database server will probably fire up Windows Picture and
Fax Viewer /on the server/, and sit waiting for the viewer to quit. Which it won't.

Command mode uses the following variables:  
 - cmd\_table_name : name to use for temporary table in database, default is 'sqcmd'  

##5.6 Using copy mode
Switch to copy mode at any time by using the '!copy' command.  

This mode enables the copying of files /from/ the server to your local
machine. Format of copy command is:  

> sp-sq> src-file [dst-file]

where 'src-file' is a full path to the file you want to copy, and the
optional 'dst-file' is a local filename.

##5.7 Using sql mode
Switch to sql mode at any time by using the '!sql' command.  

This mode enables the execution of fairly simple but arbitrary SQL queries 
on the database. It has built-in queries to help with the mapping of 
database schema, but one can easily construct one's own queries. This mode 
does not actually build an intermediate or temporary table before data 
extraction, as an added optimisation.  

The built-in queries are operated using the '!ret' command. Possible values for '!ret' include:  
- info  
- tables  
- columns < table\_name >  

E.g.:  

> sp-sq> !ret info
> sp-sq> !ret tables
> sp-sq> !ret columns sysobjects

Issuing arbitrary queries is a little more complex (but not by much!)  
The query should take the form of:  

> < column\_name > < table\_names > < where\_clause >

For instance, to extract user tables one could use the following query

> sp-sq> name sysobjects xtype='U'

##5.8 Using the DNS channel
Switch to the dns channel at any time by using the '!channel dns' command.  

This channel is useful when no HTTP error messages are present, and you
can't export reverse shells or connect to bind shells due to network
limitations. If DNS is allowed out the network, the channel will work for you.  

Depending on whether your injection point has sysadmin privileges or not,
squeeza can be instructed to use different injection strings. This is
influenced by the 'dns\_privs' configuration variable. Possible values:  

- high : database user is sysadmin, and xp_cmdshell is available  
- medium : database user is sysadmin, xp_cmdshell is not available (we'll use xp\_getfiledetails as a reasonable substitute)  
- low : database user is unprivileged, use xp\_getfiledetails  

Other configuration variables that affect the DNS channel (see Appendix A for a longer description):  

- request_timeout  
- dns_domain  
- dns_server  

##5.9 Using the timing channel
Switch to timing channel at any time by using the '!channel time' command.  

This channel enables the extraction of data when very few database or
network privileges are present. It can be extremely slow (as in, 1 or 2
bits per second) but might just be what you need.  

The timing channel provides the command '!calib' for automatic calibration
of time ranges. Feedback on the effectiveness of this command is gratefully
accepted.  

Configuration variables for the timing channel (see Appendix A for a longer
description:  

- delay  
- outlier_weight  
- one_range  
- zero_range  
- time_privs  
- ansi  
- request_timeout  

##5.10 Using the HTTP error channel
Switch to the HTTP error channel at any time by using the '!channel http' command.  

This channel requires that SQL errors are shown in the body of the HTML.
Not often seen in practise today, but useful when present. Much faster than
the other modes.  

Configuration variables for the HTTP error channel (see Appendix A for a longer
description:  
- request_timeout  

#6. Requirements
Before installing squeeza, ensure that the following system requirements
are fulfilled:  

- ruby (developed on 1.8.4, should work on any version after that, at
	 least. prior to 1.8.4, test and let me know if it works)  
- tcpdump (if you're planning on using the dns channel. if you're running
	 windows, let me know which, if any, of the various tcpdump ports worked
	 for you)  
- access to a dns server, if you'll be using the dns channel  
- a large SQL injection point in a vulnerable web application. how large?
	 typical injection strings are 600 or so bytes.  
#7. Additional Resources 
##7.1 Bugs
Apart from sql mode not working with the http error channel, we aren't
aware of major bugs in squeeza. Feel free to send your bug reports to
research@sensepost.com, along with a description of what when wrong, what
you were doing at the time, squeeza output and so on. Setting '!debug 2'
will give you much more output.

##7.2 Appendix A: Known configuration variables
Default value is given in rounded braces after the variable name. If a 
variable takes on a one of a pre-defined set of values, they are specified 
after the variable name like so:  

> random_var (default) [ value1 | value 2 | value 3 ]

All clear? Good. Let's carry one.  

ansi (off) [ on | off ] - Specifies whether your terminal capable of 
     handling ansi characters. Set to 'no' for Windows use.  
		 
cmd_table_name (sqcmd) - Name of temporary table to use in command mode  

cp_table_name (sqfilecp) - Name of temporary table to use in copy mode  

> debug (0) [ 0 | 1 | 2 ] - debug level  

delay (1) - Integer specifying how long to wait for a 1-bit when using the
      timing channel. Normally this is automatically calculated by !calib  
			
dns_domain - Domain that is appended to data when initiating DNS requests. You should have access to traffic between the database server
             and the DNS server for the dns\_domain (either because you're
             running squeeza on the DNS server or because you're on the
             path between the victim and the DNS server.  

dns\_privs (high) [ high | medium | low ] - Specifies which injection string
          to use with the dns channel.
          - high : database user is sysadmin, and xp\_cmdshell is available
          - medium : database user is sysadmin, xp\_cmdshell is not available (we'll
            use xp\_getfiledetails as a reasonable substitute)
          - low : database user is unprivileged, use xp\_getfiledetails

dns\_server - IP address of your local machine. If 'dns\_privs' is 'high'
             then we can pass the address of our own DNS server to
             nslookup. Use this variable if dns_privs is high and works,
             the server can send UDP traffic directly to your
             machine.

headers[] - Additional HTTP headers to add to the request. Use this to add
            cookies etc. Usage permits multiple headers[] lines e.g.:

               headers[]=Cookie: qweqwewqeqweqweqwe
               headers[]=User-Agent: My squeeza
						
host - Used by the http module to send requests to a vulnerable web
       application.

http\_resp\_ok (200) - a comma-separated list of http response codes that
                     squeeza should consider OK, otherwise throw errors.
                     For instance, regular DNS and timing attacks only
                     consider 200s to be acceptable by 500s are returned by
                     the HTTP error channel as part of its operation.

lines\_per\_request (1) - Used by the DNS module to request multiple lines per
                        HTTP request. Experiment with setting higher if you
                        like.

method (post) [ post | get ] - http method to use

mssql\_channel (dns) [ dns | time | http ] - Decide at start-up which channel 
              to use.

mssql\_mode (cmd) [ cmd | copy | sql ] - Decide at start-up which mode to
           enter.

one\_range - used by the time channel to determine if a request's time is 
            to be treated as a 1-bit.

outlier\_weight - used by the time channel to discard outliers when
                 calibrating

port (80) - port on which the webserver is listening

prompt (sp-sq>) - used by the shell as a prompt

querystring - either POST or GET parameters for the vulnerable page.
              mark the injection point with X_X_X_X_X_X
              e.g.

                querystring=__VIEWSTATE=dDwtMTcxMDQzNTQyMDs7PtQR3aDGafqEYIzRv
                SwVTqrcmzY0&m_search=X_X_X_X_X_X&_ctl3=Search

request\_timeout (20) - user by various channels as a generic timeout

sql\_postfix - string that will complete the injection string. typically
              this would be a "--" (excluding the "")

sql\_prefix  - string that ends the sql statement immediately prior to
              squeeza's injection string. typically this might look like
							"';" (excluding the "")
						
ssl (off) [ on | off ] - determine whether ssl is needed

time_privs (high) [ high | low ] - this value is automatically selected for
              you, depending on the chosen mode

url - a path to the vulnerable page

zero\_range - used by the time channel to determine if a request's time is 
             to be treated as a 0-bit.

