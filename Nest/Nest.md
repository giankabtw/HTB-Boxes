# About Nest
Nest is an easy difficulty Windows machine featuring an SMB server that permits guest access. The shares can be enumerated to gain credentials for a low privileged user. This user is found to have access to configuration files containing sensitive information. Another user&amp;amp;#039;s password is found through source code analysis, which is used to gain a foothold on the box. A custom service is found to be running, which is enumerated to find and decrypt Administrator credentials.


I started with a nmap scan:

```bash
nmap -p- --min-rate 1000 -T4 -sV -sC -oN full_tcp_scan.txt 10.129.149.247
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-07-22 13:39 CDT
Stats: 0:01:23 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 95.39% done; ETC: 13:40 (0:00:04 remaining)
Stats: 0:01:36 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 0.00% done
Stats: 0:01:43 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 50.00% done; ETC: 13:41 (0:00:16 remaining)
Stats: 0:03:29 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 50.00% done; ETC: 13:44 (0:02:03 remaining)
Nmap scan report for 10.129.149.247
Host is up (0.075s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
445/tcp  open  microsoft-ds?
4386/tcp open  unknown
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NULL, RPCCheck, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, X11Probe: 
|     Reporting Service V1.2
|   FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, RTSPRequest, SIPOptions: 
|     Reporting Service V1.2
|     Unrecognised command
|   Help: 
|     Reporting Service V1.2
|     This service allows users to run queries against databases using the legacy HQK format
|     AVAILABLE COMMANDS ---
|     LIST
|     SETDIR <Directory_Name>
|     RUNQUERY <Query_ID>
|     DEBUG <Password>
|_    HELP <Command>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port4386-TCP:V=7.94SVN%I=7%D=7/22%Time=687FDB2A%P=x86_64-pc-linux-gnu%r
SF:(NULL,21,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(Generic
SF:Lines,3A,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>\r\nUnrecogn
SF:ised\x20command\r\n>")%r(GetRequest,3A,"\r\nHQK\x20Reporting\x20Service
SF:\x20V1\.2\r\n\r\n>\r\nUnrecognised\x20command\r\n>")%r(HTTPOptions,3A,"
SF:\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>\r\nUnrecognised\x20co
SF:mmand\r\n>")%r(RTSPRequest,3A,"\r\nHQK\x20Reporting\x20Service\x20V1\.2
SF:\r\n\r\n>\r\nUnrecognised\x20command\r\n>")%r(RPCCheck,21,"\r\nHQK\x20R
SF:eporting\x20Service\x20V1\.2\r\n\r\n>")%r(DNSVersionBindReqTCP,21,"\r\n
SF:HQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(DNSStatusRequestTCP,2
SF:1,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(Help,F2,"\r\nH
SF:QK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>\r\nThis\x20service\x20allo
SF:ws\x20users\x20to\x20run\x20queries\x20against\x20databases\x20using\x2
SF:0the\x20legacy\x20HQK\x20format\r\n\r\n---\x20AVAILABLE\x20COMMANDS\x20
SF:---\r\n\r\nLIST\r\nSETDIR\x20<Directory_Name>\r\nRUNQUERY\x20<Query_ID>
SF:\r\nDEBUG\x20<Password>\r\nHELP\x20<Command>\r\n>")%r(SSLSessionReq,21,
SF:"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(TerminalServerCo
SF:okie,21,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(TLSSessi
SF:onReq,21,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(Kerbero
SF:s,21,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(SMBProgNeg,
SF:21,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(X11Probe,21,"
SF:\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(FourOhFourRequest
SF:,3A,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>\r\nUnrecognised\
SF:x20command\r\n>")%r(LPDString,21,"\r\nHQK\x20Reporting\x20Service\x20V1
SF:\.2\r\n\r\n>")%r(LDAPSearchReq,21,"\r\nHQK\x20Reporting\x20Service\x20V
SF:1\.2\r\n\r\n>")%r(LDAPBindReq,21,"\r\nHQK\x20Reporting\x20Service\x20V1
SF:\.2\r\n\r\n>")%r(SIPOptions,3A,"\r\nHQK\x20Reporting\x20Service\x20V1\.
SF:2\r\n\r\n>\r\nUnrecognised\x20command\r\n>")%r(LANDesk-RC,21,"\r\nHQK\x
SF:20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(TerminalServer,21,"\r\nHQK
SF:\x20Reporting\x20Service\x20V1\.2\r\n\r\n>");

Host script results:
| smb2-time: 
|   date: 2025-07-22T18:43:20
|_  start_date: 2025-07-22T18:34:33
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

```


I performed another scan targetting port 4386

```bash
nmap -p4386 -sVC 10.129.149.247

```

```bash
smbclient -N -L //10.129.149.154

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	Data            Disk      
	IPC$            IPC       Remote IPC
	Secure$         Disk      
	Users           Disk      
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.129.149.154 failed (Error NT_STATUS_IO_TIMEOUT)
Unable to connect with SMB1 -- no workgroup available
```
```bash
smbclient //10.129.149.154/Data 
Password for [WORKGROUP\mendozgi]:
Try "help" to get a list of possible commands.
smb: \> help
?              allinfo        altname        archive        backup         
blocksize      cancel         case_sensitive cd             chmod          
chown          close          del            deltree        dir            
du             echo           exit           get            getfacl        
geteas         hardlink       help           history        iosize         
lcd            link           lock           lowercase      ls             
l              mask           md             mget           mkdir          
more           mput           newer          notify         open           
posix          posix_encrypt  posix_open     posix_mkdir    posix_rmdir    
posix_unlink   posix_whoami   print          prompt         put            
pwd            q              queue          quit           readlink       
rd             recurse        reget          rename         reput          
rm             rmdir          showacls       setea          setmode        
scopy          stat           symlink        tar            tarmode        
timeout        translate      unlock         volume         vuid           
wdel           logon          listconnect    showconnect    tcon           
tdis           tid            utimes         logoff         ..             
!              
smb: \> dir
  .                                   D        0  Wed Aug  7 17:53:46 2019
  ..                                  D        0  Wed Aug  7 17:53:46 2019
  IT                                  D        0  Wed Aug  7 17:58:07 2019
  Production                          D        0  Mon Aug  5 16:53:38 2019
  Reports                             D        0  Mon Aug  5 16:53:44 2019
  Shared                              D        0  Wed Aug  7 14:07:51 2019

```

```bash
smb: \Shared\> cd Maintenance 
smb: \Shared\Maintenance\> ls
  .                                   D        0  Wed Aug  7 14:07:32 2019
  ..                                  D        0  Wed Aug  7 14:07:32 2019
  Maintenance Alerts.txt              A       48  Mon Aug  5 18:01:44 2019
```


```bash
smb: \Shared\Templates\HR\> ls
  .                                   D        0  Wed Aug  7 14:08:01 2019
  ..                                  D        0  Wed Aug  7 14:08:01 2019
  Welcome Email.txt                   A      425  Wed Aug  7 17:55:36 2019

		5242623 blocks of size 4096. 1840743 blocks available
smb: \Shared\Templates\HR\> get "Welcome Email.txt"
getting file \Shared\Templates\HR\Welcome Email.txt of size 425 as Welcome Email.txt (1.4 KiloBytes/sec) (average 0.8 KiloBytes/sec)
```

```bash
smbclient //10.129.149.154/Users 
Password for [WORKGROUP\mendozgi]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Jan 25 17:04:21 2020
  ..                                  D        0  Sat Jan 25 17:04:21 2020
  Administrator                       D        0  Fri Aug  9 10:08:23 2019
  C.Smith                             D        0  Sun Jan 26 01:21:44 2020
  L.Frost                             D        0  Thu Aug  8 12:03:01 2019
  R.Thompson                          D        0  Thu Aug  8 12:02:50 2019
  TempUser                            D        0  Wed Aug  7 17:55:56 2019

```

All of the users gave an access denied : NT_STATUS_ACCESS_DENIED listing

```bash
 cat 'Welcome Email.txt'
We would like to extend a warm welcome to our newest member of staff, <FIRSTNAME> <SURNAME>

You will find your home folder in the following location: 
\\HTB-NEST\Users\<USERNAME>

If you have any issues accessing specific services or workstations, please inform the 
IT department and use the credentials below until all systems have been set up for you.

Username: TempUser
Password: welcome2019


Thank you
HR
```
