Allowed TOOLS:  
BloodHound  
SharpHound  
PowerShell Empire  
Covenant   
Powerview  
Rubeus  
evil-winrm  
Responder (Poisoning and Spoofing is not allowed in the labs or on the exam)  
Crackmapexec  
Mimikatz  


# OSCP

Scanning:
enum.py IP  
reconmultiple.py IP IP IP  
nmap -p 445 -vv --script=smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-ms17-010.nse 10.10.10.10  
nmap -sV -sT -p445 --script vuln <ip>
nmap -sV -sT -p445 --script safe <ip>
nmap -sV -sT -p445 --script "vuln and safe" <ip>

Enumeraction:

Exploit:

File upload:
python2 -m SimpleHTTPServer ---80 Spins up a webserver in the directory you are located on port 80.  
python3 -m http.server --- 80 Spins up a python version 3.X web server in the directory you are located on port 80.  

#Privelage Escalation:
  ## Windows Privilege Escalation Guides:

Fuzzysecurity Windows Privilege Escalation Fundamentals: Shout out to fuzzysec for taking the time to write this because this is an amazing guide that will help you understand Privilege escalation techniques in Windows. http://www.fuzzysecurity.com/tutorials/16.html    
Pwnwiki Windows Privilege Escalation Commands: http://pwnwiki.io/#!privesc/windows/index.md    
Absolomb’s Security Blog: Windows Privilege Escalation Guide https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/    
Pentest.blog: Windows Privilege Escalation Methods for Pentesters https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/    
PayloadAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md  
SharpAllTheThings: https://github.com/N7WEra/SharpAllTheThings  
LOLBAS (Created by Oddvar Moe): https://lolbas-project.github.io/  

## Windows Privilege Escalation Tools:
JAWS (Created by 411Hall): A cool windows enumeration script written in PowerShell. https://github.com/411Hall/JAWS/commits?author=411Hall  
Windows Exploit Suggester Next Generation: https://github.com/bitsadmin/wesng  
Sherlock (Created by RastaMouse): Another cool PowerShell script that finds missing software patches for local privilege escalation techniques in Windows. https://github.com/rasta-mouse/Sherlock  
WinPeas: https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS  
Watson: https://github.com/rasta-mouse/Watson  
Seatbelt: https://github.com/GhostPack/Seatbelt  
Powerless: https://github.com/M4ximuss/Powerless  
Powerview: https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon  
  
## Token Manipulation:
Rotten Potato: https://github.com/breenmachine/RottenPotatoNG  
Juicy Potato: https://github.com/ohpe/juicy-potato  


Linux Privilege Escalation Guides: The only guide I probably ever used to help me understand privilege escalation techniques in Linux systems was from g0tmi1k post. This blog is a must that everyone should have for preparing for the OSCP in my opinion. You can find his guide here: https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/  

GTFOBins (I have to thank Ippsec for sharing this with me): Contains a curated list of Unix binaries that that have the ability to be exploited by an attacker to bypass local security restrictions on a Linux system. https://gtfobins.github.io/  

PayloadsAllTheThings Linux Priv Esc Guide: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md  
## Linux Privilege Escalation Tools:  

LinEnum: A great Linux privilege escalation checker that is still maintained by the guys at rebootuser.com. You can find there tool here: https://github.com/rebootuser/LinEnum  
Linux Exploit Suggester 2: https://github.com/jondonas/linux-exploit-suggester-2  
LinPEAS: [https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS]   

One thing that I will mention is if you want to practice your Linux privilege escalation, I highly recommend you take a look at Lin.Security vulnerable box created by in.security! The box was designed to help people understand how certain applications and service that are misconfigured can be easily abused by an attacker. This box really helped me improved my privilege escalation skills and techniques on Linux systems.  

Main Link: https://in.security/lin-security-practise-your-linux-privilege-escalation-foo/  
Backup: https://www.vulnhub.com/entry/linsecurity-1,244/    

privcheckerlinux.py    

## Offline Tools for Password Cracking:  
Hashcat: https://hashcat.net/hashcat/ Sample Hashes to test with Hashcat: https://hashcat.net/wiki/doku.php?id=example_hashes  
John the Ripper: https://www.openwall.com/john/  
Metasploit Unleashed using John the Ripper with Hashdump: https://www.offensive-security.com/metasploit-unleashed/john-ripper/   

## Online Tools for Password Cracking:  
THC Hydra: https://github.com/vanhauser-thc/thc-hydra  
Crowbar: https://github.com/galkan/crowbar  

## Wordlist generators:
Cewl: https://digi.ninja/projects/cewl.php  
Crunch: https://tools.kali.org/password-attacks/crunch  
Cupp (In Kali Linux): https://github.com/Mebus/cupp   

Tools to check the hash type:

Hash-Identifier: https://github.com/psypanda/hashID

## Tools to dump for hashes:
Mimikatz: https://github.com/gentilkiwi/mimikatz  
Mimipenguin: https://github.com/huntergregal/mimipenguin  
Pypykatz: https://github.com/skelsec/pypykatz  

# CHECK:
## Pentest Cheat sheet
https://github.com/21y4d/nmapAutomator  
https://sushant747.gitbooks.io/total-oscp-guide/content/port_scanning.html  
https://johnjhacking.com/blog/the-oscp-preperation-guide-2020/  
https://scund00r.com/all/oscp/2018/02/25/passing-oscp.html

## AD cheat sheet
https://github.com/Tib3rius/Active-Directory-Exploitation-Cheat-Sheet  
Kerberos  
Mimkiz
