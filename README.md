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
privcheckerlinux.py


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
