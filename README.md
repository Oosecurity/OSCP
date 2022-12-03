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

Privelage Escalation:
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
