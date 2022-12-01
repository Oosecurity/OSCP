#!/usr/bin/env python
import subprocess
import sys
import os
import multiprocessing
import socket


class Bcolors:
    """This Class is used to modify the output colors
    """
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    ENDC = '\033[0m'


def usage():
    """Usage function, show program help banner
    """
    print(Bcolors.HEADER)
    print("------------------------------------------------------------")
    print("!!!!                      ENUM SCRIPT                  !!!!!")
    print("!!!!            A multi-process service scanner        !!!!!")
    print("!!!!             ftp, ssh, pop3, imap, smb, http,      !!!!!")
    print("!!!!                         https                     !!!!!")
    print("------------------------------------------------------------")

    print("")
    print("Usage: python enum_script.py <ip>")
    print("Example: python enum_script.py 192.168.1.101")
    print("")
    print("############################################################")
    print(Bcolors.ENDC)


def multi_proc(function, scan_ip, port):
    """Create a thread for each function call
    :param function:
    :param scan_ip:
    :param port:
    """
    jobs = []
    p = multiprocessing.Process(target=function, args=(scan_ip, port))
    jobs.append(p)
    p.start()


def banner_grabber(scan_ip, port):
    """Connect to a remote port and return its banner
    :param scan_ip:
    :param port:
    :return banner:
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((scan_ip, int(port)))
    banner = s.recv(1024)
    return banner


def pop3_scan(scan_ip, port):
    """Function used to scan the POP3 service
    :param scan_ip:
    :param port:
    """
    # Getting POP3 Banner and insert the results in the template file
    print(Bcolors.HEADER + "INFO[*]: Getting POP Banner..." + Bcolors.ENDC)
    banner = banner_grabber(scan_ip, port)
    print(Bcolors.OKBLUE + "INFO[*]: Inserting POP3 Banner in " + template_file + Bcolors.ENDC)
    subprocess.check_output("replace INSERTPOP3BANNER \"" + banner.decode() + "\"  -- " + template_file, shell=True)
    # Start NMAP NSE scripts for POP3 and insert the results in the template file
    print(Bcolors.HEADER + "INFO[*]: Starting NSE scripts for POP3..." + Bcolors.ENDC)
    pop_nse_scan = subprocess.check_output("nmap -p "
                                           + port + " --script=pop3-capabilities.nse,pop3-ntlm-info.nse"
                                           + scan_ip + " -oN " + report_directory + "nse_pop." + scan_ip, shell=True)
    print(Bcolors.OKBLUE + "INFO[*]: Inserting NSE results for POP3 in " + template_file + Bcolors.ENDC)
    subprocess.check_output("replace INSERTPOP3SCAN \"" + pop_nse_scan.decode() + "\"  -- " + template_file, shell=True)


def imap_scan(scan_ip, port):
    """Function used to scan the IMAP service
    :param scan_ip:
    :param port:
    """
    # Get the IMAP banner and insert the results in the template file
    print(Bcolors.HEADER + "INFO[*]: Getting IMAP Banner..." + Bcolors.ENDC)
    banner = banner_grabber(scan_ip, port)
    print(Bcolors.OKBLUE + "INFO[*]: Inserting IMAP Banner in " + template_file + Bcolors.ENDC)
    subprocess.check_output("replace INSERTIMAPBANNER \"" + banner.decode() + "\"  -- " + template_file, shell=True)
    # Start NMAP NSE scripts for IMAP and insert the results in the template file
    print(Bcolors.HEADER + "INFO[*]: Starting NSE scripts for IMAP..." + Bcolors.ENDC)
    imap_nse_scan = subprocess.check_output("nmap -p "
                                            + port + " --script=imap-capabilities.nse,imap-ntlm-info.nse"
                                            + scan_ip + " -oN " + report_directory + "nse_imap." + scan_ip, shell=True)
    print(Bcolors.OKBLUE + "INFO[*]: Inserting NSE results for IMAP in " + template_file + Bcolors.ENDC)
    subprocess.check_output("replace INSERTIMAPSCAN \"" + imap_nse_scan.decode() + "\"  -- " + template_file,
                            shell=True)


def smtp_scan(scan_ip, port):
    """Function used to scan the SMTP service
    :param scan_ip:
    :param port:
    :return:
    """
    # Get the SMTP banner and insert the results in the template file
    print(Bcolors.HEADER + "INFO[*]: Getting SMTP Banner..." + Bcolors.ENDC)
    banner = banner_grabber(scan_ip, port)
    print(Bcolors.OKBLUE + "INFO[*]: Inserting SMTP Banner in " + template_file + Bcolors.ENDC)
    subprocess.check_output("replace INSERTSMTPBANNER \"" + banner.decode() + "\"  -- " + template_file, shell=True)

    # Start the NSE scripts for SMTP and insert the results in the template file
    print(Bcolors.HEADER + "INFO[*]: Starting NSE scripts for SMTP..." + Bcolors.ENDC)
    smtp_nse_scan = subprocess.check_output("nmap -p " + port
                                            + " --script=smtp-commands.nse,smtp-ntlm-info.nse,smtp-open-relay.nse,smtp-vuln-cve2010-4344.nse,smtp-vuln-cve2011-1720.nse,smtp-vuln-cve2011-1764.nse "
                                            + scan_ip + " -oN " + report_directory + "nse_smtp." + scan_ip, shell=True)
    print(Bcolors.OKBLUE + "INFO[*]: Inserting NSE results for SMTP in " + template_file + Bcolors.ENDC)
    subprocess.check_output("replace INSERTSMTPSCAN \"" + smtp_nse_scan.decode() + "\"  -- " + template_file,
                            shell=True)


def http_scan(scan_ip, port):
    """Function used to scan the HTTP/HTTPS services using Nikto
    :param scan_ip:
    :param port:
    """
    print(Bcolors.HEADER + "INFO[*]: Starting the nikto scanner for http://" + scan_ip + ":" + port + Bcolors.ENDC)
    subprocess.check_output("nikto -host http://" + scan_ip + ":" + port + "/ -output " + report_directory + "nikto."
                            + scan_ip + ":" + port + ".txt", shell=True)


def smb_scan(scan_ip, port):
    """Enumerate the SMB/SAMBA service
    :param scan_ip:
    :param port:
    """
    # Start the NBTSCAN process and insert the results in the template file
    print(Bcolors.HEADER + "INFO[*]: Getting NetBIOS name..." + Bcolors.ENDC)
    nbtscan = subprocess.check_output("nbtscan -v " + scan_ip, shell=True)
    print (Bcolors.OKBLUE + "INFO[*]: Inserting NBTSCAN in " + template_file + Bcolors.ENDC)
    subprocess.check_output("replace INSERTNBTSCAN \"" + nbtscan.decode() + "\"  -- " + template_file, shell=True)

    # Start the SMBMAP process and insert the results in the template file
    print(Bcolors.HEADER + "INFO[*]: Listing SMB Shares..." + Bcolors.ENDC)
    smbmap = subprocess.check_output("smbmap -H " + scan_ip, shell=True)
    print (Bcolors.OKBLUE + "INFO[*]: Inserting SMBSCAN results in " + template_file + Bcolors.ENDC)
    subprocess.check_output("replace INSERTSMBMAP \"" + smbmap.decode() + "\"  -- " + template_file, shell=True)

    # Start NMAP NSE scripts for SMB and insert the results in the template file
    print(Bcolors.HEADER + "INFO[*]: Starting NSE scripts..." + Bcolors.ENDC)
    smb_nse_scan = subprocess.check_output("nmap -p " + port
                                           + " --script=smb2-capabilities.nse,smb2-security-mode.nse,smb2-time.nse,smb2-vuln-uptime.nse,"
                                             "smb-double-pulsar-backdoor.nse,smb-enum-services.nse,smb-ls.nse,smb-mbenum.nse,smb-os-discovery.nse,"
                                             "smb-protocols.nse,smb-security-mode.nse,smb-vuln-ms17-010.nse "
                                           + scan_ip + " -oN " + report_directory + "nse_smb." + scan_ip, shell=True)
    print (Bcolors.OKBLUE + "INFO[*]: Inserting NSE Scripts results in " + template_file + Bcolors.ENDC)
    subprocess.check_output("replace INSERTSMBNSE \"" + smb_nse_scan.decode() + "\"  -- " + template_file, shell=True)

    # Start Enum4Linux Script and insert the results in the template file
    print(Bcolors.HEADER + "INFO[*]: Starting Enum4Linux..." + Bcolors.ENDC)
    enum4linux = subprocess.check_output("enum4linux -a " + scan_ip + " 2> /dev/null", shell=True)
    print (Bcolors.OKBLUE + "INFO[*]: Inserting Enum4Linux results in " + template_file + Bcolors.ENDC)
    subprocess.check_output("replace INSERTENUM4LINUX \"" + enum4linux.decode() + "\"  -- " + template_file, shell=True)


def ftp_scan(scan_ip, port):
    """Enumerate the FTP service
    :param scan_ip:
    :param port:
    """
    # Get the FTP banner and insert the results in the template file
    print(Bcolors.HEADER + "INFO[*]: Getting FTP Banner..." + Bcolors.ENDC)
    banner = banner_grabber(scan_ip, port)
    print(Bcolors.OKBLUE + "INFO[*]: Inserting FTP Banner in " + template_file + Bcolors.ENDC)
    subprocess.check_output("replace INSERTFTPBANNER \"" + banner.decode() + "\"  -- " + template_file, shell=True)

    # Start NMAP NSE scripts for FTP and insert the results in the template file
    print(Bcolors.HEADER + "INFO[*]: Starting NSE scripts for FTP..." + Bcolors.ENDC)
    ftp_nse_scan = subprocess.check_output("nmap -p " + port
                                           + " --script=ftp-anon.nse,ftp-bounce.nse,ftp-syst.nse,ftp-vuln-cve2010-4221.nse,tftp-enum.nse,ftp-libopie.nse "
                                           + scan_ip + " -oN " + report_directory + "nse_ftp." + scan_ip, shell=True)
    print(Bcolors.OKBLUE + "INFO[*]: Inserting NSE results for FTP in " + template_file + Bcolors.ENDC)
    subprocess.check_output("replace INSERTFTPSCAN \"" + ftp_nse_scan.decode() + "\"  -- " + template_file, shell=True)


def ssh_scan(scan_ip, port):
    """Enumerate the SSH service
    :param scan_ip:
    :param port:
    """
    # Get the SSH banner and insert the results in the template file
    print(Bcolors.HEADER + "INFO[*]: Getting SSH Banner..." + Bcolors.ENDC)
    banner = banner_grabber(scan_ip, port)
    print(Bcolors.OKBLUE + "INFO[*]: Inserting SSH Banner in " + template_file + Bcolors.ENDC)
    subprocess.check_output("replace INSERTSSHBANNER \"" + banner.decode() + "\"  -- " + template_file, shell=True)

    # Start NMAP NSE scripts for SSH and insert the results in the template file
    print(Bcolors.HEADER + "INFO[*]: Starting NSE scripts for SSH..." + Bcolors.ENDC)
    ssh_nse_scan = subprocess.check_output("nmap -p " + port
                                           + " --script=ssh2-enum-algos.nse,ssh-auth-methods.nse,ssh-hostkey.nse,ssh-run.nse,sshv1.nse "
                                           + scan_ip + " -oN " + report_directory + "nse_ssh." + scan_ip, shell=True)
    print(Bcolors.OKBLUE + "INFO[*]: Inserting NSE results for SSH in " + template_file + Bcolors.ENDC)
    subprocess.check_output("replace INSERTSSHSCAN \"" + ssh_nse_scan.decode() + "\"  -- " + template_file, shell=True)


def scan_function(scan_ip):
    """Start a UnicornScan then a NMAP scan on the remote IP (TCP only)
    It then call the function corresponding to the service
    """
    # Start the UnicornScan process
    print(Bcolors.HEADER + "INFO[*]: Starting UnicornScan on " + scan_ip + Bcolors.ENDC)
    subprocess.check_output("unicornscan " + scan_ip + ":0-150 -l " + report_directory + "unicornscan.log", shell=True)
    print(Bcolors.OKGREEN + "INFO[*]: UnicornScan finished on " + scan_ip + Bcolors.ENDC)

    # Write results to the template file
    print(Bcolors.OKBLUE + "INFO[*]: Writing results to " + template_file + Bcolors.ENDC)
    unicorn_scan = subprocess.check_output("cat " + report_directory + "unicornscan.log", shell=True)
    subprocess.check_output("replace UNICORNSCAN \"" + unicorn_scan.decode() + "\"  -- " + template_file, shell=True)

    # Get port from unicornscan.log file
    unicorn_scan_ports = subprocess.check_output("cat " + report_directory + "unicornscan.log"
                                                 + "| grep open | cut -d '[' -f2 | cut -d']' -f1 | sed 's/ //g' | tr '\n' ','",
                                                 shell=True)

    # Start the NMAP Scan
    print(Bcolors.HEADER + "INFO[*]: Starting NMAP scan on " + scan_ip + Bcolors.ENDC)
    nmap_scan = subprocess.check_output("nmap -sC -sV -O -p "
                                        + unicorn_scan_ports.decode() + " -oN " + report_directory + "nmap_scan.log " + scan_ip,
                                        shell=True)
    print(Bcolors.OKGREEN + "INFO[*]: NMAP scan finished on " + scan_ip + Bcolors.ENDC)
    # Print the results
    print(Bcolors.HEADER + "INFO[*]: Printing NMAP Scan results:" + Bcolors.ENDC)
    print(Bcolors.OKGREEN + nmap_scan.decode() + Bcolors.ENDC)
    # Write the results to the template file
    print(Bcolors.OKBLUE + "INFO[*]: Writing results to " + template_file + Bcolors.ENDC)
    subprocess.check_output("replace NMAPSCAN \"" + nmap_scan.decode() + "\"  -- " + template_file, shell=True)

    # Cast the "nmap_scan" variable from bytes to str
    nmap_scan = nmap_scan.decode()
    # The following code will parse the NMAP result
    # This will return the ports and services used
    lines = nmap_scan.split("\n")
    serv_dict = {}
    for line in lines:
        ports = []
        line = line.strip()
        if ("tcp" in line) and ("open" in line) and not ("Discovered" in line):
            while "  " in line:
                line = line.replace("  ", " ")
            linesplit = line.split(" ")
            service = linesplit[2]  # grab the service name

            port = line.split(" ")[0]  # grab the port/proto
            if service in serv_dict:
                ports = serv_dict[service]  # if the service is already in the dict, grab the port list

            ports.append(port)
            serv_dict[service] = ports  # add service to the dictionary along with the associated port(2)

    # Based on the services and ports
    # Start the related scan function
    for serv in serv_dict:
        ports = serv_dict[serv]
        if "ftp" in serv:
            for port in ports:
                multi_proc(ftp_scan, scan_ip, port.split("/")[0])
        elif "ssh" in serv:
            for port in ports:
                multi_proc(ssh_scan, scan_ip, port.split("/")[0])
        elif ("netbios-ssn" in serv) or ("microsoft-ds" in serv):
            for port in ports:
                multi_proc(smb_scan, scan_ip, port.split("/")[0])
        elif ("http" in serv) or ("https" in serv):
            for port in ports:
                multi_proc(http_scan, scan_ip, port.split("/")[0])
        elif "pop3" in serv:
            for port in ports:
                multi_proc(pop3_scan, scan_ip, port.split("/")[0])
        elif "imap" in serv:
            for port in ports:
                multi_proc(imap_scan, scan_ip, port.split("/")[0])
        elif "smtp" in serv:
            for port in ports:
                multi_proc(smtp_scan, scan_ip, port.split("/")[0])


if __name__ == "__main__":
    if len(sys.argv) < 2:
        usage()
        sys.exit()

    # IP Address to scan
    ip_address = sys.argv[1]

    # Initialize General Path variables
    share_folder = "/mnt/hgfs/share/"
    default_report_directory = share_folder + "reports/"
    default_template_directory = share_folder + "templates/"

    # Initialize IP_address scan folder variables
    report_directory = default_report_directory + ip_address + "/"
    template_file = report_directory + "template.md"

    # Check if the report directory exists
    if not os.path.exists(default_report_directory):
        # If not create one
        print(Bcolors.WARNING + "INFO[*]: No directory report found" + Bcolors.ENDC)
        print(Bcolors.OKGREEN + "INFO[*]: Creating one..." + Bcolors.ENDC)
        os.makedirs(default_report_directory)
        dirs = os.listdir(default_report_directory)
    else:
        dirs = os.listdir(default_report_directory)

    # check if the scan IP folder exists
    if ip_address not in dirs:
        # If not, create a new folder for the scan machine
        print(Bcolors.HEADER + "INFO[*]: No folder was found for " + ip_address + ". Creating a new folder." + Bcolors.ENDC)
        subprocess.check_output("mkdir " + report_directory, shell=True)
        print(Bcolors.OKGREEN + "INFO[*]: Folder created here: " + report_directory + Bcolors.ENDC)

        # Create a new template file to the newly created directory
        print(Bcolors.OKGREEN + "INFO[*]: Adding template file to: " + report_directory + Bcolors.ENDC)
        subprocess.check_output("cp " + default_template_directory + "template.md " + report_directory, shell=True)
        subprocess.check_output("sed -i -e s/IP_ADDRESS/" + ip_address + "/ " + template_file, shell=True)
    else:
        # If so, stop the program
        print(Bcolors.WARNING + "WARNING[*]: folder:" + report_directory + " already exists!!!" + Bcolors.ENDC)
        print(Bcolors.HEADER + "INFO[*]: stopping..." + Bcolors.ENDC)
        sys.exit()

    # Start the scan process
    scan_function(ip_address)
