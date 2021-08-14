import socket
import wmi
from datetime import datetime 
import pandas as pd
import numpy as np
import os
import zipfile


windows = wmi.WMI()
audit_computername = socket.gethostname()
audit_timestamp = datetime.now().strftime("%H:%M:%S")


# Zip entire dir and subfolders if necessary (sourced from https://stackoverflow.com/questions/1855095/how-to-create-a-zip-archive-of-a-directory)
def zipdir(path, ziph):
    # ziph is zipfile handle
    for root, dirs, files in os.walk(path):
        for file in files:
            ziph.write(os.path.join(root, file), 
                       os.path.relpath(os.path.join(root, file), 
                                       os.path.join(path, '..')))


# Collect all running processes from a computer, and return them as a CSV
def netProcMon():
    npmDF = pd.DataFrame(columns=['Computername', 'Audit_Date', 'Process', 'PID', 'Command'])
    for process in windows.Win32_Process():
        npmDF = npmDF.append('Computername', audit_computername,
                                'Audit_Date', audit_timestamp,
                                'Process', f"{process.Name}",
                                'PID', f"{process.ProcessId:<10}",
                                'Command', f"{process.CommandLine}")
    
    npmDF.to_csv("{}_netprocmon".format(audit_computername), encoding='utf-8', index=False)


# Collect all service binaries and details about each
def serviceBinaries():
    sbDF = pd.DataFrame(columns=['Computername', 'Audit_Date', 'Name', 'Description', 'Path', 'State'])
    for service in windows.Win32_Service():
        sbDF = sbDF.append('Computername', audit_computername,
                                'Audit_Date', audit_timestamp,
                                'Name', f"{service.DisplayName}",
                                'Description', f"{service.Description}",
                                'Path', f"{service.PathName}",
                                'State', f"{service.State}")

    sbDF.to_csv("{}_services".format(audit_computername), encoding='utf-8', index=False)


# Collect all nics and their configuration
def networkCards():
    nicDF = pd.DataFrame(columns=['Computername', 'Audit_Date', 'MAC', 'IP', 'Subnet', 'DHCP', 'Service'])
    for conn in windows.Win32_NetworkAdapterConfiguration():
        nicDF = nicDF.append('Computername', audit_computername,
                                'Audit_Date', audit_timestamp,
                                'MAC', f"{conn.MACAddress}",
                                'IP', f"{conn.IPAddress[0]}",
                                'Subnet', f"{conn.IPSubnet[0]}",
                                'DHCP', f"{conn.DHCPEnabled}",
                                'Service', f"{conn.ServiceName}")

    nicDF.to_csv("{}_nic".format(audit_computername), encoding='utf-8', index=False)


# Collect DNS records from Windows commandline
def dnsCache():
    dns = os.popen('ipconfig /displaydns')
    name = []
    record = []
    for line in dns.read():
        if 'Record Name' in line:
            divided = line.split()
            name.append(divided[len(divided) - 1])

        if 'Record  .' in line:
            divided = line.split()
            record.append(divided[len(divided) - 1])

    dnsDF = pd.DataFrame(columns=['Computername', 'Audit_Date', 'Name', 'Resolve'])
    for i in range[0, len(name) - 1]:
        dnsDF = dnsDF.append('Computername', audit_computername,
                                'Audit_Date', audit_timestamp,
                                'Name', f"{name[i]}",
                                'Resolve', f"{record[i]}")

    dnsDF.to_csv("{}_dns".format(audit_computername), encoding='utf-8', index=False)


# Collect active TCP connections via Windows commandline, filtering out dead/loopback connections
def netstat():
    netstat = os.popen('netstat -ano')
    local = []
    remote = []
    state = []
    pid = []
    for line in netstat.read():
        if 'TCP' in line and '[::]' not in line:
            divided = line.split()
            local = divided[1]
            remote = divided[2]
            state = divided[3]
            pid = divided[4]

    connDF = pd.DataFrame(columns=['Computername', 'Audit_Date', 'Local IP', 'Remote IP', 'State',  'PID'])
    for i in range[0, len(local) - 1]:
        connDF = connDF.append('Computername', audit_computername,
                                'Audit_Date', audit_timestamp,
                                'Local IP', f"{local[i]}",
                                'Remote IP', f"{remote[i]}",
                                'State', f"{state[i]}",
                                'PID', f"{pid[i]}")
                                
    connDF.to_csv("{}_netstat".format(audit_computername), encoding='utf-8', index=False)


# Create a working directory, run the process, and 
def main():
    owd = os.getcwd()
    os.mkdir(os.getcwd + "\\temp")
    os.chdir("\\temp")
    netProcMon()
    serviceBinaries()
    networkCards()
    dnsCache()
    os.chdir(owd)

    zipped = zipfile.ZipFile('f{audit_computername}.zip', 'w', zipfile.ZIP_DEFLATED)
    zipdir('\\temp', zipped)
    zipped.close()
    os.remove('\\temp')
