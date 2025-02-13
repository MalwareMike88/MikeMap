# MikeMap

This tool will run nmap against a list of IPs. The targets file can be an IP, hostname, or subnet.  

Target files will be generated. These target files will contain targets that have the same port and service open. I.e. if 192.168.0.2 and 192.168.0.3 both have 21/ftp open, then they will both be in the ftp.21.txt file in the service_hosts directory.

# Usage

`./MikeMap.py -h`  

**Run against file containing target IPs**

`./MikeMap.py ips.txt`  

**Run against external targets**

`./MikeMap.py -e ips.txt`

# Help Menu
```
-d, --msfdb MSFDB  Name for the MSF DB workspace. Default is hellothere.
-e, --external     Scanning for external targets.
-o, --output       Output directory. Default: MikeMap
-v                 Verbose output of nmap scan.
```

# Directories
*Note: Some scans will not have every directory*

**Nmap**: Contains the nmap scans.  
**service_hosts**: Contains target files for all services. **This is the most useful directory.**
**CommonServices**: Contains targets grouped by common services.  
**DC**: Contains nmap scans for just the domain controllers, and contains a list of domain controllers.  
**Searchsploit**: Contains searchsploit results for every service.  
**WeirdServices**: Contains all services that are not common services.  
**AllInfoHosts**: Contains -sVC information, seperated by host.  
**combinedServiceFiles**: Attempts to combine the Quick Scan and Full Scan results if there are any differences. This is a WIP.
