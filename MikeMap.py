#!/usr/bin/env python3
import subprocess, os, sys
import re
import argparse
import pwd
from time import sleep
from threading import Thread
from colorama import Fore
from multiprocessing.pool import ThreadPool
import shutil
import socket

#TODO: Create some sort of comparison between full scan and quick scan! and no ping now, maybe hosts found with active ports? 
#TODO: Consider adding a --badsum check scan. This may be good to tell us if a firewall is detected! At least do this for external

# Takes an input .gnmap file and outputs the searchsploit data into the searchsploit dir
def searchSploit(targetFile, serv, path):
    searchsploitInput = targetFile + ".gnmap"
    searchsploitOutput = "{0}/{1}".format(path, serv)

    # Revert serv from \? to ?, it will break the split otherwise
    if re.findall('\?', serv):
        serv = serv[:-2] + "?"

    # Create our searchsploit query
    pattern = "open/tcp//" + serv + "//"
    
    try:
        with open(searchsploitInput, 'r') as f:
            for line in f:
                if re.search(pattern, line):
                    splitLine = line.split(pattern)
                    sploitQuery = splitLine[1]
                    # Remove the trailing /, doing it this way makes sure to get rid of all whitespace too
                    sploitQuery = sploitQuery.split("/")
                    sploitQuery = sploitQuery[0]

                    # Check for either null or /
                    if sploitQuery != "/" and sploitQuery != "":
                        output = subprocess.check_output(["searchsploit", sploitQuery], text=True)

                        # We need this so we can reconstruct it when we print it to a file
                        output = output.split("\n")
                        with open(searchsploitOutput, 'w') as f:
                            for line in output:
                                # Give useless variable to stop printing pointless stuff
                                _ = f.write(f"{line}\n")
        # Check if searchsploit found anything interesting. If not, then delete the file.
        if os.path.isfile(searchsploitOutput):
            f = open(searchsploitOutput, 'r')
            sploitLines = f.readlines()
            if "Exploits: No Results\n" in sploitLines and "Shellcodes: No Results\n" in sploitLines:
                os.remove(searchsploitOutput)
    except Exception as e:
        print(f'Searchsploit enumeration failed... Exception: {e}')
        


def msfDatabase(nmapPath):
    
    # If workspace wasn't defined, set workspace named called techguard
    if msfWorkspace == None:
        workspace = "hellothere"
    else:
        workspace = msfWorkspace

    # Create file to create workspace and import XML
    f = open("workspace.rc", "w")
    f.write("workspace -a " + workspace + "\ndb_import " + nmapPath + ".xml\nexit")
    f.close()

    print(Fore.YELLOW + "\nImporting nmap to Metasploit Database.\r" + Fore.RESET)
    # Starts the database
    subprocess.call(["msfdb", "init"], stdout=subprocess.DEVNULL)
    # Create the workspace
    subprocess.call(["msfconsole", "-q", "-r", "workspace.rc"], stdout=subprocess.DEVNULL)
    subprocess.call(["rm", "workspace.rc"], stdout=subprocess.DEVNULL)

# Returns when a digit is found in the name of the directory. It also checks if it is one of the .lst files.
def listFileCheck(val):
    for char in val:
        if char.isdigit():
            return True

def scan(nmapTargets, scanType, excludeHostAddress):
    try:
        scanHomePath, servWeirdPath, servCommonPath, servDcPath, searchSploitPath, \
        serviceListPath, fullHostPath, eternalBluePath, nmapPath, httpPath = createSubDirectories(scanType)
        
        # nmapTargets is the path to the target's file we had the user enter at the start of the script
        if scanType == "quickScan":
            currentScanNmapPath = nmapPath
            nmapOutput = currentScanNmapPath + "/" + scanType
            # Put to a variable to keep it from outputting the return code to stdout
            if verbose:
                _ = subprocess.call(["nmap", "-sS", "-T4", "-oA", nmapOutput, "-iL", nmapTargets, "--exclude", excludeHostAddress, "-v"])
            else:
                _ = subprocess.call(["nmap", "-sS", "-T4", "-oA", nmapOutput, "-iL", nmapTargets, "--exclude", excludeHostAddress], stdout=subprocess.DEVNULL)
            checkForEternalBlue = True

        elif scanType == "fullScan":
            currentScanNmapPath = nmapPath
            nmapOutput = currentScanNmapPath + "/" + scanType
            # Put to a variable to keep it from outputting the return code to stdout
            if verbose:
                _ = subprocess.call(["nmap", "--host-timeout", "420m", "-sSV", "-T4", "-p-", "--exclude", excludeHostAddress, "-oA", nmapOutput, "-iL", nmapTargets, "-v"])
            else:
                _ = subprocess.call(["nmap", "--host-timeout", "420m", "-sSV", "-T4", "-p-", "--exclude", excludeHostAddress, "-oA", nmapOutput, "-iL", nmapTargets], stdout=subprocess.DEVNULL)
            checkForEternalBlue = False

        elif scanType == "noPingScan":
            currentScanNmapPath = nmapPath
            nmapOutput = currentScanNmapPath + "/" + scanType
            # Put to a variable to keep it from outputting the return code to stdout
            if verbose:
                _ = subprocess.call(["nmap", "-sS", "-F", "-T4", "-Pn", "-oA", nmapOutput, "-iL", nmapTargets, "--exclude", excludeHostAddress, "-v"])
            else:
                _ = subprocess.call(["nmap", "-sS", "-F", "-T4", "-Pn", "-oA", nmapOutput, "-iL", nmapTargets, "--exclude", excludeHostAddress], stdout=subprocess.DEVNULL)
            checkForEternalBlue = False

        elif scanType == "udpScan":
            currentScanNmapPath = nmapPath
            nmapOutput = currentScanNmapPath + "/" + scanType
            if verbose:
                subprocess.call(["nmap", "-sUV", "-F", "-T4", "--version-intensity", "0", "--min-hostgroup", "200", "-oA", nmapOutput, "-iL", nmapTargets, "--exclude", excludeHostAddress, "-v"],\
                            stderr=subprocess.DEVNULL)
            else:
                subprocess.call(["nmap", "-sUV", "-F", "-T4", "--version-intensity", "0", "--min-hostgroup", "200", "-oA", nmapOutput, "-iL", nmapTargets, "--exclude", excludeHostAddress],\
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            checkForEternalBlue = False
        
        elif scanType == "externalScan":
            currentScanNmapPath = nmapPath
            nmapOutput = currentScanNmapPath + "/" + scanType
            if verbose:
                _ = subprocess.call(["nmap", "--host-timeout", "420m", "-sSV", "-T4", "-p-", "-Pn", "-oA", nmapOutput, "-iL", nmapTargets, "-v"])
            else:
                #_ = subprocess.call(["nmap", "--host-timeout", "420m", "-sSV", "-T4", "-p-", "-Pn", "-oA", nmapOutput, "-iL", nmapTargets, "--resolve-all"], stdout=subprocess.DEVNULL)
                _ = subprocess.call(["nmap", "--host-timeout", "600m", "-sSV", "-T4", "-p-", "-Pn", "-oA", nmapOutput, "-iL", nmapTargets], stdout=subprocess.DEVNULL)
            checkForEternalBlue = False

        # File names
        scanNmap = nmapOutput + ".nmap"
        scanNmapPath = scanType + ".gnmap"
        servicesListName = "allServices.txt"
        dcListName = "DC.lst"
        eternalBlueFile = "eternalBlue"

        # Create allServices.lst. This contains all services that were found in the base scan
        scanFile = open(scanNmap, "r")
        pattern = "open"
        serviceList = []
        for line in scanFile:
            if re.search(pattern, line):
                splitLine = line.split()
                # Filter for any lines that are not default output, continue if it exists
                if len(splitLine) < 2:
                    continue
                # Tries to get rid of any false matches
                if splitLine[1] == "open":
                    portNumber = splitLine[0].split('/')
                    # We want to sort so we turn portnumber into an int
                    addLine = int(portNumber[0]),splitLine[2]
                    serviceList.insert(1, addLine)

        # The next few snippets of code sort the output of nmap, prints only unique, active ports into a txt file
        def sortFirst(val):
            return val[0]
        serviceList = [*set(serviceList)]
        serviceList.sort(key=sortFirst)

        newList = []
        # This makes the output look better
        for line in serviceList:
            newLine = "{0}  {1}".format(line[0], line[1])
            newList.append(newLine)

        # Create the service list file
        with open(f"{scanHomePath}/{servicesListName}", 'w') as f:
            for line in newList:
                f.write(f"{line}\n")

        #######################################
        # Create the IP list for all services #
        #######################################

        servicesFile = open(f"{scanHomePath}/{servicesListName}", "r")
        for line in servicesFile:
            splitLine = line.split()
            port = splitLine[0]
            serv = splitLine[1]

            # We do not want any list of RPC or UNKNOWN since they are both useless and numerous. Continue if that is the service. Although we want 1 msrpc if port 135
            skipServ = ['msrpc','unknown','ssl/unknown']
            if serv in skipServ:
                if port != 135:
                    continue
            # Remove some useless ports
            skipPorts = ['139','3268','3269','111']
            if port in skipPorts:
                continue

            # Checking if it has a ? in the service, we will need to escape it. The question mark will always be at the end
            if re.findall('\?', serv):
                # I am too stupid to try to do this with regex, so we will just remove the ? and add it back with \?. 
                # Future Me: Regex would be $? but its working so who cares
                serv = serv[:-1] + "\?"

            gnmapServ = None
            # Check if SSL is in the serv name, gnmap replaces the / in the serv with a |, so we need to accomdiate this bs
            if re.findall('\/', serv):
                gnmapServ = serv.replace("/", "|")

            if scanType == "udpScan":
                if gnmapServ is not None:
                    pattern = f" {port}/open/udp//{gnmapServ}/"
                else:
                    pattern = f" {port}/open/udp//{serv}/"
            else:
                if gnmapServ is not None:
                    pattern = f" {port}/open/tcp//{gnmapServ}/"
                else:
                    pattern = f" {port}/open/tcp//{serv}/"
            currentServList = []
            gmapFilePath = currentScanNmapPath + '/' + scanNmapPath
            with open(gmapFilePath, "r") as f:
                for line in f:
                    if re.search(pattern, line):
                        addLine = line.split()
                        currentServList.append(addLine[1])
            # if SSL was in the name, it likely has a / which will break file creation
            if '/' in serv:
                fixedServ = serv.split('/')
                fileName = "{0}.{1}.txt".format(fixedServ[1],port)
                # Used in the HTTP checks a few lines down, hopefully this doesnt break anything
                serv = fixedServ[1]
            else:
                fileName = "{0}.{1}.txt".format(serv,port)
            # Ensure we are targeting the proper directory which is services/IP.lsts
            targetPath = "{0}/{1}".format(serviceListPath, fileName)
            with open(targetPath, 'a') as f:
                for line in currentServList:
                    f.write(f"{line}\n")

            # Copy http files to the http directory
            httpServs = ['http','https','http-proxy', 'http-alt', 'https-alt', 'https-proxy']
            # Sometimes the -sV will rename the service to something else, but its actually a webpage. SO we will also filter for any of these.
            httpPorts = ['80','443']
            # Remove unwanted ports, such as winrm
            badHttpPorts = ['47001', '5985']

            # If the port or service is in any of the ones we have defined, then save the file to the http_hosts directory
            if serv in httpServs or port in httpPorts:
                # Remove bad ports
                if port not in badHttpPorts:
                    httpFilePath = f"{httpPath}/{fileName}"
                    shutil.copyfile(targetPath, httpFilePath)
                    # Delete the HTTP file from service_hosts
                    os.remove(targetPath)

        #########################################################
        # Create the DC list and run nmap against those devices #
        #########################################################

        # Okay I know this is possibly the most ridiculous way to do this, the most nested bull shit you will ever see but it works so whatever.
        dcListFile = f"{servDcPath}/{dcListName}"
        servicesFiles = os.listdir(serviceListPath)
        confirmExists = False
        for file in servicesFiles:
            if '.636.' in file:
                fullFilePath = f"{serviceListPath}/{file}"
                with open(fullFilePath) as f1, open(dcListFile, 'w') as outputFile:
                    for line1 in f1:
                        for file2 in servicesFiles:
                            if ".88." in file2:
                                fullFile2Path = f"{serviceListPath}/{file2}"
                                with open(fullFile2Path) as f2:
                                    for line2 in f2:
                                        if line1 == line2:
                                            outputFile.write(line1)
                                            confirmExists = True
        dcNmapPath = f"{servDcPath}/dc"
        if confirmExists:
            subprocess.call(["nmap", "-sSVC", "-p-", "-O", "-oA", dcNmapPath, "-iL", dcListFile], stdout=subprocess.DEVNULL)

        if scanType == "quickScan" or scanType == "noPingScan":
            allFiles = os.listdir(serviceListPath) # service.hosts.lsts directory
            subprocess.call(["mkdir", servCommonPath])
            subprocess.call(["mkdir", servWeirdPath])
            for file in allFiles:
                fileList = file.split(".")
                serv = fileList[0]
                port = fileList[1]
                dontScan = ["unknown"]
                # It was originally port.serv, but keeping this stuff for now
                fileName = serv + "." + port
                if serv not in dontScan:
                    if listFileCheck(file):
                        # We now want to copy the file to the other folders for organization purposes
                        if int(port) in commonPorts or serv in commonServicesList:
                            origPath = f"{serviceListPath}/{file}"
                            copyPath = f"{servCommonPath}/{file}"
                            subprocess.call(["cp", origPath, copyPath])
                        # All other services will be put into the weird directory
                        else:
                            origPath = f"{serviceListPath}/{file}"
                            copyPath = f"{servWeirdPath}/{file}"
                            subprocess.call(["cp", origPath, copyPath])

        ###########################################################################################
        # Run nmap script scan against a service, and create the directories, AND do searchsploit #
        ###########################################################################################

        # We only want to run this stuff with the full/external scan so we have a more accurate scan.
        if scanType == "fullScan" or scanType == "externalScan":
            # If a file name has a number (port) then it puts them into a list. From this list we will run nmap scans again using -sSVC
            allFiles = os.listdir(serviceListPath) # service_hosts directory

            # Searchsploit services that should not run because they will fail/not return any information because to vague
            dontSploit = ["unknown"]
            # Unknown sucks
            dontScan = ["unknown"]
            if scanType == "fullScan":
                print(Fore.GREEN + "\nFull scan: Finished initial nmap scan.\r" + Fore.RESET)
                print(Fore.YELLOW + "\nFull Scan: Starting nmap script scans and searchsploit checks.\r" + Fore.RESET)
            else:
                print(Fore.GREEN + "\nFinished initial nmap scan.\r" + Fore.RESET)
                print(Fore.YELLOW + "\nStarting nmap script scans and searchsploit checks.\r" + Fore.RESET)
            # function that we will be multi-threading
            def nmapAndSearchSploit(file):
                # Creates a directory for each service, and outputs the nmap scan against the target port into that dir
                fileList = file.split(".")
                serv = fileList[0]
                port = fileList[1]

                # It was originally port.serv, but keeping this stuff for now
                fileName = serv + "." + port
                if serv not in dontScan:
                    if listFileCheck(file):
                        # We split up where the services will go here, depending on if the service port # is in the common ports list. 
                        # If it passes, the nmap information will be put into commonServices directory
                        if int(port) in commonPorts:
                            newDir = f"{servCommonPath}/{fileName}"
                            subprocess.call(["mkdir", newDir])
                            nmapFile = f"{newDir}/{serv}"
                            filePath = f"{serviceListPath}/{file}"
                            subprocess.call(["nmap", "-sSVC", "-oA", nmapFile, "-p", port, "-iL", filePath], stdout=subprocess.DEVNULL)
                            # Run searchsploit with the output if it is not unknown service
                            if serv not in dontSploit:
                                searchSploit(nmapFile, serv, searchSploitPath)
                            
                        # All other services will be put into the weird directory
                        else:
                            newDir = f"{servWeirdPath}/{fileName}"
                            subprocess.call(["mkdir", newDir])
                            nmapFile = f"{newDir}/{serv}"
                            filePath = f"{serviceListPath}/{file}"
                            subprocess.call(["nmap", "-sSVC", "-oA", nmapFile, "-p", port, "-iL", filePath], stdout=subprocess.DEVNULL)
                            # Run searchsploit with the output if it is not unknown service
                            if serv not in dontSploit:
                                searchSploit(nmapFile, serv, searchSploitPath)

            # Create thread pool, it will create a thread for each object in allFiles. 10 thread max at a time
            with ThreadPool(processes=10) as pool:
                pool.map(nmapAndSearchSploit, allFiles)

            ######################################################################
            # Creates the combined file for each host from the more verbose scan #
            ######################################################################

            # We need to check both weird and common ports
            commonServices = os.listdir(servCommonPath)
            commonServicesFiles = []
            weirdServices = os.listdir(servWeirdPath)
            weirdServicesFiles = []

            # Creating each individual input file and putting it into commonServicesFile, same for weird
            for i in commonServices:
                splitLine = i.split(".")
                service = splitLine[0]
                i = f"{servCommonPath}/{i}/{service}.nmap"
                commonServicesFiles.insert(0, i)
            for i in weirdServices:
                splitLine = i.split(".")
                service = splitLine[0]
                i = f"{servWeirdPath}/{i}/{service}.nmap"
                weirdServicesFiles.insert(0, i)

            totalFiles = commonServicesFiles + weirdServicesFiles

            # To easy allow subnets to be passed to the script, we need to get a full list of hosts found using nmap
            foundTargets = []
            newTargetsFile = open(gmapFilePath, 'r')
            newTargetsLines = newTargetsFile.readlines()
            for line in newTargetsLines:
                pattern = "/open/"
                if re.search(pattern, line):
                    addLine = line.split()
                    foundTargets.append(addLine[1])

            for target in foundTargets:
                host = target.strip()
                fullHostFile = f"{fullHostPath}/{host}"
                fileContents = []
                for file in totalFiles:
                    with open(file) as inFile:
                        copy = False
                        for line in inFile:
                            # If host is in a line that contains Nmap scan report for, it will copy all following lines until the next Nmap scan report for line is found
                            if host in line.strip() and "Nmap scan report for" in line.strip():
                                copy = True
                                continue
                            elif "Nmap scan report for" in line.strip():
                                copy = False
                                continue
                            elif copy:
                                fileContents.append(line)
                with open(fullHostFile, 'w') as outFile:
                    outFile.write("###############################\n")
                    outFile.write("Host: {0}\n".format(host))
                    outFile.write("###############################\n")
                    # Remove all lines that have the following data in them
                    rmLine1 = 'Host is up'
                    rmLine2 = 'PORT'
                    for line in fileContents:
                        if rmLine1 not in line and rmLine2 not in line:
                            outFile.write(line)

        if checkForEternalBlue == True:
            eternalBlueCheck(eternalBluePath, eternalBlueFile, serviceListPath)
        # Changing permisions so sudoers can R/W
        subprocess.call(['chown', '-R', 'root:sudo', scanHomePath])
        subprocess.call(['chmod', '-R', '660', scanHomePath])
        # Need to add execute back to directories because they are otherwise broken
        subprocess.call(['chmod', '+X', '-R', scanHomePath])
        
        # Cleanup empty directories
        cleanupPaths = [servDcPath, servCommonPath, servWeirdPath, eternalBluePath, searchSploitPath]
        for path in cleanupPaths:
            # Confirm the dir exists cause im to lazy to do this for each scan
            if os.path.isdir(path):
                checkDir = os.listdir(path)
                if len(checkDir) == 0:
                    os.rmdir(path)

        if scanType == "quickScan":
            print(Fore.GREEN + "\nThe quick scan has finished! Check it out at {0}\r".format(scanHomePath))
            print(Fore.YELLOW + "\nThe full scan is still running, it will take significantly longer than the quick scan.\r" + Fore.RESET)
        elif scanType == "fullScan":
            # Ingest the nmap xml file into msf database. I do it here because it really fucks with stdout for some reason
            msfDatabase(nmapOutput)
            print(Fore.GREEN + f"\nThe full scan has finished. Check it out at {scanHomePath}\r" + Fore.RESET)
        elif scanType == "noPingScan":
            print(Fore.GREEN + f"\nThe no ping scan has finished. Check it out at {scanHomePath}\r" + Fore.RESET)
        elif scanType == "udpScan":
            print(Fore.GREEN + f"\nThe UDP scan has finished. Check it out at {scanHomePath}\r" + Fore.RESET)
        elif scanType == "externalScan":
            print(Fore.GREEN + f"\nThe External scan has finished. Check it out at {scanHomePath}\r" + Fore.RESET)
    except KeyboardInterrupt:
        quit()

def createCombinedLists():

    # Get all service hosts files
    noPingServices = os.listdir(f"{scriptHomeDir}/noPingScan/service_hosts")
    quickScanServices = os.listdir(f"{scriptHomeDir}/quickScan/service_hosts")
    fullScanServices = os.listdir(f"{scriptHomeDir}/fullScan/service_hosts")

    # Create a list of all hosts that were found in the noPing scan but not in the quick scan
    allNoPingHosts = []
    allQuickHosts = []
    for file in noPingServices:
        # Set full file path
        file = f"{scriptHomeDir}/noPingScan/service_hosts/{file}"
        f = open(file, 'r')
        allNoPingHosts += f.readlines()
    for file in quickScanServices:
        file = f"{scriptHomeDir}/quickScan/service_hosts/{file}"
        f = open(file, 'r')
        allQuickHosts += f.readlines()
    # Make the two lists unique
    uniqNoPing = set(allNoPingHosts)
    uniqQuick = set(allQuickHosts)
    missingHosts = [host for host in uniqNoPing if host not in uniqQuick]
    # Only run if hosts were found
    if missingHosts:
        differentHostFile = f"{scriptHomeDir}/differentHosts"
        f = open(differentHostFile, 'w')
        f.write("These are the differences between quickScan and noPingScan.\n")
        for host in missingHosts:
            f.write(host)
        f.close()

    # Create full list of DCs using both full and quick scan
    quickDcListFile = f"{scriptHomeDir}/quickScan/dc/DC.lst"
    fullDcListFile = f"{scriptHomeDir}/fullScan/dc/DC.lst"
    # Confirm if either file exists
    if os.path.isfile(quickDcListFile) and os.path.isfile(fullDcListFile):
        quickFileData = open(quickDcListFile, 'r')
        quickDCs = quickFileData.readlines()
        fullFileData = open(fullDcListFile, 'r')
        fullDCs = fullFileData.readlines()
        # Combine the two lists and then remove any duplicates
        completeDCs = quickDCs + fullDCs
        completeDCs = set(completeDCs)
        # Write the file to the root
        completeFile = f"{scriptHomeDir}/dcs.txt"
        f = open(completeFile, 'w')
        for host in completeDCs:
            f.write(host)
        f.close()
    else:
        print(Fore.RED + "\nThere were no domain controllers found!!" + Fore.RESET)

    # Attempt at creating a list of all shared files and combining them if there are different hosts
    # Right now, many services will probably be off since the full scan will get the service name and may have a ? in it
    # We use quick scan's services because it will always have the basic services. Full scan will be the one with extra ones that quick wont have
    # Create the directory... idk how i forgot this initially
    differentServiceDir = f"{scriptHomeDir}/combinedServiceFiles"
    os.mkdir(differentServiceDir)
    for file in quickScanServices:
        if file in fullScanServices:
            quickFilePath = f"{scriptHomeDir}/quickScan/service_hosts/{file}"
            fullFilePath = f"{scriptHomeDir}/fullScan/service_hosts/{file}"
            quickFile = open(quickFilePath, 'r')
            fullFile = open(fullFilePath, 'r')
            quickHosts = quickFile.readlines()
            fullHosts = fullFile.readlines()
            # Check if a host in the quick scan file is not in the full scan
            missingHosts = [host for host in quickHosts if host not in fullHosts]
            # Do the same check, but reversed
            missingHosts += [host for host in fullHosts if host not in quickHosts]
            # Only create combined file if different hosts were found
            if missingHosts:
                print(f"There were differences in hosts for the quick/full scans for the {file} service. Creating a combined list at {differentServiceDir}/{file}")
                # Combine the two lists and remove any duplicates
                completeList = quickHosts + fullHosts
                completeList = set(completeList)
                differentServiceFile = f"{differentServiceDir}/{file}"
                f = open(differentServiceFile, 'w')
                for host in completeList:
                    f.write(host)
                f.close()

def createSubDirectories(scanType):
    # This is called each time a scan type has finished
    global fullEternalPath

    scanHomePath = f'{scriptHomeDir}/{scanType}'
    servWeirdPath = f'{scanHomePath}/weirdServices'
    servCommonPath = f'{scanHomePath}/commonServices'
    servDcPath = f'{scanHomePath}/dc'
    searchSploitPath = f"{scanHomePath}/searchsploit"
    serviceListPath = f"{scanHomePath}/service_hosts"
    fullHostPath = f"{scanHomePath}/Hosts"
    eternalBluePath = f"{scanHomePath}/eternalBlue"
    nmapPath = f"{scanHomePath}/nmap"
    httpPath = f"{scanHomePath}/http_hosts"

    # Create some directories 
    subprocess.call(["mkdir", scanHomePath, serviceListPath, nmapPath])

    # Write when directories are created
    if scanType == "quickScan":
        print(Fore.GREEN + "\nCreated the directories for the Quick Scan.\r" + Fore.RESET)
    elif scanType == "fullScan": 
        print(Fore.GREEN + "\nCreated the directories for the Full Scan.\r" + Fore.RESET)
    elif scanType == "udpScan":
        print(Fore.GREEN + "\nCreated the directories for the UDP Scan.\r" + Fore.RESET)
    elif scanType == "noPingScan":
        print(Fore.GREEN + "\nCreated the directories for the no ping Scan.\r" + Fore.RESET)
    elif scanType == "externalScan":
        print(Fore.GREEN + "\nCreated the directories for the External Scan.\r" + Fore.RESET)
    # Do not want DC directory in UDP dir or external
    if scanType != "udpScan" and scanType != "externalScan":
        subprocess.call(["mkdir", servDcPath])
    if scanType == "quickScan":
        subprocess.call(["mkdir", eternalBluePath])

    # Craete http folder for all scans besides udp scan
    if scanType != "udpScan":
        subprocess.call(["mkdir", httpPath])
    # Create other directories if it is a full scan
    if scanType == "fullScan" or scanType == "externalScan":
        # We need this variable later to copy the eternal blue directory, and this is the easiest way to get it :)
        fullEternalPath = eternalBluePath
        subprocess.call(["mkdir", searchSploitPath, servWeirdPath, servCommonPath, fullHostPath])

    return scanHomePath, servWeirdPath, servCommonPath, servDcPath, searchSploitPath, serviceListPath, fullHostPath, eternalBluePath, nmapPath, httpPath

def eternalBlueCheck(eternalBluePath, eternalBlueFile, serviceListPath):
    eternalTargets = serviceListPath + "/microsoft-ds.445.lst"
    eternalNmapOutput = eternalBluePath + "/" + eternalBlueFile
    print(Fore.YELLOW + "\nQuick Scan: Starting Eternalblue and other SMB vuln checks using nmap.\r" + Fore.RESET)
    subprocess.call(["nmap", "-oA", eternalNmapOutput, "-iL", eternalTargets, "-p445", "--script=smb-vuln*"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # copy the results to full scan
    subprocess.call(["cp", "-R", eternalBluePath, fullEternalPath])

def createDirectories(output):
    
    global scriptHomeDir
    
    # Checks and creates the directories if they do not exist, removes it first if it does
    if output is None:
        scriptHomeDir = 'MikeMap'
    else:
        scriptHomeDir = output
    if os.path.exists(scriptHomeDir):
        input(f"The target directory {scriptHomeDir} already exists. Press enter to delete it.")
        subprocess.call(["rm", "-rf", scriptHomeDir])
    # This will also create any parent directories if they do not already exist
    subprocess.call(["mkdir", "-p", scriptHomeDir])
    # Make it writeable by sudo users
    subprocess.call(["chown", "root:sudo", scriptHomeDir])
    subprocess.call(['chmod', '660', scriptHomeDir])
    subprocess.call(['chmod', '+x', scriptHomeDir])
    scriptHomeDir = os.path.abspath(scriptHomeDir)

def main():
    try:
        global commonPorts
        global commonServicesList
        global dcPorts
        global msfWorkspace
        global verbose
        # We need nopingscan to wait for quickscan to finish, so we will just make quick's thread global here
        global quickThread
        # Argument parser, requires targetsFile to be defined
        parser = argparse.ArgumentParser(
            description="Mike's nmap script. Cash money. P.S. You need to run this as root.",
            epilog="Awooooooo")
        parser.add_argument('targetsFile', help="File that contains the target IPs. This can be individual IPs, hostnames, or subnets.")
        parser.add_argument('-d', '--msfdb', help="Name for the MSF DB workspace. Default is hellothere.")
        parser.add_argument('-e', '--external', action="store_true", help="Scanning for external targets.")
        parser.add_argument('-o', '--output', help="Output directory. Default: MikeMap")
        parser.add_argument('-v', action="store_true", help="Verbose output of nmap scan.")
        # Makes sure at least one arguemnt exists
        if len(sys.argv)==0:
            parser.print_help(sys.stderr)
            sys.exit(1)
        
        args = parser.parse_args()
        targetFile = args.targetsFile
        msfWorkspace = args.msfdb
        externalScanActive = args.external
        output = args.output
        verbose = args.v

        # Confirming root is running the script, exit if not
        currentUser = pwd.getpwuid(os.getuid())[0]
        if currentUser != "root":
            print("You must run this script as root! Try again baka.")
            sys.exit()
        
        # Gets full path of file
        nmapTargets = os.path.abspath(targetFile)
        # Get full path to output
        if output is not None: output = os.path.abspath(output)
        createDirectories(output)

        # Get current IP so we can exlucde it from NMAP scans
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        excludeHostAddress = s.getsockname()[0]
        s.close()

        # 5800 is VNC HTTP, 515 is printer, 514 is shell (idk what that is but sounds interesting)
        commonPorts = 21,22,23,25,53,80,135,443,445,514,515,1433,2049,3306,3389,4000,5800,5985,5986,8000,8080,143,110
        # Very short list right now... mainly doing this if they are on non standard ports
        commonServicesList = ['http','ssh','telnet']
        dcPorts = 636,88

        # Scan Types. DO NOT CHANGE THESE NAMES. If you do, you will need to change the checks in scan()
        quickScan = "quickScan"
        fullScan = "fullScan"
        udpScan = "udpScan"
        noPingScan = "noPingScan"
        externalScan = "externalScan"
        # Note: All print statements the remainder of the script must end with a \r, or else the output will break. Something to do with raw stdout and stdin
        # Checks if external scan was used/is set to True
        if externalScanActive:
            exteranlThread = Thread(target=scan, args=(nmapTargets, externalScan, excludeHostAddress))
            exteranlThread.start()
        else:
            quickThread = Thread(target=scan, args=(nmapTargets, quickScan, excludeHostAddress))
            fullThread = Thread(target=scan, args=(nmapTargets, fullScan, excludeHostAddress))
            noPingThread = Thread(target=scan, args=(nmapTargets, noPingScan, excludeHostAddress))
            quickThread.start()
            fullThread.start()
            noPingThread.start()
            sleep(1)
            print(Fore.GREEN + "\nStarting the quick, full, no ping, and UDP scans.\r" + Fore.RESET)

        # All scan types use the same UDP scan
        udpThread = Thread(target=scan, args=(nmapTargets, udpScan, excludeHostAddress))
        udpThread.start()

        if externalScanActive:
            exteranlThread.join() 
            udpThread.join()
        else:
            # Wait for all scans to finish
            quickThread.join()
            fullThread.join()
            udpThread.join()
            noPingThread.join()
            # Create combined list files if there are differnces
            createCombinedLists()

        # Changing permisions so sudoers can R/W
        subprocess.call(['chown', '-R', 'root:sudo', scriptHomeDir])
        subprocess.call(['chmod', '-R', '660', scriptHomeDir])
        # Need to add execute back to directories because they are otherwise broken
        subprocess.call(['chmod', '+X', '-R', scriptHomeDir])

        print(Fore.GREEN + "\nThe script has finished.")
    except KeyboardInterrupt:
        print("\n\rOH MY GOD YOU STOPPED THE SCRIPT WTF DUDE. Exiting.")
        quit()
main()
