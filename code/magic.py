from ciscoconfparse import CiscoConfParse
import nmap3
import json
import configparser
from openpyxl import Workbook
from napalm import get_network_driver
import os
from types import SimpleNamespace
from pathlib import Path
from datetime import datetime
import ipaddress
import traceback
import concurrent.futures
from netmiko.ssh_autodetect import SSHDetect
from netmiko.ssh_dispatcher import ConnectHandler
import re
import logging


# TODO: Dump Device Data to json file for each device, generate tables using structured json data, move nmap


os.makedirs("./outputs/", exist_ok=True)

# TODO: If needed, open previous log file if exists and create append log

logging.basicConfig(filename='./outputs/log.txt', level=logging.WARNING, filemode='w' )


#Def Functions
def FetchNmapData(ipAddress):

    nmap = nmap3.Nmap()
    results = nmap.scan_top_ports(ipAddress)
    return results

def CreateNapalmConnection(ipAddress, driver, sshUserName, sshPassword):

    #NapalmConnection
    driver = get_network_driver(driver)
    device = driver(ipAddress, sshUserName, sshPassword)
    device.open()

    return device

def DeviceInfoFetchPipeline(ipAddress, username, password, timeout):

    swVersion = "unresolved"
    swVersionRegex = "\d+(?:\.\d+)+"

    napalmDriverName = None

    remote_device = {
        'device_type': 'autodetect',
        'host': ipAddress,
        'username': username,
        'password': password }

    guesser = SSHDetect(**remote_device)
    bestMatch = guesser.autodetect()

    #print(bestMatch) # Name of the best device_type to use further
    #print(guesser.potential_matches) # Dictionary of the whole matching result

    if bestMatch == None:
        remote_device['device_type'] = "cisco_s300"
        connection = ConnectHandler(**remote_device)

        commandOutput = connection.send_command('show version', expect_string="#")

        regexVersionMatches = re.findall(swVersionRegex, commandOutput)

        if regexVersionMatches: napalmDriverName = 's350'

        else: raise Exception(f'Unrecognized Device. Tried to resolve device as Cisco SMB! Show version command output: {commandOutput}, regexVersionMatches: {regexVersionMatches}')

        swVersion = regexVersionMatches[0]

        logging.warning(swVersion)

    elif "huawei" in bestMatch:
        remote_device['device_type'] = bestMatch
        connection = ConnectHandler(**remote_device)
        
        commandOutput = connection.send_command('display version')

        if "VRP (R) software," in commandOutput:
            

            vrpVersion = str(commandOutput.partition("Version ")[2][0])
            
            if vrpVersion == "5": napalmDriverName = 'huawei_vrp'
            elif vrpVersion == "8": napalmDriverName = 'ce'
            else: raise Exception("Unrecognized Device. Tried to resolve device as Huawei Vrp5 & Vrp8!")

        if napalmDriverName == None: raise Exception("Unrecognized Device. Tried to resolve device as Huawei Vrp5 & Vrp8!")

        regexVersionMatches = re.findall(swVersionRegex, commandOutput)

        if regexVersionMatches: swVersion = regexVersionMatches[0]


    elif "cisco" in bestMatch: napalmDriverName = "ios"

    connection = CreateNapalmConnection(ipAddress, napalmDriverName, username, password)

    # compatibility matrix switch
    napalmData = {
       "deviceConfig": str(connection.get_config()["running"]),
       "arpTable" : connection.get_arp_table(),
       "interfaces" : connection.get_interfaces(),
       "interfacesIp" : connection.get_interfaces_ip(),
       "lldpNeighbors" : connection.get_lldp_neighbors()}

    if not napalmDriverName == 's350':
        napalmData["macTable"] = connection.get_mac_address_table()
        napalmData["interfacesCounter"] = connection.get_interfaces_counters()
        napalmData["deviceUsers"] = connection.get_users()


    if napalmDriverName == "huawei_vrp":
        pass

    if napalmDriverName == "ce":
        pass

    if napalmDriverName == "ios":
        pass

    return {
        'ip': ipAddress,
        'napalmDriverName': napalmDriverName,
        'napalmData': napalmData,
        'nmapData': FetchNmapData(ipAddress),
        'swVersion': swVersion
    }   

# TODO: Remove column feature for is_enabled in interfaces
# TODO: Ensure order of columns
def CreateWorksheet(workBook, workSheetName, dataCollection):

    if not dataCollection:
        #todo: log
        return

    workSheet = workBook.create_sheet(workSheetName)
    workSheet.append(list(dataCollection[0].keys()))

    for data in dataCollection:
        workSheet.append(list(data.values()))
    
def ConvertDictInDictToDictInList(dataDictDict, newColumnName):

    listDict = []


    for key, valueDict in dataDictDict.items():

        #Vytvarime novy dict s key=newColumnName a value=parentKey (GigabitEthernet0/0/3)
        dict = { newColumnName: key }

        #Appendneme zbytek key value hodnot za nove vytvoreny dict
        dict.update(valueDict)

        #novy dict hoduime do listu, ktery reprezenetuje 2d tabulku
        listDict.append(dict)


    return listDict


def SaveDeviceDataAsWorkbook(napalmData, path):
    
    workBook = Workbook()

    if "macTable" in napalmData:
        CreateWorksheet(workBook, "macTable", napalmData["macTable"])

    if "arpTable" in napalmData:
        CreateWorksheet(workBook, "arpTable", napalmData["arpTable"])

    if "interfaces" in napalmData:
        interfacesData = ConvertDictInDictToDictInList(napalmData["interfaces"], "interface")
        CreateWorksheet(workBook, "interfaces", interfacesData)
    
    if "interfacesCounter" in napalmData:
        interfaceCountersData = ConvertDictInDictToDictInList(napalmData["interfacesCounter"], "interfacesCounter")
        CreateWorksheet(workBook, "interfacesCounter", interfaceCountersData)

    if "lldpNeighbors" in napalmData:
        lldppNeigbors = ConvertDictInDictToDictInList(napalmData["lldpNeighbors"], "interface")

        CreateWorksheet(workBook, "lldpNeighbors", lldppNeigbors)

    if "interfacesIp" in napalmData:
        interfacesIp = ConvertDictInDictToDictInList(napalmData["interfacesIp"], "interface")
        print(interfacesIp)

        interfacesWithIp = []

        for ipInterface in interfacesIp:
            ipsWithMasks = ''

            for ipAddressDictionary in ConvertDictInDictToDictInList(ipInterface['ipv4'], 'ip'):
                ipsWithMasks += ipAddressDictionary['ip'] + '/' + str(ipAddressDictionary['prefix_length']) + ", "

            if ipsWithMasks[-2:] == ', ':
                ipsWithMasks = ipsWithMasks[:-2]

            interfacesWithIp.append({ 
                'interface': ipInterface['interface'],
                'ipsWithMasks': ipsWithMasks})

        CreateWorksheet(workBook, "interfacesIp", interfacesWithIp)

    #delete default sheet
    del workBook['Sheet']

    workBook.save(path)


def SaveDeviceConfigFile(deviceConfig, path):
    deviceConfigFile = open(path, "w",encoding='utf8')
    deviceConfigFile.write(deviceConfig)
    deviceConfigFile.close()


    # else: raise Exception(f"Invalid configuration - operating system {vendor} is not supported.")

#FETCHING CONFIG and gather variables
config = configparser.ConfigParser()
config.read('./config.conf')

#Targets
ipAddresessFromConfig = config["Targets"]["IpAddresessToScan"].split(",")
networkFromConfig = config["Targets"]["NetworkToScan"]
UseJsonFileWithTargets = config["Targets"].getboolean("UseJsonFileWithTargets")

#Timeout for ssh connection
timeoutFromConfig = config["Targets"]["Timeout"]

#Credentials
sshUserName = config["Credentials"]["SshUserName"]
sshPassword = config["Credentials"]["SshPassword"]


snmpCommunityName = config["Credentials"]["SnmpCommunityName"]
deviceConfigurationSave = config["Outputs"]["DeviceConfigurationSave"]
jsonNmapRaw = config["Outputs"]["JsonNmapRaw"]

vlanTables = config["Outputs"]["VlanTables"]
macTable = config["Outputs"]["MacTable"]
arpTables = config["Outputs"]["ArpTables"]

lldpPNeigbors = config["Outputs"]["LldpPNeigbors"]

#InterfaceOptions
interfaceTables = config["Outputs"]["InterfaceTables"]
interfaceCountersTables = config["Outputs"]["InterfaceCountersTables"]
interfacesIp = config["Outputs"]["InterfacesIp"]


#FETCHING CONFIG

if (networkFromConfig):
    print(networkFromConfig)

if ipAddresessFromConfig:
    print(ipAddresessFromConfig)

if UseJsonFileWithTargets: pass #Import Json data to ipAddresessToScan

else:
    if ipAddresessFromConfig and networkFromConfig: ipAddresessToScan = [str(ip) for ip in ipaddress.IPv4Network(networkFromConfig)]
    elif ipAddresessFromConfig and not networkFromConfig: ipAddresessToScan = ipAddresessFromConfig
    else: raise Exception("RTFM !!!")



#Async Block with 256 threads
with concurrent.futures.ThreadPoolExecutor(max_workers=256) as executor:

    future_to_ipAddressToScan = {executor.submit(DeviceInfoFetchPipeline, ipAddressToScan, sshUserName, sshPassword, int(timeoutFromConfig)): ipAddressToScan for ipAddressToScan in ipAddresessToScan}

    for future in concurrent.futures.as_completed(future_to_ipAddressToScan):

        ipAddressToScan = future_to_ipAddressToScan[future]

        try:
            deviceData = future.result()

            deviceOutputFolderPath = "./outputs/devices/" + deviceData["ip"].replace(".", "_")

            os.makedirs(deviceOutputFolderPath, exist_ok=True)

            if jsonNmapRaw:
                nmapRawJson = open(deviceOutputFolderPath + "/nmapRaw.json", "w", encoding='utf8')
                nmapRawJson.write(json.dumps(deviceData['nmapData'], indent=4))
                nmapRawJson.close()

            SaveDeviceConfigFile(deviceData["napalmData"]["deviceConfig"], deviceOutputFolderPath + "/config.txt")
            SaveDeviceDataAsWorkbook(deviceData["napalmData"], deviceOutputFolderPath + "/deviceInfo.xlsx")
                   
        except Exception as ex:
            logging.error(f'{ipAddressToScan} generated an exception: {ex}')
            logging.error(traceback.format_exc())


#ENDE
print("Capo ti tuti capi ende slus !!!")

os.system("capo.mp3")





# useTestingData=False
# createTestingData = False

# if useTestingData:
#         json.loads(open("./testSwitchData.json",'r').read())

# if createTestingData:
#                 with open("./testSwitchData.json", 'w') as outfile:
#                     json.dump(deviceData, outfile)