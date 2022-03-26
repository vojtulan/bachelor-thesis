from ast import Delete
from asyncio.windows_events import NULL
import re
from tkinter import E
from ciscoconfparse import CiscoConfParse
import json
import nmap3
import configparser
import pprint
from openpyxl import Workbook
from napalm import get_network_driver
import os
from types import SimpleNamespace
from pathlib import Path
from datetime import datetime
import ipaddress
from pssh.clients import ParallelSSHClient
from pssh.config import HostConfig



import vlc


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


def ResolveDriver(ipAddressess, sshUserName, sshPassword):

    #if defaultDriver == "HuaweiVrp5" or defaultDriver == "HuaweiVrp8":
        
    #connection = CreateNapalmConnection(ipAddress, "huawei_vrp", sshUserName, sshPassword)
            
    output = client.run_command('display version')

    for host_out in output:
        for line in host_out.stdout:
            print(line)

            if "Cisco IOS Software," in line:
                driver = "ios"
                break

            if "VRP (R) software," in line:
                driver = "huaweiVrp" + line.partition("Version ")[2][0]
                break

            if "SW version    " in line:
                driver = "ios"
                break

    print(driver)


def CreateWorksheet(workBook, workSheetName, dataCollection):

    workSheet = workBook.create_sheet(workSheetName)
    workSheet.append(list(dataCollection[0].keys()))

    for data in dataCollection:
        workSheet.append(list(data.values()))
    
def ConvertDictInDictToDictInList(dataDictDict, newColumnName):

    #vytahneme klice
    keys = list(dataDictDict.keys())
    listDict = []

    for key in keys:
        
        #ke klicum ve sloupci prilepime hodnoty
        dataDict = { newColumnName: key}
        #tady se prilepi hodnoty ke klici (jako tx errors)
        dataDict.update(dataDictDict[key])

        listDict.append(dataDict)

    return listDict


def SaveDeviceDataAsWorkbook(deviceData, path):
    
    workBook = Workbook()

    CreateWorksheet(workBook, "macTable", deviceData["macTable"])
    CreateWorksheet(workBook, "arpTable", deviceData["arpTable"])

    interfacesData = ConvertDictInDictToDictInList(deviceData["interfaces"], "interface")
    interfaceCountersData = ConvertDictInDictToDictInList(deviceData["interfacesCounter"], "interfacesCounter")

    CreateWorksheet(workBook, "interfaces", interfacesData)
    CreateWorksheet(workBook, "interfacesCounter", interfaceCountersData)

    del workBook['Sheet']

    workBook.save(path)


def SaveDeviceConfigFile(deviceConfig, path):
    deviceConfigFile = open(path, "w",encoding='utf8')
    deviceConfigFile.write(deviceConfig)
    deviceConfigFile.close()


    # else: raise Exception(f"Invalid configuration - operating system {vendor} is not supported.")

#FETCHING CONFIG and gather variables
config = configparser.ConfigParser()
config.read('config.conf')
print(config.sections())
print(config["Targets"]["IpAddresessToScan"])

ipAddresessFromConfig = config["Targets"]["IpAddresessToScan"].split(",")
networkFromConfig = config["Targets"]["NetworksToScan"].split(",")
UseJsonFileWithTargets = config["Targets"]["UseJsonFileWith"]

timeoutFromConfig = config["Targets"]["Timeout"]

#Credentials
sshUserName = config["Credentials"]["SshUserName"]
sshPassword = config["Credentials"]["SshPassword"]


SnmpCommunityName = config["Credentials"]["SnmpCommunityName"]

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

parallelHostConfigs = []
parallelConfig = []

if UseJsonFileWithTargets: pass #Import Json data to ipAddresessToScan

else:
    if not ipAddresessFromConfig and networkFromConfig: ipAddresessToScan = ipaddress.IPv4Network(networkFromConfig)
    elif ipAddresessFromConfig and not networkFromConfig: ipAddresessToScan = ipAddresessFromConfig
    else: raise Exception("RTFM !!!")

    for ip in ipAddresessToScan:
        parallelHostConfigs.append(HostConfig(user=sshUserName, password=sshPassword, timeout=timeoutFromConfig))
        #ipAddresessToScan, user='my_user', password='my_pass', timeout=timeoutFromConfig




clients = ParallelSSHClient(ipAddresessToScan, host_config=parallelHostConfigs)
outputs = clients.run_command('display version')





nmapResults = {}
deviceType = ""


#Testing
useTestingData=True
#Testing

for ip in ipAddresessToScan:

    #TESTING DATA
    if useTestingData: deviceData = json.loads(open("./testDataHuawei.json",'r').read())

    else:
        connectionVariables = ResolveDriver(ip, sshUserName, sshPassword, defaultDriver)

        connection = connectionVariables[0]
        connectionOs = connectionVariables[1]

        print(connectionOs)

        deviceData = {
           "deviceConfig": str(connection.get_config()["running"]),
           "arpTable" : connection.get_arp_table(),
           "macTable" : connection.get_mac_address_table(),
           "interfaces" : connection.get_interfaces(),
           "interfacesIp" : connection.get_interfaces_ip(),
           "interfacesCounter" : connection.get_interfaces_counters(),
           "lldpNeighbors" : connection.get_lldp_neighbors()}


        if connectionOs == "HuaweiVrp5":
           print(deviceData)


        elif connectionOs == "HuaweiVrp8":
           deviceData["deviceUsers"] = connection.get_device_users()

        elif connectionOs == "IOS":
            deviceData["deviceUsers"] = connection.get_device_users()
            deviceData["blaBla"] = 'blabla'



    #Create Device Folder if not exists
    deviceOutputFolderPath = "./outputs/devices/" + ip.replace(".", "_")
    if not os.path.exists(deviceOutputFolderPath):
        os.mkdir(deviceOutputFolderPath)

    #NMAP
    nmapResult = FetchNmapData(ip)
    nmapResults.update(nmapResult)

    if jsonNmapRaw:
        nmapRawJson = open(deviceOutputFolderPath + "/nmapRaw.json", "w", encoding='utf8')
        nmapRawJson.write(json.dumps(nmapResults, indent=4))
        nmapRawJson.close()
    #NMAP_END



    SaveDeviceConfigFile(deviceData["deviceConfig"], deviceOutputFolderPath + "/config.txt")
    SaveDeviceDataAsWorkbook(deviceData, deviceOutputFolderPath + "/deviceInfo.xlsx")



    #type = ReturnResolvedDeviceOs(nmapResults[ip]["macaddress"]["vendor"])


    #device = CreateNapalmConnection(ip, vendor, sshUserName, sshPassword)
    









#ENDE
print("Capo ti tuti capi ende slus !!!")

os.system("capo.mp3")
