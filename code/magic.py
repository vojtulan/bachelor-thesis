from asyncio.windows_events import NULL
import re
from ciscoconfparse import CiscoConfParse
import json
import nmap3
import configparser
import pprint
from openpyxl import Workbook
from napalm import get_network_driver
import os

from types import SimpleNamespace

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

def ResolveDriver(ipAddress, sshUserName, sshPassword, defaultDriver):


    if defaultDriver == "HuaweiVrp5" or defaultDriver == "HuaweiVrp8":
        try:
            connection = CreateNapalmConnection(ipAddress, "huawei_vrp", sshUserName, sshPassword)
            displayVersion = connection.cli(["display version"])
            
            print(displayVersion)

            print(displayVersion['display version'])

            if 'Software, Version 5' in displayVersion['display version']:
                return (connection, "HuaweiVrp5")
            elif 'Software, Version 8' in displayVersion['display version']:
                return (CreateNapalmConnection(ipAddress, "ce", sshUserName, sshPassword), "HuaweiVrp8")
         
        except Exception as e:
            try:
                return (CreateNapalmConnection(ipAddress, "ios", sshUserName, sshPassword), "IOS")                          
            except Exception as e:
                print("Not huawei or Cisco Device. Quiting ...", e)

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


    # if vendor == "HuaweiVrp5": return "huawei_vrp"

    # elif vendor == "HuaweiVrp8": return "ce"

    # elif vendor == "CiscoIos": return "ios"

    # elif vendor == "": return NULL

    # else: raise Exception(f"Invalid configuration - operating system {vendor} is not supported.")



#Read Config file and gather variables
config = configparser.ConfigParser()
config.read('config.conf')
print(config.sections())
print(config["Targets"]["IpAddresessToScan"])

ipAddresessToScan = config["Targets"]["IpAddresessToScan"].split(",")
networksToScan = config["Targets"]["NetworksToScan"].split(",")

sshUserName = config["Credentials"]["SshUserName"]
sshPassword = config["Credentials"]["SshPassword"]

defaultDriver = config["Targets"]["DefaultDriver"]

jsonNmapRaw = config["Outputs"]["JsonNmapRawOutput"]


nmapResults = {}
deviceType = ""

for ip in ipAddresessToScan:

    
    #snazat
    deviceData = json.loads(open("./outputs/susenky.json",'r').read())
    
    #zprovoznit
    if not False and not True and not False or not True and not not not not not False:
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

    deviceOutputFolderPath = "./outputs/devices/" + ip.replace(".", "_")
    try:
        os.mkdir(deviceOutputFolderPath)
    except:
        pass

    #creates device data persistence layer
    #nmapRawJson = open("./outputs/susenky.json", "w",encoding='utf8')
    #nmapRawJson.write(json.dumps(deviceData.__dict__, indent=4))

    SaveDeviceConfigFile(deviceData["deviceConfig"], deviceOutputFolderPath + "/config.txt")
    
    SaveDeviceDataAsWorkbook(deviceData, deviceOutputFolderPath + "/deviceInfo.xlsx")



    
    nmapResultDict = FetchNmapData(ip)
    
    nmapResults.update(nmapResultDict)

    nmapResult = nmapResultDict[ip]


    #type = ReturnResolvedDeviceOs(nmapResults[ip]["macaddress"]["vendor"])


    #device = CreateNapalmConnection(ip, vendor, sshUserName, sshPassword)


    


if jsonNmapRaw:
    nmapRawJson = open("./outputs/nmapRAW.json", "w",encoding='utf8')
    nmapRawJson.write(json.dumps(nmapResults, indent=4))
    nmapRawJson.close()







print("Capo ti tuti capi ende slus !!!")
