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

class DeviceData:
  def __init__(self, deviceConfig, arpTables, macTable, interfaces, interfacesIp, interfacesCounter, lldpNeighbors):
    self.deviceConfig = deviceConfig
    self.arpTables = arpTables
    self.macTable = macTable
    self.interfaces = interfaces
    self.interfacesIp = interfacesIp
    self.interfacesCounter = interfacesCounter
    self.lldpNeighbors = lldpNeighbors

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

def SaveDeviceDataAsWorksheet(deviceData, path):
    
    workbook = Workbook()



    workbook.save(path)

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

    
    connectionVariables = ResolveDriver(ip, sshUserName, sshPassword, defaultDriver)

    connection = connectionVariables[0]
    connectionOs = connectionVariables[1]

    print(connectionOs)

    deviceData = DeviceData(
       deviceConfig = str(connection.get_config()["running"]),
       arpTables = connection.get_arp_table(),
       macTable = connection.get_mac_address_table(),
       interfaces = connection.get_interfaces(),
       interfacesIp = connection.get_interfaces_ip(),
       interfacesCounter = connection.get_interfaces_counters(),
       lldpNeighbors = connection.get_lldp_neighbors())


    if connectionOs == "HuaweiVrp5":
       print(vars(deviceData))
       
    
    elif connectionOs == "HuaweiVrp8":
       deviceData.deviceUsers = connection.get_device_users()

    elif connectionOs == "IOS":
        deviceData.deviceUsers = connection.get_device_users()
        deviceData.blaBla = 'blabla'

    deviceOutputFolderPath = "./outputs/devices/" + ip.replace(".", "_")
    try:
        os.mkdir(deviceOutputFolderPath)
    except:
        pass

    #nmapRawJson = open("./outputs/susenky.json", "w",encoding='utf8')
    #nmapRawJson.write(json.dumps(deviceData.__dict__, indent=4))

    

    SaveDeviceConfigFile(deviceData.deviceConfig, deviceOutputFolderPath + "/config.txt")
    
    SaveDeviceDataAsWorksheet(deviceData, deviceOutputFolderPath + "/deviceInfo.xlsx")



    
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
