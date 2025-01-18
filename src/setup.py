from sources import Sources
import os
import time
from threading import Thread, Event
import ctypes
import configparser


class Setup:
    def __init__(self):
        self.sources = Sources()
        self.config = configparser.ConfigParser()
        self.wireless_interface = ""
        self.wireless_interface2 = ""
        self.target_network = {}

        self.isdeauth_start = 0
        self.isdeauth_stop = 0
        self.iseviltwin_start = 0
        self.iseviltwin_stop = 0
    
    
    

    def start_Detecting_pack1(self):
        os.system("clear")
        self.config["Mode"] = {"Detection_Mode_1":1,"Detection_Mode_2":0}
        self.wireless_interface = self.sources.selectadapter()
        if self.sources.checkmode(self.wireless_interface) == "Managed":
            from changemode import ChangeMode
            self.wireless_interface = ChangeMode().changetomonitormode(self.wireless_interface)
        os.system("clear")
        self.target_network = self.sources.select_network(self.wireless_interface)
        self.config["Configurations"] = {"Network_Adaptor_1":self.wireless_interface,"Network_Adaptor_2":""}
        self.config["Target_Network_Information_Pack1"] = self.target_network
        with open("configuration.conf", "w") as configfile:
            self.config.write(configfile)
        #self.sources.create_service_file()
        os.system("clear")
        

    def start_Detecting_pack2(self):
        os.system("clear")
        self.config["Mode"] = {"Detection_Mode_1":0,"Detection_Mode_2":1}
        self.wireless_interface2 = self.sources.selectadapter()
        os.system("clear")
        if self.sources.checkmode(self.wireless_interface2) == "Monitor" or self.sources.checkmode(self.wireless_interface2) == "Master":
            from changemode import ChangeMode
            self.wireless_interface2 = ChangeMode().changetomanagedmode(self.wireless_interface2)
        os.system("clear")
        input("Please make sure you are connected to target network. Press enter after connected to target network -->")
        self.config["Configurations"] = {"Network_Adaptor_1":"","Network_Adaptor_2":self.wireless_interface2}
        ip_address = self.sources.get_ip_address(self.wireless_interface2)
        ip_base = str(ip_address).split(".")
        gateway_ip = f"{ip_base[0]}.{ip_base[1]}.{ip_base[2]}.1"
        print("Configuring Gateway IP and MAC...")
        arp_table = self.sources.capture_mac_address_in_network(self.wireless_interface2)
        try:
            gateway_mac = str(arp_table[gateway_ip]).lower()
        except KeyError:
            print("Could not configure mac address for your network may be due to your network adapter. Change network adapter and Try Again!!!")
            time.sleep(4)
        else:
            os.system("clear")
            while True:
                gateway_ip_check = input(f"Default gateway or router ip and mac address is set to be {gateway_ip}={gateway_mac} if it is correct ip type 'y' or enter. If it is wrong type 'n' to change it -->  ").lower()
                if gateway_ip_check == 'n':
                    new_gateway_ip = input("Input the ip address of your gateway or main router like '192.168.1.1' --> ")
                    if new_gateway_ip in arp_table:
                        gateway_ip = new_gateway_ip
                        try:
                            gateway_mac = str(arp_table[gateway_ip]).lower()
                        except KeyError:
                            print("Could not configure mac address for your network. Try Again!!!")
                        arp_table["gateway_ip"] = gateway_ip
                        break
                    else:
                        ip_confirm = input("This ip address does not captured in arp table. Do you want to select it? y/n --> ").lower()
                        if ip_confirm == "y":
                            gateway_ip = new_gateway_ip
                            try:
                                gateway_mac = str(arp_table[gateway_ip]).lower()
                            except KeyError:
                                gateway_mac = str(self.target_network["bssid"]).lower()
                            arp_table["gateway_ip"] = gateway_ip
                            break
                else:
                    arp_table["gateway_ip"] = gateway_ip
                    break
            
            self.config["Target_Network_Information_Pack2"] = {"gateway_ip":gateway_ip, "gateway_mac":gateway_mac}
            with open("configuration.conf", "w") as configfile:
                self.config.write(configfile)
            #self.sources.create_service_file()
            os.system("clear")

        
    def start_full_detecting(self):
        os.system("clear")
        self.config["Mode"] = {"Detection_Mode_1":1,"Detection_Mode_2":1}
        adapters_list = self.sources.listinterfaces()
        while True:
            option1 = input("Select First Network Adaptor for DDOS and Evil Twin Detection by typing corresponding index number (It's mode will be changed to monitor) --> ")
            option2 = input("Select second Network Adaptor for ARP spoofing and MITM attack by typing corresponding index number (It should be connected to Target Network ) --> ")
            try:
                option1 = int(option1)
                option2 = int(option2)
                self.wireless_interface = adapters_list[option1]
                self.wireless_interface2 = adapters_list[option2]
                if option1 == option2:
                    print("[-] Can not select similar network adaptor for both options.. Select Different ones ..")
                    time.sleep(2)
                else:
                    break
            except Exception as e:
                print("[-] Error occurs try again......")
                time.sleep(2)
        os.system("clear")
        if self.sources.checkmode(self.wireless_interface) == "Managed":
            from changemode import ChangeMode
            self.wireless_interface = ChangeMode().changetomonitormode(self.wireless_interface)
        os.system("clear")
        self.config["Configurations"] = {"Network_Adaptor_1":self.wireless_interface,"Network_Adaptor_2":self.wireless_interface2}
        self.target_network = self.sources.select_network(self.wireless_interface)
        self.config["Target_Network_Information_Pack1"] = self.target_network
        os.system("clear")
        input("Make sure your wireless adaptor for arp spoofing and MITM detection should be connected to target network now. If you are connected to target network press 'ENTER' --> ")
        ip_address = self.sources.get_ip_address(self.wireless_interface2)
        ip_base = str(ip_address).split(".")
        print("[+] Configuring Gateway IP and Mac addresses.....")
        try:
            gateway_ip = f"{ip_base[0]}.{ip_base[1]}.{ip_base[2]}.1"
            arp_table = self.sources.capture_mac_address_in_network(self.wireless_interface2)
            gateway_mac = str(arp_table[gateway_ip]).lower()
        except KeyError:
            gateway_mac = str(self.target_network["bssid"]).lower()
        except Exception:
            print("Error occur for setting up for ARP Spoofing and MITM Detection..")
            time.sleep(4)
        else:
            while True:
                gateway_ip_check = input(f"Default gateway or router ip and mac address is set to be {gateway_ip}={gateway_mac} if it is correct ip type 'y' or enter. If it is wrong type 'n' to change it -->  ").lower()
                if gateway_ip_check == 'n':
                    new_gateway_ip = input("Input the ip address of your gateway or main router like '192.168.1.1' --> ")
                    if new_gateway_ip in arp_table:
                        gateway_ip = new_gateway_ip
                        try:
                            gateway_mac = str(arp_table[gateway_ip]).lower()
                        except KeyError:
                            gateway_mac = str(self.target_network["bssid"]).lower()
                        arp_table["gateway_ip"] = gateway_ip
                        break
                    else:
                        ip_confirm = input("This ip address does not captured in arp table. Do you want to select it? y/n --> ").lower()
                        if ip_confirm == "y":
                            gateway_ip = new_gateway_ip
                            try:
                                gateway_mac = str(arp_table[gateway_ip]).lower()
                            except KeyError:
                                gateway_mac = str(self.target_network["bssid"]).lower()
                            arp_table["gateway_ip"] = gateway_ip
                            break

                else:
                    arp_table["gateway_ip"] = gateway_ip
                    break
            
            self.config["Target_Network_Information_Pack2"] = {"gateway_ip":gateway_ip, "gateway_mac":gateway_mac}
            os.system("clear")
        
        with open("configuration.conf", "w") as configfile:
            self.config.write(configfile)
        #self.sources.create_service_file()
        
        





        