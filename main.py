import sys
import os
import time
import subprocess
current_path = os.getcwd()
sys.path.insert(1, f'{os.getcwd()}/src')
from setup import Setup # type: ignore


from colorama import init, Fore
init()
GREEN = Fore.GREEN
RED   = Fore.RED
BLUE   = Fore.BLUE
RESET = Fore.RESET



def banner():
    print(f"{RED}         Welcome to EthHacks Wireless Protect Tool         {RESET}")
    print(f"""{RED}
     ______ _   _     _    _            _        
    |  ____| | | |   | |  | |          | |       
    | |__  | |_| |__ | |__| | __ _  ___| | _____ {RESET}{BLUE}
    |  __| | __| '_ \|  __  |/ _` |/ __| |/ / __|
    | |____| |_| | | | |  | | (_| | (__|   <\___ {RESET}{GREEN}
    |______|\__|_| |_|_|  |_|\__,_|\___|_|\_\___|
        {RESET}""")
    print("\n")
    print("----------------------------------------------------------------------------")

def start_service():
    service_status = checking_running_service()
    if service_status == "Running":
        print("[-] Service is already running.....")
        run_again = input("Do you want to stop the previous service and run new one? y/n --> ").lower()
        if run_again == "y":
            kill_service()
            time.sleep(1)
            print("[+] Starting Wireless Attacks Detection Service.....")
            os.system(f"nohup /usr/bin/python3 {current_path}/src/service_run.py > output.log 2>&1 &")
        else:
            run_again = input("Do you want to run the second service while keep running the first one? y/n --> ").lower()
            if run_again == "y":
                print("[+] Starting Wireless Attacks Detection Service.....")
                os.system(f"nohup /usr/bin/python3 {current_path}/src/service_run.py > output.log 2>&1 &")
        time.sleep(3)
    else:
        print("[+] Starting Wireless Attacks Detection Service.....")
        os.system(f"nohup /usr/bin/python3 {current_path}/src/service_run.py > output.log 2>&1 &")
        time.sleep(3)

def checking_running_service():
    print("[!] Checking if wireless detection service is running....")
    service_status = "Stopped"
    command = f"ps aux | grep '[/]usr/bin/python3 {current_path}/src/service_run.py'"
    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, text=True)
    for line in result.stdout.splitlines():
        parts = line.split()
        if f"/usr/bin/python3 {current_path}/src/service_run.py" in line:
            service_status = "Running"
    return service_status

def kill_service():
    command = f"ps aux | grep '[/]usr/bin/python3 {current_path}/src/service_run.py'"
    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, text=True)
    for line in result.stdout.splitlines():
        parts = line.split()
        if f"/usr/bin/python3 {current_path}/src/service_run.py" in line:
            pid = int(parts[1])
            print(f"PID found: {pid}")
            os.kill(pid, 9)
            print(f"Already running services are stopped..")
    time.sleep(1)


ON = True
while ON:
    os.system("clear")
    banner()
    print(f"{GREEN}0. Setup the configurations for Wireless Attacks Detection Service")
    print("1. Start the Wireless Attacks Detection Service (First make configurations using first option...)")
    print("2. Stop all running Wireless Attacks Detection Services ")
    print(f"3. Exit..{RESET}")
    option = input("Select the option by typing corresponding index number e.g 0 or 4 --> ")
    if option == "3" or option.upper() == "EXIT":
        ON = False
    elif option == "0":
        os.system("clear")
        banner()
        print(f"{GREEN}0. Deauth Detector, Evil Twin Detector, Clonned Wifi Detector  (Requires 1 network adapter that can be Built-in Adaptor)")
        print("1. Arp Spoofing and MITM detector (Requires 1 network adapter connected to selected network)")
        print("2. Both 1 and 2.. (Requires 2 network adapter.. One connected to network)")
        print(f"3. Back...{RESET}")
        selected_option = input("Select the option by typing corresponding index number e.g 0 or 3 --> ")
        if selected_option == "3" or selected_option.upper() == "Back":
            pass
        elif selected_option == "0":
            Setup().start_Detecting_pack1()
        elif selected_option == "1":
            Setup().start_Detecting_pack2()
        elif selected_option == "2":
            Setup().start_full_detecting()
    
    elif option == "1":
        os.system("clear")
        banner()
        start_service()
    elif option == "2":
        os.system("clear")
        banner()
        kill_service()
