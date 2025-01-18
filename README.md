
# EthHacks Wireless Protect (Service Version)

EthHacks Wireless Protect application is an open source application to detect most common wifi or wireless attacks with in the network. This is service version of Wireless Protect application.

- Programming Language: Python3
- Operating System Type: Linux
- Tested On: Kali linux 2024


## Requirements

In order to run The Wireless-Protect tool as service, this application is using nohup tool which comes preinstalled in many linux distro but check it before running this application that nohup is installed using:

```bash
  nohup --version
```
or install it if not installed using:

```bash
  sudo apt update
  sudo apt install coreutils
```

The Wireless-Protect_Service_Version folder contains "requirements.txt" file. Its contains all the required python libraries for this tool. Install them manualy by using:

```bash
  sudo pip3 install [library]
```
    
OR use the requirements.txt file and install as:

```bash
  sudo pip3 install -r requirements.txt
```
## Options

1.  Deauth Detector, Evil Twin Detector , Clonned Wifi Detector -->  You can select this option by pressing '0' after running the application. In this option, application detect deauthentication attack, Evil Twin attack or Clonned wifi attack on selected network. After selecting this option, You need to select the network adapter for detect these attack and the mode of this network adapter will be changed to monitor mode if its mode is not monitor mode. Then, application will check for nearby wifi networks and show them to select your target network. Application then detect the above mentioned attacks on selected network and notify when any attack detected.

- Deauthentication Attack Detection
- Evil Twin Attack Detection
- Clonned Wifi Detection
---

2.  Arp Spoofing and MITM Detector -->  You can select this option by pressing '1' after running the application. In this option, application detect arp Spoofing attack and man in the middle attack in selected network. After selecting this option, You need to select the network adapter for detect these attack and the mode of this network adapter should me managed mode. Also, you be connected to your target network in which you want to detect above mentioned attacks. Application will check for gateway ip and mac address of network you are connected to. Application then detect the above mentioned attacks in selected network and notify when any attack detected.

- Arp Spoofing Attack Detection
- (MITM) Man in the Middle Attack Detection
---

3.  Detect All including both 1 and 2.. -->  You can select this option by pressing '2' after running the application. In this option, application detect deauthentication attack, Evil Twin attack, Clonned Wifi attack, arp Spoofing attack and man in the middle attack in selected network. After selecting this option, You need to select the 2 network adapter for detecting these attack and the mode of one network adapter will be converted to monitor mode to detect deauthentication, evil twin and clonned wifi attacks. The second network adapter should be in managed mode and should be connected to target or selected network.Then, application will check for nearby wifi networks and show them to select your target network. Application will check for gateway ip and mac address of network you are connected to using second network adapter.  Application then detect the above mentioned attacks in selected network and notify when any attack detected.


[Note] You cannot select same network adapter for both in this option. As, one network adapter will be in monitor mode and other will be in managed mode for proper working.

- Deauthentication Attack Detection
- Evil Twin Attack Detection
- Clonned Wifi Detection
- Arp Spoofing Attack Detection
- (MITM) Man in the Middle Attack Detection
---
## Usage/Installation

After installing the requirements using "requirements.txt". Run the program using following command:

```
sudo python3 main.py
```

There will be three options after running the application:
1.  Setup the configurations for Wireless Attacks Detection Service -->  You can select this option by pressing '0' after running the application. In this option, application will amke configurations for the service. It this condifuration, you will specify which attacks you want the wireless protect service to detect. Also, specify the network adapters and other informations required for it.
---

2.  Start the Wireless Attacks Detection Service (First make configurations using first option...) -->  You can select this option by pressing '1' after running the application. In this option, application will start the wireless protect service to detect the attacks in accordance with the configurations you made using first option.

[Note] Before starting the wireless protect service make sure you have made the configurations using first option. It will we required only one time to configure afterward it will choose that configurations automatically. You can change the configurations again using the first option.
---

3.  Stop all running Wireless Attacks Detection Services -->  You can select this option by pressing '2' after running the application. In this option, application will stop the wireless protect service if running.

## Features

When any of the attack is detected. The application will have below features to allert you.

- `Allert Message in outuput.log`

- `Send System Notification`

