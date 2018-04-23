# SlowDoS_Detector

slowdos_detector is Python tool to detect Slow HTTP DoS Attacks (GET and POST) on pcap files.

### Prerequisites

Linux Distribution

Python 2.7.x 

tshark 

Scapy module for Python 

### Installing

For Scapy Module:

https://scapy.readthedocs.io/en/latest/installation.html

For tshark:

https://pkgs.org/download/tshark


### Usage

slowdos_dectect.py -f <mypcap.pcap> -s <myserverip> [-p]

### High Level Description on how it works:

It opens the pcap file and use tshark to verify how many TCP sessions for the serverip it has.
Once this is identified, if there is any session, it still uses tshark to break the pcap into small pcaps per TCP stream.

Files are save to /tmp/sess-????.pcap and a mapping session file is created (/tmp/sessions.txt).
Once breaking of the pcap is done, it iterates all over small pcaps files identifying all slow transcations.

Slow transcations here are considered the ones with no response from webservers in 25 seconds after 3WHS.
The data are consolidated into a dictionary and a sample of the payload along with statistics are collected and displayed to the user.

### Authors

* **Ismael Goncalves** -  [Sharingsec](https://sharingsec.blogspot.com)
