#!/usr/bin/python

# Import the necessary modules
from scapy.all import *
import sys
import signal
import os
import subprocess

# Function to handle when the user enters Ctrl+C
def signal_handler(signal, frame):
    print('\n=======================')
    print('Execution aborted by User')
    print('=========================')
    subprocess.run(f'kill -9 {str(os.getpid())}')
    sys.exit(1)

# Create a function to exit
def signal_exit(signal, frame):
    print('Signal exit')
    sys.exit(1)

# Create a function to remaind the user the basic sytanx, if incorrect
def usage():
    if len(sys.argv) < 3:
        print('\nUsage:')
        print('\twifi_scanner.py -i <interface>\n')
        sys.exit(1)

# Create a function to sniff the packets
def sniffpackets(packet):
    try:
        SRCMAC = packet[0].addr2
        DSTMAC = packet[0].addr1
        BSSID = packet[0].addr3
    except:
        print('Cannot read MAC address')
        print(str(packet).encode('hex'))

    try:
        SSIDSize = packet[0][Dot11Elt].len
        SSID =packet[0][Dot11Elt].info
    except:
        SSID = ''
        SSIDSize = 0

# Check to see whether the packet type =0 and subtype 8 (Beacon frames)
    if packet[0].type == 0:
        ST = packet[0][Dot11].subtype
        if str(ST) == '8' and SSID != '' and DSTMAC.lower() == 'ff:ff:ff:ff:ff:ff':
            p = packet[Dot11Elt]
            cap = packet.sprintf('{Dot11Beacon:%Dot11Beacon.cap%}'
                                 '{Dot11ProbeResp:%Dot11ProbeResp.cap%}').split('+')
            channel = None
            crypto = set()

# Create function to track discovered SSDID'S so as not to list them each time they are discovered
def init_process():
    global ssid_list
    ssid_list = {}
    global s
    s = conf.L2socket(ifaces=newiface)

# Define function to set up wireless interface in monitore mode

def run_cmd(cmd):
    subprocess.run(cmd, check=True, capture_output=True, text=True)

def setup_monitor(iface):
    print('Setting up sniffing options...')
    try:
        run_cmd(['ip', 'link', 'set', iface, 'down'])
        run_cmd(['iw', 'dev', iface, 'set', 'type', 'monitor'])
        run_cmd(['ip', 'link', 'set', iface, 'up'])
    except subprocess.CalledProcessError as e:
        print(f'Failed to set {iface} to monitor mode')
        print(f'Command: {e.cmd}')
        print(f'Error: {e.stderr}')
        sys.exit(1)
    except FileNotFoundError as e:
        print(f'Required tool not found {e}')
        sys.exit(1)
    return iface   

# Define a function to check whether the user has admin/root privileges and if not message them
def is_admin() -> bool:
    # Return true if the current porcess has admin/root pribileges.
    if sys.platform == 'win32':
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    
    if hasattr(os, 'geteuid'):
        return os.geteuid() == 0

    raise RuntimeError(f'Undupported platform for privilege check: {sys.platform}')

def check_root() -> None:
    'Exit if the current process does not have admin/root privileges'
    if not is_admin():
        print('You must run this script as admin/root', file=sys.stderr)
        sys.exit(1)

# Main Code Body
if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal_handler)
    usage()
    check_root()
    parameters = {sys.argv[1]:sys.argv[2]}
    if 'mon' not in str(parameters['-i']):
        newiface = setup_monitor(parameters['-i'])
    else:
        newiface = str(parameters['-i'])
    init_process()
    print('Starting Wi-Fi Scanner')
    print(f'Sniffinf on interface {str(newiface)}...\n')
    sniff(iface=newiface, prn=sniffpackets, store=0)