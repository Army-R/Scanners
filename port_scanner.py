#!/bin/python3

import sys #allow us to enter command line arguments
import socket
from datetime import datetime as dt

# Define our target
if len (sys.argv) == 2:
    target = socket.gethostbyname(sys.argv[1]) # Translate a host name to IPV4
else:
    print('Invalid amount of arguments.')
    print('Syntax: python3 scanner.py <ip>')
    sys.exit()

# Add a pretty banner
print('_' * 50)
print(f'Scanning target: {target}')
print('Time started' + str(dt.now()))
print('_' * 50)

try:
    for port in range(0, 255):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1) #is a float
        result = s.connect_ex((target, port)) #return error indicator
        print(f'Checking port {port}')
        if result == 0:
            print(f'Port {port} is open')
        s.close()

except KeyboardInterrupt:
    print('\nExiting program.')
    sys.exit()
except socket.gaierror:
    print('Hostname could not be resolved')
    sys.exit()
except socket.error:
    print('Could not connect to server.')
    sys.exit()
