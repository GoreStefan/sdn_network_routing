#! /usr/bin/env python3
# -- coding: utf-8 --

"""
About: Simple client.
"""

import socket
import time
import numpy as np

SERVICE_IP = "10.0.0.123"
SERVICE_PORT = 8888

"""
CREATING LARGE DATA
"""
def large_data(size_in_kb): 
    return b"a"*(size_in_kb*1024*1024)

if __name__ == "__main__":
    # Declare that will use IP/UDP protocols
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Wait for the answer for 2 seconds
    sock.settimeout(2)
    data = b"Hello World" # msg sent to server
    big_data = large_data(1)

    #data will be sent with poisson distribution
    #parameters for poisson
    rate = 5
    interval = 1/rate

    while True:
        wait_time = np.random.poisson(interval)
        # Sends packet to server
        print(" Sending data...")
        sock.sendto(big_data, (SERVICE_IP, SERVICE_PORT))
        try:
            # Wait for the answer from server
            counter, _ = sock.recvfrom(1024)
            print("Client received: <{}>".format(counter.decode("utf-8")))
            time.sleep(1)
        except socket.timeout: 
            # If does not receive answer, wait 5 seconds
            print("Client received: <nothing>")
            time.sleep(5)
            pass
        time.sleep(wait_time)