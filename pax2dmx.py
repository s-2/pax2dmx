#!/usr/bin/env python3

import sched
import threading
import time

from dmx import DMXInterface
from scapy.all import sniff
from scapy.layers.dot11 import Dot11ProbeReq

# Define the RSSI threshold and interval
RSSI_THRESHOLD = -50
INTERVAL = 30

# Initialize a counter
counter = 0

universe = [255, 127, 0, 0]   # chinese 4-channel DMX fixture at address 1 (brightness, r, g, b)

interface = DMXInterface("FT232R")


# Function to handle probe requests
def handle_probe_request(packet):
    if packet.haslayer(Dot11ProbeReq):
        rssi = packet['RadioTap'].dBm_AntSignal
        if rssi > RSSI_THRESHOLD:
            global counter, universe
            counter += 1
            print(f"rssi {rssi}, counter {counter}")
            universe[3] = min(255, counter * 5)


# Print all fields available in the RadioTap header
# for field in RadioTap.fields_desc:
#    print(f"Field name: {field.name}, Field type: {field.__class__.__name__}")


def schedule_transmission(scheduler):
    global universe
    global counter
    scheduler.enter(0.5, 1, schedule_transmission, (scheduler,))
    print(f"prq count {counter}")

    universe[3] = min(255, counter * 5)
    interface.set_frame(universe)
    interface.send_update()

    if counter > 0:
        counter -= 1


# Initialize the scheduler
scheduler = sched.scheduler(time.time, time.sleep)

# Schedule the first transmission
scheduler.enter(0.5, 1, schedule_transmission, (scheduler,))


# Function to run the scheduler in a separate thread
def run_scheduler():
    scheduler.run()


# Start the scheduler in a separate thread
thread = threading.Thread(target=run_scheduler)
thread.start()

# Start the sniffer
print("Starting Wi-Fi sniffer...")
bpf_filter = "wlan type mgt subtype probe-req"
sniff(iface="phy0-mon0", prn=handle_probe_request, store=0, monitor=True, filter=bpf_filter)
