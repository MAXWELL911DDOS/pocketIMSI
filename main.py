import os
import sys
import time
import random
import string
import socket
import threading
import argparse
import subprocess

# *** YOU NEED ROOT PRIVILEGES ***
if os.geteuid() != 0:
    print("[!] Run as root!")
    sys.exit(1)

# *** Dependencies Check (Termux) ***
def check_dependencies():
    try:
        subprocess.check_call(["which", "hostapd"])
        subprocess.check_call(["which", "dnsmasq"])
        subprocess.check_call(["which", "iptables"])
        subprocess.check_call(["which", "termux-setup-storage"])
    except subprocess.CalledProcessError:
        print("[!] Missing dependencies. Installing...")
        os.system("pkg update && pkg install -y hostapd dnsmasq iptables termux-tools termux-api")
        os.system("termux-setup-storage")
        print("[+] Dependencies installed. Run the script again.")
        sys.exit(1)

check_dependencies()


interface = "wlan0"  # Your wireless interface
ssid_prefix = "LOL_FREE_WIFI_"  # SSID prefix - get creative
ip_address = "192.168.4.1" # Static IP for the AP


warning_page_content = """
<!DOCTYPE html>
<html>
<head>
<title>YOU'VE BEEN PWNED</title>
<style>
body {
  background-color: black;
  color: red;
  font-family: monospace;
  text-align: center;
}
h1 {
  font-size: 4em;
  margin-top: 20%;
}
p {
  font-size: 1.5em;
}
</style>
</head>
<body>
<h1>YOU'VE BEEN PWNED</h1>
<p>This is a FAKE Wi-Fi network. Don't be a dumbass and connect to random shit.</p>
<p>Consider this a lesson.</p>
</body>
</html>
"""


def generate_ssid(prefix):
    rand = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(5))
    return prefix + rand


def generate_password(length):
    return ''.join(random.choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(length))


def create_hostapd_config(interface, ssid, password):
    config = f"""
interface={interface}
driver=nl80211
ssid={ssid}
hw_mode=g
channel=6
wpa=2
wpa_passphrase={password}
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
"""
    with open("/data/data/com.termux/files/home/hostapd.conf", "w") as f:
        f.write(config)


def create_dnsmasq_config(interface, ip_address):
    config = f"""
interface={interface}
dhcp-range={ip_address},192.168.4.254,255.255.255.0,12h
dhcp-option=3, {ip_address} # Gateway
dhcp-option=6, {ip_address} # DNS Server
address=/#/{ip_address}  # Redirect all requests
"""
    with open("/data/data/com.termux/files/home/dnsmasq.conf", "w") as f:
        f.write(config)


def create_warning_page():
    warning_page_path = "/sdcard/warning.html"  # Path to the warning page
    with open(warning_page_path, "w") as f:
        f.write(warning_page_content) # Writes the HTML to the warning file
    print(f"[+] Warning page created: {warning_page_path}")
    return warning_page_path


def start_ap(interface, ssid, password, ip_address, warning_page_path):
    create_hostapd_config(interface, ssid, password)
    create_dnsmasq_config(interface, ip_address)

    os.system("ip link set {} up".format(interface)) # Use 'ip' instead of 'ifconfig'
    os.system("ip addr add {}/24 dev {}".format(interface, ip_address))
    os.system("ip route add default via {}".format(ip_address)) # Set the default route

    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward") # Enable IP forwarding

    # NAT for internet access (if you want it) - CHANGE THE OUTPUT INTERFACE
    os.system("iptables -t nat -A POSTROUTING -o rmnet0 -j MASQUERADE") # Change rmnet0 to your mobile data interface

    os.system("iptables -A FORWARD -i {} -o rmnet0 -m state --state RELATED,ESTABLISHED -j ACCEPT".format(interface))
    os.system("iptables -A FORWARD -i rmnet0 -o {} -j ACCEPT".format(interface)) # Again, change the interface

    subprocess.Popen(["hostapd", "/data/data/com.termux/files/home/hostapd.conf"]) # Full path
    subprocess.Popen(["dnsmasq", "-C", "/data/data/com.termux/files/home/dnsmasq.conf"])

    print(f"[+] AP Started: SSID={ssid}, Password={password}")

   
    webserver_thread = threading.Thread(target=start_webserver, args=(warning_page_path,))
    webserver_thread.daemon = True # Kill with the main thread
    webserver_thread.start()

    os.system("iptables -t nat -A PREROUTING -i {} -p tcp --dport 80 -j DNAT --to-destination {}:8080".format(interface, ip_address))


def start_webserver(warning_page_path):
    try:
         # Check if warning_page exists in /sdcard (storage directory)
        if not os.path.exists(warning_page_path):
             print(f"[!] Warning page not found: {warning_page_path}")
             return

         # Start a simple web server to redirect to the warning page
        command = f"cd /sdcard && python -m http.server 8080" 
        os.system(command)
        print("[+] Web server running on port 8080")

    except Exception as e:
        print(f"Error starting web server: {e}")


def stop_ap(interface):
    os.system("killall hostapd")
    os.system("killall dnsmasq")
    os.system("killall python") 
    os.system("iptables -F") 
    os.system("iptables -X")
    os.system("iptables -t nat -F")
    os.system("iptables -t nat -X")

    os.system("ip link set {} down".format(interface))  
    os.system("rm -f /data/data/com.termux/files/home/hostapd.conf /data/data/com.termux/files/home/dnsmasq.conf")

    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward") 
    print("[+] AP Stopped.")


def show_devices():
    print("\n[+] Connected Devices:")
    os.system("arp -a") # Still basic, still works(ish)


def main():
    parser = argparse.ArgumentParser(description="POCKET IMSI: Creates fake AP for demonstration purposes in Termux.")
    parser.add_argument("-s", "--ssid", help="Custom SSID (optional)")
    parser.add_argument("-p", "--password", help="Custom password (optional)")
    args = parser.parse_args()

    ssid = args.ssid if args.ssid else generate_ssid(ssid_prefix)
    password = args.password if args.password else generate_password(12) 
    # Create the warning page
    warning_page_path = create_warning_page()

    try:
        start_ap(interface, ssid, password, ip_address, warning_page_path)
        while True:
            show_devices()
            time.sleep(10) 
    except KeyboardInterrupt:
        stop_ap(interface)

if __name__ == "__main__":
    main()
