import scapy.all as scapy
import nmap
import manuf
from datetime import datetime


def scan_devices(target_ip):
    nm = nmap.PortScanner()
    nm.scan(hosts=target_ip, arguments='-O')

    devices = []
    for host in nm.all_hosts():
        if 'osclass' in nm[host]:
            for osclass in nm[host]['osclass']:
                devices.append({"ip": host, "os_family": osclass['osfamily'], "os_genus": osclass['osgen']})
        else:
            devices.append({"ip": host, "os_family": "Unknown", "os_genus": "Unknown"})

    return devices


def get_device_info(mac_address):
    parser = manuf.MacParser()
    manufacturer = parser.get_manuf(mac_address)
    return manufacturer


def save_results(devices):
    now = datetime.now()
    current_time = now.strftime("%Y-%m-%d %H:%M:%S")
    file_name = "device_scan_results.txt"

    with open(file_name, 'a') as file:
        file.write(f"Scan Results at {current_time}:\n")
        file.write("IP Address\t\tOS Family\t\tOS Genus\t\tManufacturer\n")
        file.write("------------------------------------------------------------------------------\n")
        for device in devices:
            manufacturer_info = get_device_info(device['mac']) if 'mac' in device else "Unknown"
            file.write(f"{device['ip']}\t\t{device['os_family']}\t\t{device['os_genus']}\t\t{manufacturer_info}\n")
        file.write("\n")


def main(target_ip):
    try:
        devices = scan_devices(target_ip)
        save_results(devices)
        print(f"[+] Scan results saved to 'device_scan_results.txt'.")
    except KeyboardInterrupt:
        print("\n[-] Exiting program due to user interruption.")
    except Exception as e:
        print(f"[-] An error occurred: {str(e)}")


if __name__ == "__main__":
    target_ip = input("Enter target IP address or IP range to scan: ")
    main(target_ip)
