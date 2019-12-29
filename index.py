import scapy.all as scapy
from  optparse import OptionParser
import sys

def get_args():
    parser = OptionParser()
    parser.add_option(
        "-i",
        "--interface",
        dest="interface",
        help="the interface you want to scan from"
    )
    parser.add_option(
        "-n",
        "--network",
        dest="network",
        help="the network you want to scan"
    )

    (options ,args) = parser.parse_args()
    if not options.interface or not options.network :
        parser.error("Provide the interface and the network type --help for more info")

    return options

def scan(network ,interface):
    packet_ip = scapy.ARP(pdst=network) 
    packet_mac = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") 
    # get all the attribute of that object scapy.ls(packet_TCP)
    # get info about this object packet_TCP.show()
    # to send a packet use [scapy.send]
    # to send a packet and receive the response use [scapy.sr(Ether/Ip/Transport Layer)]
    print("[+] Scaning...")
    try :
        (responses , unresponsed) = scapy.srp(
            packet_mac/packet_ip,
            iface=interface,
            timeout=1,
            verbose=False
        )
    except :
        print("the interface or Network you provided is invalid")
        print("Provide a valid interface and network please!")
        sys.exit()

    result_dict = {}
        # responsed is a list of tuples each tuple has  2 objects
        # one for the request(ARP request) information 
        # and the second is for the response information
    for res in responses:   
        result_dict[res[1].psrc] = res[1].hwsrc
    return result_dict

def show_result(result):
    are_or_is = "are : " if len(result.keys()) > 1 else "is : "
    print('There '+ are_or_is + str(len(result.keys())) + " devices in this Network") 
    print('********************************************************')
    print('\t\tIP\t\t|\t\tMAC\t\t')
    for ip in result.keys():
        print('\t' + ip+'\t\t' + '|' +'\t'+ result[ip] +'\t\t')
        


options = get_args()
result = scan(options.network ,options.interface)
show_result(result)