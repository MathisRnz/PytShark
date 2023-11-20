#
# ______              ______ _                 _     
#(_____ \        _   / _____) |               | |    
# _____) )   _ _| |_( (____ | |__  _____  ____| |  _ 
#|  ____/ | | (_   _)\____ \|  _ \(____ |/ ___) |_/ )
#| |    | |_| | | |_ _____) ) | | / ___ | |   |  _ ( 
#|_|     \__  |  \__|______/|_| |_\_____|_|   |_| \_)
#       (____/ (1.5)         
#                      
from scapy.all import sniff, wrpcap, rdpcap, TCP, UDP, ICMP, IP
import sys

# Variable globale pour contrôler la capture
capture_running = True

def menu():
    print("Bienvenue sur PytSark !")
    print("1 - Capturer le trafic")
    print("2 - Analyser une trame")
    print("3 - Quitter")
    choice = input("Veuillez sélectionner une option : ")
    if choice == "2":
        print("1 - TCP")
        print("2 - UDP")
        print("3 - FTP")
        print("4 - ICMP")
        print("5 - SSH")
        choice_protocol = input("Veuillez sélectionner une option (chiffre ou nom du protocole) : ")
        protocol_mapping = {
            "1": "TCP",
            "2": "UDP",
            "3": "FTP",
            "4": "ICMP",
            "5": "SSH",
        }
        if choice_protocol in protocol_mapping:
            analyse_file("capture.pcap", protocol_mapping[choice_protocol])
            menu()
        else:
            print("Erreur. Veuillez sélectionner une option valide.")
            menu()
    elif choice == "1":
        interface = input("Veuillez entrer le nom de l'interface réseau : ")
        capture_frame("capture.pcap", interface)
        menu()
    elif choice == "3":
        print("Extinction de PytShark")
        sys.exit()
    else:
        print("Erreur. Veuillez sélectionner une option valide.")
        menu()

def capture_frame(file_name, interface):
    global capture_running  # Accéder à la variable globale
    print("Capture de paquets en cours... Appuyez sur 'CTRL+C' pour arrêter la capture.")
    try:
        packets = sniff(iface=interface, stop_filter=lambda x: not capture_running)
    except KeyboardInterrupt:
        pass
    wrpcap(file_name, packets)
    print(f"Nombre de paquets capturés : {len(packets)}")


def packet_info(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            return f"IP src/port: {src_ip}:{src_port}\nIP dest/port: {dst_ip}:{dst_port}"
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            return f"IP src/port: {src_ip}:{src_port}\nIP dest/port: {dst_ip}:{dst_port}"
        elif ICMP in packet:
            return f"IP source: {src_ip}\nIP destination: {dst_ip}"
    return ""

def analyse_file(file_name, protocol):
    print(f"Analyse du fichier : {file_name}")
    packets = rdpcap(file_name)  # Lire les paquets à partir du fichier capturé
    print(protocol)
    i = 0
    for packet in packets:
        # Analyser chaque paquet dans le fichier
        if protocol == "TCP" and TCP in packet:
            info = packet_info(packet)
            if info:
                print(info)
            analyse_tcp_packet(packet)
            i += 1
        elif protocol == "UDP" and UDP in packet:
            info = packet_info(packet)
            if info:
                print(info)
            analyse_udp_packet(packet)
            i += 1
        elif protocol == "FTP" in packet:
            info = packet_info(packet)
            if info:
                print(info)
            analyse_ftp_packet(packet)
            i += 1
        elif protocol == "ICMP" and ICMP in packet:
            info = packet_info(packet)
            if info:
                print(info)
            analyse_icmp_packet(packet)
            i += 1
        elif protocol == "SSH" and TCP in packet:
            info = packet_info(packet)
            if info:
                print(info)
            analyse_ssh_packet(packet)
            i += 1

    print(f"{i} trames capturées.")

def analyse_tcp_packet(packet):
    print("Analyse du paquet TCP ...")
    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        print("Port source :", src_port)
        print("Port destination :", dst_port)
    else:
        print("Ce n'est pas un paquet TCP.")


def analyse_udp_packet(packet):
    print("Analyse du paquet UDP ...")
    if packet.haslayer(UDP):
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        print("Port source:", src_port)
        print("Port destination:", dst_port)
    else:
        print("Ce n'est pas un paquet UDP.")


def analyse_ftp_packet(packet):
    print("Analyse du paquet FTP ...")
    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        print("Port source:", src_port)
        print("Port destination:", dst_port)
        # Extraction des données FTP via le payload
        payload = str(packet[TCP].payload)
        if 'USER' in payload:
            # Extraction username
            username = payload.split('USER ')[1].split('\r\n')[0]
            print("User:", username)
        elif 'PASS' in payload:
            # Extraction mot de passe
            password = payload.split('PASS ')[1].split('\r\n')[0]
            print("Mot de passe:", password)
        elif 'RETR' in payload:
            # Extraction fichier
            filename = payload.split('RETR ')[1].split('\r\n')[0]
            print("Fichier:", filename)
        else:
            print("Ce n'est pas un paquet FTP.")
            
def analyse_icmp_packet(packet):
    print("Analyse du paquet ICMP ...")
    if packet.haslayer(ICMP):
        icmp_layer = packet[ICMP]
        icmp_type = icmp_layer.type
        icmp_code = icmp_layer.code
        print("Type ICMP:", icmp_type)
        print("Type Code:", icmp_code)
    else:
        print("Ce n'est pas un paquet ICMP.")
        
        
def analyse_ssh_packet(packet):
    print("Analyse du paquet SSH ...")
    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        print("Port source:", src_port)
        print("Port destination:", dst_port)
        payload = str(packet[TCP].payload)
        if 'SSH' in payload:
            # Extraction des données SSH via le payload
            if 'SSH-2.0-' in payload:
                version = payload.split('SSH-2.0-')[1].split('\r\n')[0]
                print("Version SSH:", version)
    else:
        print("Ce n'est pas un paquet SSH.")

# Ajout de blocs try/except pour capturer les exceptions
try:
    # Appel à la fonction menu pour démarrer le programme
    menu()
except Exception as e:
    # Affichage de l'erreur en cas d'échec du script
    print("Une erreur s'est produite :", e)