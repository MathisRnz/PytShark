#
# ______              ______ _                 _     
#(_____ \        _   / _____) |               | |    
# _____) )   _ _| |_( (____ | |__  _____  ____| |  _ 
#|  ____/ | | (_   _)\____ \|  _ \(____ |/ ___) |_/ )
#| |    | |_| | | |_ _____) ) | | / ___ | |   |  _ ( 
#|_|     \__  |  \__|______/|_| |_\_____|_|   |_| \_)
#       (____/ (1.2)                                      
# Execution sur VM Ubuntu/Debian avec le module "Python3-scapy"
from scapy.all import sniff, wrpcap, rdpcap, TCP, UDP, ICMP
import sys

def menu():
    print("Bienvenue sur PytSark !")
    print("1 - Capturer le trafic")
    print("2 - Analyser une trame")
    print("3 - Quitter")
    choice = input("Veuillez sélectionner une option : ")
    if choice == "2":
        print("TCP")
        print("UDP")
        print("FTP")
        print("ICMP")
        print("SSH")
        choice_protocol = input("Veuillez sélectionner une option : ")
        if choice_protocol == "TCP":
            analyse_file("test.pcap", "TCP")
            menu()
        elif choice_protocol == "UDP":
            analyse_file("test.pcap", "UDP")
            menu()
        elif choice_protocol == "FTP":
            analyse_file("test.pcap", "FTP")
            menu()
        elif choice_protocol == "ICMP":
            analyse_file("test.pcap", "ICMP")
            menu()
        elif choice_protocol == "SSH":
            analyse_file("test.pcap", "SSH")
            menu()
        else:
            print("Erreur. Veuillez sélectionner une option valide.")
            menu()
    elif choice == "1":
            capture_frame("test.pcap")
            menu()
    elif choice == "3":
        print("Extinction de PytShark")
        sys.exit()
    else:
        print("Erreur. Veuillez sélectionner une option valide.")
        menu()

 
def capture_frame(file_name):
    print("Capture de la trame")
    packets = sniff(count=10, iface='enp0s3') # Capturer une seule trame
    wrpcap(file_name, packets) # Stocker la trame capturée dans un fichier
    print(f"Trame capturée et stockée dans le fichier : {file_name}")


def analyse_file(file_name, protocol):
    print(f"Analyse du fichier : {file_name}")
    packets = rdpcap(file_name) # Lire les paquets à partir du fichier capturé
    print(protocol)
    i=0
    for packet in packets:
        print("Numéro de paquet :",i)
        i=i+1
        # Analyser chaque paquet dans le fichier
        if protocol == "TCP":
            analyse_tcp_packet(packet)
        elif protocol == "UDP":
            analyse_udp_packet(packet)
        elif protocol == "FTP":
            analyse_ftp_packet(packet)
        elif protocol == "ICMP":
            analyse_icmp_packet(packet)
        elif protocol == "SSH":
            analyse_ssh_packet(packet)


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
