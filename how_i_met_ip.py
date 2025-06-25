from scapy.all import conf, get_working_ifaces
from struct import unpack
from typing import Tuple

BROADCAST_MAC = "ffffffffffff"


def main():
    iface = get_working_ifaces()[3]
    sock = conf.L2socket(iface=iface, promisc=True)  # Create the socket
    while True:
        get_packet_for_me(sock, iface)


def get_packet_for_me(socket, iface):
    my_macs = (remove_colons(iface.mac), BROADCAST_MAC)

    while True:
        recv: Tuple = (None, None, None)
        while not any(recv):
            recv = socket.recv_raw()  # Receive data

        preamble, dst_mac = unpack("6s6s", recv[1][:12])
        if dst_mac.hex() in my_macs:
            return recv


def remove_colons(string: str) -> str:
    return "".join(filter(lambda x: x != ":", string))


if __name__ == "__main__":
    main()
