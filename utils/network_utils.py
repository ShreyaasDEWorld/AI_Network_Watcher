import socket
import ipaddress

def get_network_range():

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]

    finally:
        s.close()

    network = ipaddress.IPv4Network(
        f"{ip}/24",
        strict=False
    )

    return str(network)