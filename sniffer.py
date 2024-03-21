#Basic Packet Sniffer in Python
from pylibpcap.pcap import sniff
from pylibpcap import get_iface_list


def do_sniff():
    print("[💾] Avaliable Devices")
    for i,d_name in enumerate(get_iface_list()):
        print(f"{i}.\t{d_name}")

    print("[💿] Enter Device Number")
    dev = int(input(": "))
    dev = get_iface_list()[dev]

    print("[🖊] Enter a filter")
    filter_str = input("Filter: ")
    print("[✔] Entering Sniffer Mode")
    for packet_len, time, buffer in sniff(dev, filters=filter_str, count=-1, promisc=1, out_file=f"captures/{dev}.pcap", timeout=1000):
        print(f"[📏]:\tPayload Length {packet_len}")
        print(f"[⌚]:\tPayload Time {time}")
        try:
            print(f'[💲]:\tPayload Data: {buffer.decode("utf-8")}')
        except UnicodeDecodeError:
            print(f'[💲]:\tPayload Data: {buffer}')


do_sniff()