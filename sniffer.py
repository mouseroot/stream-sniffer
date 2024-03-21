#Basic Packet Sniffer in Python
import curses
from pylibpcap.pcap import sniff
from pylibpcap import get_iface_list
from curses import wrapper

ESCAPE = 27
SPACE = 32

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

def main(stdscr):
    stdscr.clear()
    stdscr.addstr("Keyboard Sniffer (ESC to Exit)")
    

    while 1:
        keyc = stdscr.getch()
        if keyc == 27:
            stdscr.clear()
            stdscr.addstr(0,0,"Program Exit")
            stdscr.refresh()
        else:
            stdscr.clear()
            stdscr.addstr(3,0,f"Key Code: {keyc}\n")
            if keyc >= 65 and keyc <= 255:
                stdscr.addstr(4,0,f"Key: {chr(keyc)}")
            else:
                stdscr.addstr(4,0,f"Special Key (NON-ASCII)")
            stdscr.refresh()
        stdscr.refresh()


#wrapper(main)
do_sniff()