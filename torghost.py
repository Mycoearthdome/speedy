#!/opt/virtualenv/torghost/bin/python3
# -*- coding: utf-8 -*-

import os
import sys
import getopt
from requests import get
import subprocess
import time
import signal
from stem import Signal
from stem.control import Controller
from packaging import version

VERSION = "3.1.1"

IP_API = "https://api.ipify.org/?format=json"

LATEST_RELEASE_API = "https://api.github.com/repos/SusmithKrishnan/torghost/releases/latest"


class bcolors:

    BLUE = '\033[94m'
    GREEN = '\033[92m'
    RED = '\033[31m'
    YELLOW = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    BGRED = '\033[41m'
    WHITE = '\033[37m'


def t():
    current_time = time.localtime()
    ctime = time.strftime('%H:%M:%S', current_time)
    return '[' + ctime + ']'


def sigint_handler(signum, frame):
    print("User interrupt ! shutting down")
    stop_torghost()


def logo():
    print(bcolors.RED + bcolors.BOLD)
    print("""
      _____           ____ _               _
     |_   _|__  _ __ / ___| |__   ___  ___| |_
       | |/ _ \| '__| |  _| '_ \ / _ \/ __| __|
       | | (_) | |  | |_| | | | | (_) \__ \ |_
       |_|\___/|_|   \____|_| |_|\___/|___/\__|
	{V} - github.com/SusmithKrishnan/torghost

    """.format(V=VERSION))
    print(bcolors.ENDC)


def usage():
    logo()
    print("""
    Torghost usage:
    -s    --start       Start Torghost
    -r    --switch      Request new tor exit node
    -x    --stop        Stop Torghost
    -h    --help        print(this help and exit)
    -u    --update      check for update

    """)
    sys.exit()


#def ip():
#    while True:
#        try:
#            jsonRes = get(IP_API).json()
#            ipTxt = jsonRes["ip"]
#        except:
#            continue
#        break
#    return ipTxt


def check_root():
    if os.geteuid() != 0:
        print("You must be root; Say the magic word 'sudo'")
        sys.exit(0)


signal.signal(signal.SIGINT, sigint_handler)

TorrcCfgString = \
    """
VirtualAddrNetwork 10.0.0.0/10
AutomapHostsOnResolve 1
TransPort 9040
ControlPort 9051
DNSPort 5353
RunAsDaemon 1
"""

resolvString = 'nameserver 127.0.0.1'

Torrc = '/etc/tor/torghostrc'
resolv = '/etc/resolv.conf'


def start_torghost():
    print(t() + ' Always check for updates using -u option')
    os.system('sudo cp /etc/resolv.conf /etc/resolv.conf.bak')
    if os.path.exists(Torrc) and TorrcCfgString in open(Torrc).read():
        print(t() + ' Torrc file already configured')
    else:

        with open(Torrc, 'w') as myfile:
            print(t() + ' Writing torcc file ')
            myfile.write(TorrcCfgString)
            print(bcolors.GREEN + '[done]' + bcolors.ENDC)
    if resolvString in open(resolv).read():
        print(t() + ' DNS resolv.conf file already configured')
    else:
        with open(resolv, 'w') as myfile:
            print(t() + ' Configuring DNS resolv.conf file.. '),
            myfile.write(resolvString)
            print(bcolors.GREEN + '[done]' + bcolors.ENDC)

    print(t() + ' Stopping tor service '),
    os.system('sudo systemctl stop tor')
    os.system('sudo fuser -k 9051/tcp > /dev/null 2>&1')
    print(bcolors.GREEN + '[done]' + bcolors.ENDC)
    print(t() + ' Starting new tor daemon '),
    os.system('sudo -u jordan tor -f /etc/tor/torghostrc > /dev/null'
              )
    print(bcolors.GREEN + '[done]' + bcolors.ENDC)
    print(t() + ' setting up iptables rules'),

    iptables_rules = \
        """
	iptables -F
	iptables -t nat -F
	iptables -t mangle -F
        iptables -P INPUT ACCEPT
        iptables -P FORWARD ACCEPT
        iptables -P OUTPUT ACCEPT
	iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
	ebtables -t nat -F
	iptables -A INPUT -p tcp --dport 22 -j ACCEPT
	iptables -A INPUT -p udp --dport 53 -j ACCEPT
	iptables -A INPUT -s 127.0.0.0/8 -j ACCEPT
	iptables -A INPUT -i em1 -j ACCEPT
	iptables -A INPUT -i em2 -j ACCEPT
	iptables -A INPUT -i lo -p tcp --dport 9040 -j ACCEPT
	iptables -t mangle -A OUTPUT -j TTL --ttl-dec 1
	
	ebtables -t nat -A POSTROUTING -o em1 -j snat --to-src 74:86:7a:cf:94:7e 

	iptables -t nat -A OUTPUT -o em1 -p tcp -j REDIRECT --to-ports 9040

	ebtables -t nat -A OUTPUT -o lo -j dnat --to-dst 54:b2:03:f1:19:81

	iptables -t nat -A OUTPUT -o lo -s 192.168.2.115 -j DNAT --to-destination 172.16.0.102
	iptables -t nat -A OUTPUT -p udp --dport 53 -j DNAT --to-destination 127.0.0.1:5353 
	iptables -t nat -A POSTROUTING -o em2 -p udp --dport 53 -j SNAT --to-source 172.16.0.226
	iptables -t nat -A POSTROUTING -o lo -j SNAT --to-source 192.168.2.115
	iptables -t nat -A POSTROUTING -o em1 -j SNAT --to-source 192.168.2.115
	
	iptables -A OUTPUT -d 127.0.0.0/8 -j ACCEPT
	iptables -A OUTPUT -d 192.168.2.115 -j ACCEPT
	iptables -A FORWARD -i em2 -o em1 -p udp --dport 53 -j ACCEPT
	iptables -A FORWARD -i em1 -o em2 -p udp --dport 53 -j ACCEPT
	iptables -A FORWARD -i em2 -o lo -p tcp -j ACCEPT
	iptables -A FORWARD -i lo -o em2 -p tcp -j ACCEPT
	iptables -A FORWARD -i lo -o em1 -p tcp -j ACCEPT
	iptables -A FORWARD -i em1 -o lo -p tcp -j ACCEPT
	iptables -A OUTPUT -p tcp --sport 22 -j ACCEPT
	iptables -A INPUT -j DROP
	""" \
        #% subprocess.getoutput('id -ur jordan')

    os.system(iptables_rules)
    print(bcolors.GREEN + '[done]' + bcolors.ENDC)
 #   print(t() + ' Fetching current IP...')
 #   print(t() + ' CURRENT IP : ' + bcolors.GREEN + ip() + bcolors.ENDC)


def stop_torghost():
    print(bcolors.RED + t() + 'STOPPING torghost' + bcolors.ENDC)
    print(t() + ' Flushing iptables, resetting to default'),
    os.system('mv /etc/resolv.conf.bak /etc/resolv.conf')
    IpFlush = \
        """
	iptables -P INPUT ACCEPT
	iptables -P FORWARD ACCEPT
	iptables -P OUTPUT ACCEPT
	iptables -t nat -F
	iptables -t mangle -F
	iptables -F
	iptables -X
	ebtables -t nat -F
	iptables -t nat -A POSTROUTING -o em1 -j MASQUERADE
	"""
    os.system(IpFlush)
    os.system('sudo fuser -k 9051/tcp > /dev/null 2>&1')
    print(bcolors.GREEN + '[done]' + bcolors.ENDC)
    print(t() + ' Restarting Network manager'),
    os.system('service network-manager restart')
    print(bcolors.GREEN + '[done]' + bcolors.ENDC)
 #   print(t() + ' Fetching current IP...')
 #   time.sleep(3)
 #   print(t() + ' CURRENT IP : ' + bcolors.GREEN + ip() + bcolors.ENDC)


def switch_tor():
    print(t() + ' Please wait...')
    time.sleep(7)
    print(t() + ' Requesting new circuit...'),
    with Controller.from_port(port=9051) as controller:
        controller.authenticate()
        controller.signal(Signal.NEWNYM)
    print(bcolors.GREEN + '[done]' + bcolors.ENDC)
#    print(t() + ' Fetching current IP...')
#    print(t() + ' CURRENT IP : ' + bcolors.GREEN + ip() + bcolors.ENDC)


def check_update():
    print(t() + ' Checking for update...')
    jsonRes = get(LATEST_RELEASE_API).json()
    newversion = jsonRes["tag_name"][1:]
    print(newversion)
    if version.parse(newversion) > version.parse(VERSION):
        print(t() + bcolors.GREEN + ' New update available!' + bcolors.ENDC)
        print(t() + ' Your current TorGhost version : ' + bcolors.GREEN + VERSION + bcolors.ENDC)
        print(t() + ' Latest TorGhost version available : ' + bcolors.GREEN + newversion + bcolors.ENDC)
        yes = {'yes', 'y', 'ye', ''}
        no = {'no', 'n'}

        choice = input(
            bcolors.BOLD + "Would you like to download latest version and build from Git repo? [Y/n]" + bcolors.ENDC).lower()
        if choice in yes:
            os.system(
                'cd /tmp && git clone  https://github.com/SusmithKrishnan/torghost')
            os.system('cd /tmp/torghost && sudo ./build.sh')
        elif choice in no:
            print(t() + " Update aborted by user")
        else:
            print("Please respond with 'yes' or 'no'")
    else:
        print(t() + " Torghost is up to date!")


def main():
    check_root()
    if len(sys.argv) <= 1:
        check_update()
        usage()
    try:
        (opts, args) = getopt.getopt(sys.argv[1:], 'srxhu', [
            'start', 'stop', 'switch', 'help', 'update'])
    except (getopt.GetoptError):
        usage()
        sys.exit(2)
    for (o, a) in opts:
        if o in ('-h', '--help'):
            usage()
        elif o in ('-s', '--start'):
            start_torghost()
        elif o in ('-x', '--stop'):
            stop_torghost()
        elif o in ('-r', '--switch'):
            switch_tor()
        elif o in ('-u', '--update'):
            check_update()
        else:
            usage()


if __name__ == '__main__':
    main()
