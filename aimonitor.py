#!/usr/bin/env python
#
# NCurses interface for controling and instance of pyaiengine.
#
# Copyright (C) 2013-2018  Luis Campo Giralte
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Library General Public
# License as published by the Free Software Foundation; either
# version 2 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Library General Public License for more details.
#
# You should have received a copy of the GNU Library General Public
# License along with this library; if not, write to the
# Free Software Foundation, Inc., 51 Franklin St, Fifth Floor,
# Boston, MA  02110-1301, USA.
#
# Written by Luis Campo Giralte <luis.camp0.2009@gmail.com> 
#
""" Script for check on real time the most important functionalities 
    of AIengine """
from threading import Thread
import optparse
import curses
import socket
import time
import itertools
import sys, signal
# import ast

try:
    import psutil
except:
    print("Install python-psutils for use the aimonitor")
    sys.exit(-1)

try:
    import GeoIP
    geoip = GeoIP.new(GeoIP.GEOIP_MEMORY_CACHE)
except:
    pass 

process_header = ("CPU", "Memory")
flows_header = ("Flow", "Bytes", "Packets")
process_template = "{0:<8}{1:<8}"
flows_template = "{0:<110}{1:<10}{2:<8}"

def option_parser():

    def get_comma_separated_args(option, opt, value, parser):
        setattr(parser.values, option.dest, value.split(','))

    p = optparse.OptionParser()

    p.add_option("-p", "--port", dest="port", default=0,
        type="int", help="Specify the local port.")

    p.add_option("-v", "--verbose",dest="verbose", default=False, action="store_true",
        help="Shows extra messages.")

    return p

class ConnectionManager (object):
    def __init__(self, host, port):
        self.__sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.__host = host
        self.__port = port
        self.__lines = []
        self.__status = "DISCONNECT"
        self.__sock.settimeout(1)
        self.__data = None

    def __del__(self):
        self.__sock.close()

    def send_command(self, command):
        try:
            self.__sock.sendto(command, (self.__host, self.__port))
            self.__data, server = self.__sock.recvfrom(1024 * 16)

            self.__lines = self.__data.split("\n")
            self.__status = "CONNECT"
        except (socket.error, Exception) as e:
            self.__status = "DISCONNECT"

    @property
    def data(self):
        return self.__data

    @property
    def status(self):
        return self.__status

    @property
    def lines(self):
        return self.__lines

class MethodDispatcher (object):
    def __init__(self):
        self.__funcs = {}

    def add_method(self, key, function):
       self.__funcs[key] = function

    def __call__(self, key, *args):
        if (key in self.__funcs):
            self.__funcs[key](*args)
            args[0].refresh()

    def __contains__(self, value):
        return value in self.__funcs

class DNSResolver (object):
    def __init__(self):
        self.__cache = {}
        self.__enable = False
        self.__address = list()
        self.__thread = Thread(target = self.__resolver_thread, args = ())
        self.__thread.daemon = True
        self.__thread.start()

    def __handler(self, signum, frame):
        pass

    def __resolver_thread(self, *kargs):
        while True:
            try:
                ip = self.__address.pop()
            except IndexError:
                time.sleep(1)
                continue
            try:
                ret = socket.gethostbyaddr(ip)
                self.__cache[ip] = ret[0]
            except:
                pass 
            time.sleep(1)

    def __call__(self, ip):
        if ip in self.__cache:
            value = self.__cache[ip]
        else:
            self.__address.append(ip)
            value = "Unknown"
        return value
    
    @property
    def enable(self):
        return self.__enable

    @enable.setter
    def enable(self, value):
        self.__enable = value

    @property
    def total_items(self):
        return len(self.__cache)

def get_process_stats(port):

    proc_cpu = 0
    proc_memory = 0

    for proc in psutil.process_iter():
        try:
            cmdline = proc.cmdline()
            if (len(cmdline) > 0):
                if "python" in cmdline[0]:
                    for n in proc.connections():
                        if (n.laddr[1] == port):
                            proc_cpu = proc.cpu_percent()
                            proc_memory = proc.memory_percent()
                            return proc_cpu, proc_memory
        except Exception as e:
            pass

    return proc_cpu, proc_memory

def show_menu(win, conn):
    win.clear()
    win.border(1)
    win.addstr(1, 2, "AIEngine Administration Console " + time.ctime())
    if "DISCONNECT" in conn.status:
        win.addstr(1, 60, str(conn.status) , curses.color_pair(1))
    else:
        win.addstr(1, 60, str(conn.status) , curses.color_pair(2))
    win.addstr(3, 3, "1 - Show HTTP network flows          a - Show HTTP cache   d - Release HTTP cache")
    win.addstr(4, 3, "2 - Show SSL network flows           b - Show SSL cache    e - Release SSL cache")
    win.addstr(5, 3, "3 - Show DNS network flows           c - Show DNS cache    f - Release DNS cache")
    win.addstr(6, 3, "4 - Show TCPGeneric network flows    j - Show TCP IPSet    g - Release TCP traffic")
    win.addstr(7, 3, "5 - Show UDPGeneric network flows    k - Show UDP IPSet    h - Release UDP traffic")
    win.addstr(8, 3, "6 - Show Protocol statistics         l - Show TCP Regex    z - Show HTTP Matchs")
    win.addstr(9, 3, "7 - Show current packet              m - Show UDP Regex    x - Show SSL Matchs")
    win.addstr(10, 3, "8 - Show Anomalies                   i - Resolve IPs(%d)" % dns.total_items)
    win.addstr(10, 62, "w - Show DNS Matchs")

    win.addstr(11, 3, "q - Exit")
    win.refresh()

def show_packet_dispatcher_status(win, conn):
    win.clear()
    win.border(1)

    ln = 2
    conn.send_command("pd.show()")
    for l in conn.lines[1:]:
        win.addstr(ln, 3, l.strip())
        ln += 1
    win.refresh()

def show_process_status(win, conn):
    win.clear()
    win.border(1)

    proc_cpu, proc_memory = get_process_stats(3000)

    item = (proc_cpu, proc_memory)

    win.addstr(1, 3, process_template.format(*process_header))
    win.addstr(3, 3, process_template.format(*item))

    win.refresh()


def show_flows(win, conn, name):
    win.clear()
    win.border(1)

    conn.send_command("st.show_flows('%s', 35)" % name)

    y, x = win.getmaxyx(); 
    win.addstr(1, 3, flows_template.format(*flows_header))
    ln = 3
    for l in conn.lines[3: y - 2]:
        if (l.startswith("[")):
            a = l.split()
            fid = a[0].replace("[", "").replace("]", "").split(":")
            ipsrc = fid[0] 
            portsrc = fid[1] 
            proto = fid[2] 
            ipdst = fid[3] 
            portdst = fid[4] 
            country = ""
            name = ""
            if (geoip):
                country = "[%s]" % geoip.country_name_by_addr(ipdst) 

            if (dns.enable == True):
                name = "[%s]" % dns(ipdst) 
           
            regex_str = ""
            other = l.split("Regex")
            if (len(other) > 1):
                regex_str = " Matchs:%s" % other[1]
            cad = "[%s:%s]%s[%s:%s]%s%s%s" % (ipsrc, portsrc, proto, ipdst, portdst, country, name, regex_str)
            items =(cad, a[1], a[2])

            win.addstr(ln, 3, flows_template.format(*items))
            ln += 1

    win.refresh()

def show_http_flows(win, conn):
    show_flows(win, conn, "http")

def show_ssl_flows(win, conn):
    show_flows(win, conn, "ssl")

def show_dns_flows(win, conn):
    show_flows(win, conn, "dns")

def show_tcp_flows(win, conn):
    show_flows(win, conn, "tcpgeneric")

def show_udp_flows(win, conn):
    show_flows(win, conn, "udpgeneric")

def show_protocol_statistics(win, conn):
    win.clear()
    win.border(1)

    conn.send_command("st.show_protocol_statistics()")

    if (len(conn.lines) > 0):
        y, x = win.getmaxyx(); 
        try:
            win.addstr(1, 3, conn.lines[1].lstrip())
            ln = 3
            for l in conn.lines[2: y - 2]:
                win.addstr(ln, 3, l.lstrip())
                ln += 1
        except:
            pass

    win.refresh()

def show_generic_cache(win, conn, name):

    win.clear()
    win.border(1)

    conn.send_command("st.show_cache('%s')" % name)

    if (len(conn.lines) > 0):
        y, x = win.getmaxyx(); 
        try:
            win.addstr(1, 3, conn.lines[0].lstrip())
            ln = 3
            for l in conn.lines[1: y - 3]:
                win.addstr(ln, 3, l.lstrip())
                ln += 1
        except:
            pass

    win.refresh()

def show_http_cache(win, conn):
    show_generic_cache(win, conn, "http")

def show_dns_cache(win, conn):
    show_generic_cache(win, conn, "dns")

def show_ssl_cache(win, conn):
    show_generic_cache(win, conn, "ssl")

def clear_cache(win, conn, name):
    conn.send_command("st.release_cache('%s')" % name)
    win.clear()

def clear_http_cache(win, conn):
    clear_cache(win, conn, "http")

def clear_ssl_cache(win, conn):
    clear_cache(win, conn, "ssl")

def clear_dns_cache(win, conn):
    clear_cache(win, conn, "dns")

def clear_flows(win, conn, name):
    conn.send_command("st.%s_flow_manager.flush()" % name)

def clear_tcp_flows(win, conn):
    clear_flows(win, conn, "tcp")

def clear_udp_flows(win, conn):
    clear_flows(win, conn, "udp")

def show_current_packet(win, conn):

    win.clear()
    win.border(1)

    conn.send_command("pd.show_current_packet()")

    y, x = win.getmaxyx(); 
    try:
        win.addstr(1, 3, conn.lines[0].lstrip())
        ln = 3
        for l in conn.lines[1: y - 3]:
            win.addstr(ln, 3, l.lstrip())
            ln += 1
    except:
        pass

    win.refresh()

def show_anomalies(win, conn):

    win.clear()
    win.border(1)

    conn.send_command("st.show_anomalies()")

    y, x = win.getmaxyx(); 
    try:
        win.addstr(1, 3, conn.lines[0].lstrip())
        ln = 3
        for l in conn.lines[1: y - 3]:
            win.addstr(ln, 3, l.lstrip())
            ln += 1
    except:
        pass

    win.refresh()

def show_ipset(win, conn, cmd):
    win.clear()
    win.border(1)

    conn.send_command(cmd)

    y, x = win.getmaxyx();
    try:
        win.addstr(1, 3, conn.lines[0].lstrip())
        ln = 3
        for l in conn.lines[1: y - 3]:
            win.addstr(ln, 3, l.lstrip())
            ln += 1
    except:
        pass

    win.refresh()

def show_tcp_ipset(win, conn):
    show_ipset(win, conn, "st.tcp_ip_set_manager.show()")

def show_udp_ipset(win, conn):
    show_ipset(win, conn, "st.udp_ip_set_manager.show()")

def show_regex(win, conn, cmd):
    win.clear()
    win.border(1)

    conn.send_command(cmd)

    y, x = win.getmaxyx();
    try:
        win.addstr(1, 3, conn.lines[0].lstrip())
        ln = 3
        for l in conn.lines[1: y - 3]:
            win.addstr(ln, 3, l.lstrip().split("Callback")[0])
            ln += 1
    except:
        pass

    win.refresh()

def show_tcp_regex(win, conn):
    show_regex(win, conn, "st.tcp_regex_manager.show()")

def show_udp_regex(win, conn):
    show_regex(win, conn, "st.udp_regex_manager.show()")

def show_http_matchs(win, conn):
    show_regex(win, conn, "http_names.show()")

def show_ssl_matchs(win, conn):
    show_regex(win, conn, "ssl_names.show()")

def show_dns_matchs(win, conn):
    show_regex(win, conn, "dns_names.show()")

def curses_main_loop(screen, port):

    conn = ConnectionManager("localhost", port)

    try:
        curses.curs_set(0)
    except:
        pass

    curses.start_color()
    curses.use_default_colors()
    for i in range(0, curses.COLORS):
        curses.init_pair(i, i, -1);

    screen.box()
    y,x = screen.getmaxyx()
    screen.nodelay(1)

    """ Good resolution x >= 226 and y >= 53 """

    if ((x < 224) and (y < 50)):
        raise Exception("No valid resolution x=%d y=%d" % (x, y))

    half_x = x / 2
    half_y = y / 2
     
    cuarter_x = half_x / 2
    cuarter_y = half_y / 2

    """ Create the menu window """
    menu_window = curses.newwin(14, half_x - 1, 1, 1)
    menu_window.border(1)
    
    """ Create the PacketDispatcher window """
    packet_dispatcher_window = curses.newwin(14, cuarter_x, 1, half_x)
    packet_dispatcher_window.border(1)

    """ Create the process status window """
    process_window = curses.newwin(14, cuarter_x , 1, half_x + cuarter_x )
    process_window.border(1)

    """ Create the flows window """
    flows_window = curses.newwin(y - 16, half_x + (cuarter_x / 2), 15, 1)
    flows_window.border(1)

    """ Create the cache window """
    cache_window = curses.newwin(y - 16, half_x - (cuarter_x/2) - 2, 15, half_x + (cuarter_x/2) + 1)
    cache_window.border(1)

    md_5seconds = MethodDispatcher()
    md_5seconds.add_method(ord('1'), show_http_flows)
    md_5seconds.add_method(ord('2'), show_ssl_flows)
    md_5seconds.add_method(ord('3'), show_dns_flows)
    md_5seconds.add_method(ord('4'), show_tcp_flows)
    md_5seconds.add_method(ord('5'), show_udp_flows)
    md_5seconds.add_method(ord('6'), show_protocol_statistics)

    md_10seconds = MethodDispatcher()
    md_10seconds.add_method(ord('a'), show_http_cache)
    md_10seconds.add_method(ord('b'), show_ssl_cache)
    md_10seconds.add_method(ord('c'), show_dns_cache)
    md_10seconds.add_method(ord('8'), show_anomalies)
    md_10seconds.add_method(ord('j'), show_tcp_ipset)
    md_10seconds.add_method(ord('k'), show_udp_ipset)
    md_10seconds.add_method(ord('l'), show_tcp_regex)
    md_10seconds.add_method(ord('m'), show_udp_regex)
    md_10seconds.add_method(ord('z'), show_http_matchs)
    md_10seconds.add_method(ord('x'), show_ssl_matchs)
    md_10seconds.add_method(ord('w'), show_dns_matchs)

    md_cache = MethodDispatcher()
    md_cache.add_method(ord('d'), clear_http_cache)
    md_cache.add_method(ord('e'), clear_ssl_cache)
    md_cache.add_method(ord('f'), clear_dns_cache)
    md_cache.add_method(ord('g'), clear_tcp_flows)
    md_cache.add_method(ord('h'), clear_udp_flows)

    menu_window_refresh = last_2sec_timer = last_5sec_timer = last_10sec_timer = current_time = time.time()

    screen.refresh()
    menu_window.refresh()

    show_menu(menu_window, conn)
    show_packet_dispatcher_status(packet_dispatcher_window, conn)
    show_process_status(process_window, conn)
    user_option = 0
    active_5sec_option = 0
    active_10sec_option = 0
    force_write_screen = False
    while user_option != ord('q'):

        """ Refresh the menu every 1 second """
        if (current_time - menu_window_refresh > 1):
            show_menu(menu_window, conn)
            menu_window_refresh = current_time

        """ Refresh the options every 2 seconds """
        if ((current_time - last_2sec_timer > 2.5)):
            show_packet_dispatcher_status(packet_dispatcher_window, conn)
            show_process_status(process_window, conn)
            last_2sec_timer = current_time

        """ Refresh the options every 5 seconds """
        if (current_time - last_5sec_timer > 5):
            md_5seconds(active_5sec_option, flows_window, conn)
            last_5sec_timer = current_time

        """ Refresh the options every 10 seconds """
        if (current_time - last_10sec_timer > 10):
            md_10seconds(active_10sec_option, cache_window, conn)
            last_10sec_timer = current_time

        try:
            user_option = screen.getch()
        except:
            user_option = -1

        if (user_option != -1):
            if (user_option in md_5seconds):
                active_5sec_option = user_option
                flows_window.clear()
                flows_window.refresh()
                md_5seconds(active_5sec_option, flows_window, conn)

            elif (user_option in md_10seconds):
                active_10sec_option = user_option
                md_10seconds(active_10sec_option, cache_window, conn)

            if (user_option == ord('6')):
                active_5sec_option = user_option
                md_5seconds(active_5sec_option, flows_window, conn)

            if (user_option == ord('7')):
                show_current_packet(cache_window, conn)
                active_10sec_option = -1

            if (user_option in md_cache):
                md_cache(user_option, cache_window, conn)
            
            if (user_option == ord('i')):
                dns.enable = not dns.enable

            last_user_option = user_option
            force_write_screen = True

        screen.refresh()
        current_time = time.time()

if __name__ == '__main__':

    (options, args) = option_parser().parse_args()

    if (int(options.port) == 0):
        print("The parameter 'port' is mandatory")
        option_parser().print_help()
        sys.exit(-1)

    dns = DNSResolver()

    curses.wrapper(curses_main_loop, options.port)

