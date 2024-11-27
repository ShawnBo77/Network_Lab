import networkx as nx
from mininet.net import Mininet
from mininet.node import Controller, RemoteController
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel
import subprocess

# return (switch, port_num)
def get_host_switch(host): 
    host_switch = {"H1":("S1", 1), "H2":("S3", 1), "H3":("S7", 2), "H4":("S5", 3), "H5":("S5", 4)
    , "H6":("S8", 3), "H7":("S8", 4), "H8":("S6", 1), "H9":("S4", 5)}
    if host[0] != "H":
        host = ip_to_hostname(host)
    return host_switch[host]

def find_two_shortest_paths(s, t):

    if s == t:
        return [[s]]

    G = nx.Graph()

    G.add_edge("S1", "S2")
    G.add_edge("S1", "S3")
    G.add_edge("S1", "S6")
    G.add_edge("S2", "S3")
    G.add_edge("S2", "S4")
    G.add_edge("S2", "S5")
    G.add_edge("S2", "S7")
    G.add_edge("S3", "S4")
    G.add_edge("S4", "S5")
    G.add_edge("S4", "S8")
    G.add_edge("S5", "S7")
    G.add_edge("S5", "S8")
    G.add_edge("S6", "S7")

    path1 = nx.shortest_path(G, source = s, target = t)
    # print("path1:", path1)

    middle_switch = path1[1:-1]
    # print(middle_switch)

    for switch in middle_switch:
        G.remove_node(switch)

    path2 = nx.shortest_path(G, source = s, target = t)
    # print("path2:", path2)

    return [path1, path2]

def get_link_port(switch1, switch2):
    switch_port = {"S1S2":(3,1), "S1S3":(4,2), "S1S6":(2,3), "S2S3":(5,3), "S2S4":(4,2), "S2S5":(3,1), "S2S7":(2,4),
      "S3S4":(4,1), "S4S5":(3,6), "S4S8":(4,1), "S5S7":(2,3), "S5S8":(5,2), "S6S7":(2,1)}
    if int(switch1[1]) > int(switch2[1]):
        ports = switch_port[switch2.upper()+switch1.upper()]
        return (ports[1], ports[0])
    return switch_port[switch1.upper()+switch2.upper()]

def get_switch(switch_name):
        switches_dict = {"S1":S1, "S2":S2, "S3":S3, "S4":S4, "S5":S5, "S6":S6, "S7":S7, "S8":S8}
        return switches_dict[switch_name.upper()]

def network_topo(net, source, target, path):
    for i in range(len(path)-1):
        if not net.linksBetween(net.get(path[i].lower()), net.get(path[i+1].lower())):
            ports = get_link_port(path[i], path[i+1])
            # print("net.addLink(", path[i], ", ", path[i+1], ", port1=",ports[0], ", port2=",ports[1], ")", sep="")
            switch1 = get_switch(path[i])
            switch2 = get_switch(path[i+1])
            switch1_port = ports[0]
            switch2_port = ports[1]
            net.addLink(switch1, switch2, port1=switch1_port, port2=switch2_port)
            switch1.cmd(f'ifconfig {path[i]}-eth{switch1_port} up')
            switch2.cmd(f'ifconfig {path[i+1]}-eth{switch2_port} up')
        
def hostname_to_ip(hostname):
    host_num = int(hostname[1:])
    return f"10.0.0.{host_num}"

def ip_to_hostname(ip):
    host_num = int(ip.split(".")[-1])
    return f"H{host_num}"

def clear_flows(switch):
    try:
        cmd = f"sudo ovs-ofctl del-flows {switch}"
        subprocess.run(cmd, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Failed to add flow rule: {e}")

def allow_ARP(switch, priority):
    try:
        cmd = f"sudo ovs-ofctl add-flow {switch} \"priority={priority},dl_type=0x0806,action=flood\""
        subprocess.run(cmd, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Failed to add flow rule: {e}")

def add_openflow_rule(switch, rule):
    try:
        cmd = f"sudo ovs-ofctl add-flow {switch} \"{rule}\""
        subprocess.run(cmd, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Failed to add flow rule: {e}")

def add_openflow_rules(source_ip, target_ip, path, priority, table_num):
    if len(path) == 1:
        # source to target
        # untracking
        # print(f"add_openflow_rule({path[0]},priority={priority},dl_type=0x0800,nw_src={source_ip},\
        #         nw_dst={target_ip},ct_state=-trk,actions=ct(table={table_num}))")
        add_openflow_rule(path[0], f"priority={priority},dl_type=0x0800,nw_src={source_ip},\
                    nw_dst={target_ip},ct_state=-trk,actions=ct(table={table_num})")

        # +trk+new
        # print(f"add_openflow_rule({path[0]},table={table_num},priority={priority},dl_type=0x0800,nw_src={source_ip},\
        #         nw_dst={target_ip},ct_state=+trk+new,actions=ct(commit),output:{get_host_switch(target_ip)[1]})")
        add_openflow_rule(path[0], f"table={table_num},priority={priority},dl_type=0x0800,nw_src={source_ip},\
                    nw_dst={target_ip},ct_state=+trk+new,actions=ct(commit),output:{get_host_switch(target_ip)[1]}")

        # +trk+est
        # print(f"add_openflow_rule({path[0]},table={table_num},priority={priority},dl_type=0x0800,nw_src={source_ip},\
        #         nw_dst={target_ip},ct_state=+trk+est,actions=output:{get_host_switch(target_ip)[1]})")
        add_openflow_rule(path[0], f"table={table_num},priority={priority},dl_type=0x0800,nw_src={source_ip},\
                    nw_dst={target_ip},ct_state=+trk+est,actions=output:{get_host_switch(target_ip)[1]}")
        
        # target to source
        # -trk
        # print(f"add_openflow_rule({path[0]},priority={priority},dl_type=0x0800,nw_src={target_ip},\
        #         nw_dst={source_ip},ct_state=-trk,actions=ct(table={table_num}))", sep="")
        add_openflow_rule(path[0], f"priority={priority},dl_type=0x0800,nw_src={target_ip},\
                    nw_dst={source_ip},ct_state=-trk,actions=ct(table={table_num})")
        
        # +trk+est
        # print(f"add_openflow_rule({path[0]},table={table_num},priority={priority},dl_type=0x0800,nw_src={target_ip},\
        #         nw_dst={source_ip},ct_state=+trk+est,actions=output:{get_host_switch(source_ip)[1]})")
        add_openflow_rule(path[0], f"table={table_num},priority={priority},dl_type=0x0800,nw_src={target_ip},\
                    nw_dst={source_ip},ct_state=+trk+est,actions=output:{get_host_switch(source_ip)[1]}")

    else:
        # source to target
        for i in range(len(path)):
            if i == len(path)-1:
                # untracking
                # print(f"add_openflow_rule({path[i]},priority={priority},dl_type=0x0800,nw_src={source_ip},\
                #         nw_dst={target_ip},ct_state=-trk,actions=ct(table={table_num}))")
                add_openflow_rule(path[i], f"priority={priority},dl_type=0x0800,nw_src={source_ip},\
                            nw_dst={target_ip},ct_state=-trk,actions=ct(table={table_num})")

                # +trk+new
                # print(f"add_openflow_rule({path[i]},table={table_num},priority={priority},dl_type=0x0800,nw_src={source_ip},\
                #         nw_dst={target_ip},ct_state=+trk+new,actions=ct(commit),output:{get_host_switch(target_ip)[1]})", sep="")
                add_openflow_rule(path[i], f"table={table_num},priority={priority},dl_type=0x0800,nw_src={source_ip},\
                            nw_dst={target_ip},ct_state=+trk+new,actions=ct(commit),output:{get_host_switch(target_ip)[1]}")

                # +trk+est
                # print(f"add_openflow_rule({path[i]},table={table_num},priority={priority},dl_type=0x0800,nw_src={source_ip},\
                #         nw_dst={target_ip},ct_state=+trk+est,actions=output:{get_host_switch(target_ip)[1]})", sep="")
                add_openflow_rule(path[i], f"table={table_num},priority={priority},dl_type=0x0800,nw_src={source_ip},\
                            nw_dst={target_ip},ct_state=+trk+est,actions=output:{get_host_switch(target_ip)[1]}")

            else:
                # untracking
                # print(f"add_openflow_rule({path[i]},priority={priority},dl_type=0x0800,nw_src={source_ip},\
                #         nw_dst={target_ip},ct_state=-trk,actions=ct(table={table_num}))", sep="")
                add_openflow_rule(path[i], f"priority={priority},dl_type=0x0800,nw_src={source_ip},\
                            nw_dst={target_ip},ct_state=-trk,actions=ct(table={table_num})")

                # +trk+new
                # print(f"add_openflow_rule({path[i]},table={table_num},priority={priority},dl_type=0x0800,nw_src={source_ip},\
                #         nw_dst={target_ip},ct_state=+trk+new,actions=ct(commit),output:{get_link_port(path[i], path[i+1])[0]})", sep="")
                add_openflow_rule(path[i], f"table={table_num},priority={priority},dl_type=0x0800,nw_src={source_ip},\
                            nw_dst={target_ip},ct_state=+trk+new,actions=ct(commit),output:{get_link_port(path[i], path[i+1])[0]}")

                # +trk+est
                # print(f"add_openflow_rule({path[i]},table={table_num},priority={priority},dl_type=0x0800,nw_src={source_ip},\
                #         nw_dst={target_ip},ct_state=+trk+est,actions=output:{get_link_port(path[i], path[i+1])[0]})", sep="")
                add_openflow_rule(path[i], f"table={table_num},priority={priority},dl_type=0x0800,nw_src={source_ip},\
                            nw_dst={target_ip},ct_state=+trk+est,actions=output:{get_link_port(path[i], path[i+1])[0]}")
        
        # target to source
        for i in range(len(path)):
            if i == 0:
                # -trk
                # print(f"add_openflow_rule({path[i]},priority={priority},dl_type=0x0800,nw_src={target_ip},\
                #         nw_dst={source_ip},ct_state=-trk,actions=ct(table={table_num}))", sep="")
                add_openflow_rule(path[i], f"priority={priority},dl_type=0x0800,nw_src={target_ip},\
                            nw_dst={source_ip},ct_state=-trk,actions=ct(table={table_num})")
                
                # +trk+est
                # print(f"add_openflow_rule({path[i]},table={table_num},priority={priority},dl_type=0x0800,nw_src={target_ip},\
                #         nw_dst={source_ip},ct_state=+trk+est,actions=output:{get_host_switch(source_ip)[1]})", sep="")
                add_openflow_rule(path[i], f"table={table_num},priority={priority},dl_type=0x0800,nw_src={target_ip},\
                            nw_dst={source_ip},ct_state=+trk+est,actions=output:{get_host_switch(source_ip)[1]}")

            else:
                # -trk
                # print(f"add_openflow_rule({path[i]},priority={priority},dl_type=0x0800,nw_src={target_ip},\
                #         nw_dst={source_ip},ct_state=-trk,actions=ct(table={table_num}))", sep="")
                add_openflow_rule(path[i], f"priority={priority},dl_type=0x0800,nw_src={target_ip},\
                            nw_dst={source_ip},ct_state=-trk,actions=ct(table={table_num})")
                
                # +trk+est
                # print(f"add_openflow_rule({path[i]},table={table_num},priority={priority},dl_type=0x0800,nw_src={target_ip},\
                #         nw_dst={source_ip},ct_state=+trk+est,actions=output:{get_link_port(path[i-1], path[i])[1]})", sep="")
                add_openflow_rule(path[i], f"table={table_num},priority={priority},dl_type=0x0800,nw_src={target_ip},\
                            nw_dst={source_ip},ct_state=+trk+est,actions=output:{get_link_port(path[i-1], path[i])[1]}")


"""Input source host and target host"""
print("Please input the hosts as H1, H2, ..., H9.")
source_host = input("Input source host: ")
while source_host[0] != "H" or (not source_host[1].isdigit()) or int(source_host[1]) == 0 or len(source_host) != 2:
    print("Please input either H1, H2, ..., or H9 as source host")
    source_host = input("Input source host: ")

target_host = input("Input target host: ")
while target_host[0] != "H" or (not target_host[1].isdigit()) or int(target_host[1]) == 0 or len(target_host) != 2:
    print("Please input either H1, H2, ..., or H9 as target host")
    target_host = input("Input target host: ")


"""Find paths"""
source_switch = get_host_switch(source_host)[0]
target_switch = get_host_switch(target_host)[0]
paths = find_two_shortest_paths(source_switch, target_switch)
# only 2 switches
if len(paths) >= 2 and paths[0] == paths[1]:
    paths = [paths[0]]

print("source:", source_host, " target:", target_host)
# path_num = 0
if len(paths) == 2:
    print("path1:", paths[0], "\npath2:", paths[1])
    # path_num = int(input("Choose one of the paths(1 or 2): "))-1
else:
    print("path:", paths[0])

try:
    """Create net"""
    net = Mininet(controller=RemoteController, link=TCLink, cleanup=True)
    controller = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6633)
    # Add hosts
    H1 = net.addHost('H1', ip='10.0.0.1', mac='00:00:00:00:00:01')
    H2 = net.addHost('H2', ip='10.0.0.2', mac='00:00:00:00:00:02')
    H3 = net.addHost('H3', ip='10.0.0.3', mac='00:00:00:00:00:03')
    H4 = net.addHost('H4', ip='10.0.0.4', mac='00:00:00:00:00:04')
    H5 = net.addHost('H5', ip='10.0.0.5', mac='00:00:00:00:00:05')
    H6 = net.addHost('H6', ip='10.0.0.6', mac='00:00:00:00:00:06')
    H7 = net.addHost('H7', ip='10.0.0.7', mac='00:00:00:00:00:07')
    H8 = net.addHost('H8', ip='10.0.0.8', mac='00:00:00:00:00:08')
    H9 = net.addHost('H9', ip='10.0.0.9', mac='00:00:00:00:00:09')
    # Add switches
    S1 = net.addSwitch('s1')
    S2 = net.addSwitch('s2')
    S3 = net.addSwitch('s3')
    S4 = net.addSwitch('s4')
    S5 = net.addSwitch('s5')
    S6 = net.addSwitch('s6')
    S7 = net.addSwitch('s7')
    S8 = net.addSwitch('s8')
    # Create host's link to swtich
    net.addLink(H1, S1, port2=1)
    net.addLink(H2, S3, port2=1)
    net.addLink(H3, S7, port2=2)
    net.addLink(H4, S5, port2=3)
    net.addLink(H5, S5, port2=4)
    net.addLink(H6, S8, port2=3)
    net.addLink(H7, S8, port2=4)
    net.addLink(H8, S6, port2=1)
    net.addLink(H9, S4, port2=5)

    # Add network links (path1)
    network_topo(net, source_host, target_host, paths[0])
    net.start()

    """Flow Control"""
    switches = ["s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8"]
    for switch in switches:
        clear_flows(switch)

    path = [s.lower() for s in paths[0]]
    # print(path)

    source_ip = hostname_to_ip(source_host)
    target_ip = hostname_to_ip(target_host)

    # for path1
    add_openflow_rules(source_ip, target_ip, path, 200, 0)

    if len(paths) >= 2:
        path = [s.lower() for s in paths[1]]
        # print(path)
        network_topo(net, source_host, target_host, paths[1])
        add_openflow_rules(source_ip, target_ip, path, 100, 1)

    for switch in switches:
        allow_ARP(switch, 200)

    CLI(net)

finally:
    net.stop()
    # if net not cleanup correctly, run "sudo mn -c"
    print()
