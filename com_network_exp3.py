from psutil import net_if_addrs

#获取本机多个网卡MAC地址
def getMACs():
    for k, v in net_if_addrs().items():
        for item in v:
            address = item[1]
            if '-' in address and len(address)==17:
                print(address)


from winpcapy import WinPcapDevices
from winpcapy import WinPcapUtils

import dpkt
import time
import datetime

#list_device = WinPcapDevices.list_devices()
#print(list_device)


def packet_callback(win_pcap, param, header, pkt_data):
    eth = dpkt.ethernet.Ethernet(pkt_data)
    # # 判断是否为IP数据报
    if not isinstance(eth.data, dpkt.ip.IP):
        print("Non IP packet type not supported ", eth.data.__class__.__name__)
        return
    # 抓IP数据包
    packet = eth.data
    # 取出分片信息
    df = bool(packet.off & dpkt.ip.IP_DF)
    mf = bool(packet.off & dpkt.ip.IP_MF)
    offset = packet.off & dpkt.ip.IP_OFFMASK
    
    # 输出数据包信息：time,src,dst,protocol,length,ttl,df,mf,offset,checksum
    output1 = {'time':time.strftime('%Y-%m-%d %H:%M:%S',(time.localtime()))}
    output2 = {'src':'%d.%d.%d.%d'%tuple(packet.src) , 'dst':'%d.%d.%d.%d'%tuple(packet.dst)}
    output3 = {'protocol':packet.p, 'len':packet.len, 'ttl':packet.ttl}
    output4 = {'df':df, 'mf':mf, 'offset':offset, 'checksum':packet.sum}
    output5 = {'pkt_data':pkt_data}

    print(output5)
    print(output1)
    print(output2)
    print(output3)
    print(output4)

WinPcapUtils.capture_on(pattern="Microsoft", callback=packet_callback)
from scapy.all import *

dpkt  = sniff(iface = "VirtualBox Host-Only Network", count = 1)
print(dpkt)
print(len(dpkt))
print(dpkt[0])
#获取ether层，ip层，tcp层信息
def get_network():
    """
    获取网卡的名称, ip, mask返回格式为列表中多个元祖:类似于 [('lo', '127.0.0.1', '255.0.0.0'), ('ens33', '192.168.100.240', '255.255.255.0')]
    :return:
    """
    network_info = []
    info = psutil.net_if_addrs()
    for k, v in info.items():
        for item in v:
            if item[0] == 2 and not item[1] == '127.0.0.1':  # 不包括本地回环的话
                # if item[0] == 2:
                network_info.append((k, item[1], item[2]))
    return network_info
#print(get_network())
