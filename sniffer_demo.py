import socket
import struct
import textwrap

TAB = '\t'
TAB1 = '\t\t'
TAB2 = '\t\t\t'
TAB3 = '\t\t\t\t'
TAB4 = '\t\t\t\t\t'
DATA_TAB_1 = '\t   '
DATA_TAB_2 = '\t\t   '
DATA_TAB_3 = '\t\t\t   '
DATA_TAB_4 = '\t\t\t\t   '

def main():
    conn = socket.socket ( socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3) )
    while True :
        raw_data,addres=conn.recvfrom(23423)
        dest_mac,src_mac,eth_proto,data=ethernet_frame(raw_data)
        print("Ethernet Frame")
        print(TAB+"Destination address: {}, source address: {}, protocol: {}".format(dest_mac,src_mac,eth_proto))
        if eth_proto == 8 :
            (version,header_length,ttl,proto,src,target,data)=ipv4_packet(data)
            print(TAB+"IPv4 Packet")
            print(TAB1+"Version: {}, Header Length: {}, TTL: {}".format(version,header_length,ttl))
            print(TAB1+"Protocol: {}, Source: {}, Target: {}".format(proto,src,target))
            if proto == 1:
                icmp_type,code,checksum,data=icmp_packet(data)
                print(TAB+"ICMP Packet")
                print(TAB1+"Type: {}, Code: {}, Checksum: {}".format(icmp_type,code,checksum))
                print(TAB1+"Data:")
                print(format_multi_line(DATA_TAB_2,data))
            elif proto == 6:
                src_port,dest_port,sequence,acknowledgment,flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin,data=tcp_segment(data)
                print(TAB+"TCP Segment")
                print(TAB1+"Source Port: {}, Destination Port: {}".format(src_port,dest_port))
                print(TAB1+"Sequence: {}, Acknowledgment: {}".format(sequence,acknowledgment))
                print(TAB1+"Flags:")
                print(TAB2+"URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}".format(flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin))
                print(TAB1+"Data:")
                print(format_multi_line(DATA_TAB_2,data))
            elif proto == 17:
                src_port,dest_port,size,data=udp_segment(data)
                print(TAB+"UDP Segment")
                print(TAB1+"Source Port: {}, Destination Port: {}, Length: {}".format(src_port,dest_port,size))
                print(TAB1+"Data:")
                print(format_multi_line(DATA_TAB_2,data))
            else:
                print(TAB+"Data:")
                print(format_multi_line(DATA_TAB_1,data))

#unpack ethernet frame
def ethernet_frame(data):
    dest_mac,src_mac,proto= struct.unpack("! 6s 6s H",data[:14])
    return getmacadd(dest_mac),getmacadd(src_mac),socket.htons(proto),data[14:]

#returing the proper mac address
def getmacadd(byte_data):
    datastr=map(':02x'.format,byte_data)
    return ':'.join(datastr).upper()

def ipv4_packet(data):
    version_header_length=data[0]
    version=version_header_length >> 4
    header_length=(version_header_length & 15)*4
    ttl,proto,src,target=struct.unpack('! 8x B B 2x 4s 4s',data[:20])
    return version,header_length,ttl,proto,ipv4(src),ipv4(target),data[header_length:]

def ipv4(data):
    return '.'.join(map(str,data))

def icmp_packet(data):
    icmp_type,code,checksum=struct.unpack('! B B H',data[:4])
    return icmp_type,code,checksum,data[4:]
def tcp_segment(data):
    (src_port,dest_port,sequence,acknowledgment,offset_reserved_flags)=struct.unpack('! H H L L H',data[:14])
    offset=(offset_reserved_flags >> 12)*4
    flag_urg=(offset_reserved_flags & 32) >> 5
    flag_ack=(offset_reserved_flags & 16) >> 4
    flag_psh=(offset_reserved_flags & 8) >> 3
    flag_rst=(offset_reserved_flags & 4) >> 2
    flag_syn=(offset_reserved_flags & 2) >> 1
    flag_fin=offset_reserved_flags & 1
    return src_port,dest_port,sequence,acknowledgment,flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin,data[offset:]

def udp_segment(data):
    src_port,dest_port,size=struct.unpack('! H H 2x H',data[:8])
    return src_port,dest_port,size,data[8:]

def format_multi_line(prefix,string,size=80):
    size-=len(prefix)
    if isinstance(string,bytes):
        string=''.join(r'\x{:02x}'.format(byte) for byte in string)
    return '\n'.join([prefix+line for line in textwrap.wrap(string,size)])


main()
