import socket
import struct
import textwrap


def main():
    conn = socket.socket ( socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3) )
    while True :
        raw_data,addres=conn.recvfrom(23423)
        dest_mac,src_mac,eth_proto,data=ethernet_frame(raw_data)
        print("Ethernet Frame")
        print("Destination address: {},source address: {},data: {}".format(dest_mac,src_mac,data))


#unpack ethernet frame
def ethernet_frame(data):
    dest_mac,src_mac,proto= struct.unpack("! 6s 6s H",data[:14])
    return getmacadd(dest_mac),getmacadd(src_mac),socket.htons(proto),data[14:]

#returing the proper mac address
def getmacadd(byte_data):
    datastr=map(':02x'.format,byte_data)
    return ':'.join(datastr).upper()

main()
