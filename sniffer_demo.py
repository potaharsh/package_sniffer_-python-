import socket
import struct
import textwrap

#unpack ethernet frame
def ethernet_frame(data):
    dest_mac,src_mac,proto= struct.unpack("! 6s 6s H",data[:14])
    return getmacadd(dest_mac),getmacadd(src_mac),socket.htons(proto)
