import pcapy
import struct
import socket
import sys

typ = ''

def handle_packet(hdr, data):
    global typ
    
    #create the result parameter
    op_type = typ
    op_method = ''
    trans_pro = ''
    MAC_src_addr = ''
    MAC_dest_addr = ''
    IP_src_addr = ''
    IP_dest_addr = ''
    Port_src = ''
    Port_dest = ''
    opt = ''
    query_info = ''
    response_info = ''


    #extract the MAC address from the ethernet frame
    dest, src, protocal = struct.unpack('! 6s 6s H', data[:14])
    protocal = socket.htons(protocal)

    dest = map('{:02x}'.format, dest)
    MAC_dest_addr = ':'.join(dest).upper()

    src = map('{:02x}'.format, src)
    MAC_src_addr = ':'.join(src).upper()

    if protocal == 8:

        #extract ip address from ip headers
        ip_headers = data[14:34]
        version_IHL, type_of_service, total_length, identification, fragment, ttl, pro, check, ip_src, ip_dest = struct.unpack('! B B H H H B B H 4s 4s' , ip_headers)

        IP_src_addr = socket.inet_ntoa(ip_src)
        IP_dest_addr = socket.inet_ntoa(ip_dest)
    
        # TCP
        if pro == 6:
            trans_pro = 'tcp'
            tcp_headers = data[34:54]

            src_port, dest_port, _, _, reserved, _, _, _, _ = struct.unpack('! H H L L B B H H H', tcp_headers)
            
            Port_src = str(src_port)
            Port_dest = str(dest_port)
            tcp_header_length = reserved >> 4

            header_size = 34 + tcp_header_length * 4
            payload = data[header_size:]
            n = len(payload)
            if n == 0:
                return

            content = struct.unpack('! {}s'.format(n), payload)
            
            try:
                con = content[0].decode().split()
                if Port_src == '80':
                    op_method = con[1]
                elif Port_dest == '80':
                    op_method = con[0]

                if len(op_method) > 8:
                    return
            except UnicodeDecodeError:
                return

        # UDP
        elif pro == 17:
            trans_pro = 'udp'
            udp_headers = data[34:42]

            src_port, dest_port, _, _ = struct.unpack('! H H H H', udp_headers)
            Port_src = str(src_port)
            Port_dest = str(dest_port)
            
            dns_headers = data[42:54]
            _, mix, qd_count, an_count, as_count, ar_count = struct.unpack('! 6H', dns_headers)
            qr = (mix & 0x8000) != 0
            if qr:
                op_method = 'response'
            else:
                op_method = 'query'

            #extract information from dns message
            payload = data[54:] 
            
            pointer = 0
            for _ in range(qd_count):
                res = []
                while True:
                    length = payload[pointer]
                    pointer += 1

                    if length == 0:
                        web = '.'.join(res)
                        query_info += web + '\t'
                        pointer += 4
                        break

                    else:
                        res.append(payload[pointer:pointer + length].decode())
                        pointer += length
           
            if an_count >= 1:
                res = []
                for i in payload[pointer + 12: pointer + 16]:
                    res.append(str(i))
                addr = '.'.join(res)
                response_info += addr + '\t'


    # content = payload.decode('utf-8')
    if op_method == 'response' and response_info == '':
        return 

    print()
    print('==================================================================')
    print(op_type + ' ' + op_method + ' ' + trans_pro)
    print('srcmc: {},            dstmc: {}'.format(MAC_src_addr, MAC_dest_addr))
    print('srcip: {},                dstip: {}'.format(IP_src_addr, IP_dest_addr))
    print('srcport: {},                 dstport: {}'.format(Port_src, Port_dest))
    print()
    if query_info != '':
        print('query info:')
        print(query_info)
    print()
    if response_info != '':
        print('response info:')
        print(response_info)
    print('==================================================================')
    print()

if __name__ == '__main__':
    typ = sys.argv[1]
    
    bfp_filter = ''
    if typ == 'dns':
        bfp_filter = 'dst port 53 or src port 53'
    elif typ == 'http':
        bfp_filter = 'tcp and (dst port 80 or src port 80)'
    
    devs = pcapy.findalldevs()
    cap = pcapy.open_live(devs[0], 10240, 1, 300) 
    cap.setfilter(bfp_filter)
    cap.loop(0, handle_packet)
