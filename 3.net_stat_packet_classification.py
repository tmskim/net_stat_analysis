import time
import os
import re
import glob
import pyshark
from scapy.all import PcapWriter
from scapy.layers.l2 import Ether
from collections import defaultdict
from pathlib import Path

# ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# Setting
PROCESS_NAME = 'chrome.exe'  # 프로세스 이름
INTERFACE = '이더넷'                # 패킷 위치 
PATH = Path('C:/Temp/net_stat_data')              # 패킷 분류 파일 저장경로

# ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# Class Definition
class SocketInformation:
    def __init__(self, proto:str, pid:int, local:tuple, remote:tuple|str):
        self.proto = proto              # tcp or udp
        self.pid = pid                  # pid
        self.local = local              # (laddr.ip, laddr.port)
        self.remote = remote            # (raddr.ip, raddr.port) or 'LISTEN' or 'None'
        self.time_informations = []     # [time_info, time_info, ...]
        
    def return_information_set(self):
        if type(self.remote) == str:
            return {self.proto, self.local}
        else:
            return {self.proto, self.local, self.remote}
        
SI = SocketInformation

# ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
def packet_data_extraction(pcap_file, pcap_writer, socket_informations):
    with pyshark.FileCapture(pcap_file, use_json = True, include_raw = True) as packet_captured:
        for packet in packet_captured:
            # ip 계층 유무 확인
            if not hasattr(packet, 'ip'):   continue
            
            # tcp, udp 확인
            proto_num = int(packet.ip.proto)
            if proto_num not in [6, 17]:    continue    # protocol number: tcp = 6, udp = 17
            
            # packet 정보
            proto = 'tcp' if proto_num == 6 else 'udp'
            src_ip = str(packet.ip.src)
            dst_ip = str(packet.ip.dst)
            src_port = int(packet.tcp.srcport) if proto == 'tcp' else int(packet.udp.srcport)
            dst_port = int(packet.tcp.dstport) if proto == 'tcp' else int(packet.udp.dstport)
            packet_info_set = {proto, (src_ip, src_port), (dst_ip, dst_port)}
            
            # packet이 process에 해당하는 socket인지 확인
            if not any(socket_information.return_information_set().issubset(packet_info_set) for socket_information in socket_informations): continue
            
            # packet data 작성
            raw_data = bytes(packet.get_raw_packet())
            scapy_packet = Ether(raw_data)  # Scapy 패킷 객체로 변환
            scapy_packet.time = float(packet.sniff_timestamp)
            pcap_writer.write(scapy_packet)
            
# ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
def read_packet_data(socket_data_dict):
    print('[INFO] Packet Data 추출중...')
    output_file = os.path.join(PATH, '3.packet_classification', f'packet_data({PROCESS_NAME}).pcap')
    pcap_writer = PcapWriter(output_file, append = True, sync = True, linktype = 1)
    
    for file_name, socket_informations in socket_data_dict.items():
        pcap_file_name = file_name.replace('sockets', 'packets').replace('txt', 'pcap')
        pcap_file = os.path.join(PATH, '2.packet_data', INTERFACE, pcap_file_name)
        print(f'[INFO] {pcap_file_name} 처리중...')
        
        if not os.path.exists(pcap_file):
            print(f'{pcap_file_name} could not be found.')
            continue

        packet_data_extraction(pcap_file, pcap_writer, socket_informations)
        
        print(f'[INFO] {pcap_file_name} 처리 완료!')
                    
    pcap_writer.close()
    print('[INFO] Packet Data 추출 완료!')

# ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
def socket_data_extraction(file_name, file, socket_data_dict):  
    while True:
        # socket information 추출
        line = file.readline()
        if not line:    break
        if PROCESS_NAME not in line:    continue
        
        line_splited = re.split(r'[\s()\[\]:]+', line)
        pid = int(line_splited[3])
        local_ip = line_splited[4]
        local_port = int(line_splited[5])
        if 'UDP' in line:               # UDP
            socket_data_dict[file_name].append(SI('udp', pid, (local_ip, local_port), 'None'))
        elif 'LISTEN' in line:          # TCP, LISTEN
            socket_data_dict[file_name].append(SI('tcp', pid, (local_ip, local_port), 'LISTEN'))
        else:                           # TCP, CONNECTED
            remote_ip = line_splited[9]
            remote_port = int(line_splited[10])
            socket_data_dict[file_name].append(SI('tcp', pid, (local_ip, local_port), (remote_ip, remote_port)))
        
        # time information 추출
        while True:
            line = file.readline()
            if line == '\n':    break
            
            line_splited = line.split()
            start_time_str = line_splited[0]
            end_time_str = line_splited[2]
            duration_time_str = line_splited[3]
            
            start_time = time.mktime(time.strptime(start_time_str, '%Y.%m.%d_%H.%M.%S'))
            if end_time_str == 'None':
                end_time = 'None'
                duration_time = 'None'
            else:
                end_time = time.mktime(time.strptime(end_time_str, '%Y.%m.%d_%H.%M.%S'))
                duration_time_list = [float(t) for t in duration_time_str.split('.')]
                duration_time = duration_time_list[0]*3600 + duration_time_list[1]*60 + duration_time_list[2]
            socket_data_dict[file_name][-1].time_informations.append((start_time, end_time, duration_time))

# ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
def read_socket_data():
    print('[INFO] Socket Data 추출중...')
    file_paths = sorted(glob.glob(f'{PATH}/1.socket_data/*.txt'))

    socket_data_dict = defaultdict(list)  # 파일 이름과 내용을 저장할 딕셔너리
    for file_path in file_paths:
        with open(file_path, 'r', encoding = 'utf-8') as file:
            file_name = os.path.basename(file_path)
            
            print(f'[INFO] {file_name} 처리중...')
            socket_data_extraction(file_name, file, socket_data_dict)
            print(f'[INFO] {file_name} 처리 완료!')
    
    print('[INFO] Socket Data 추출 완료!')
    read_packet_data(socket_data_dict)

# ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
if __name__ == '__main__':
    # 폴더 생성
    packet_classification_dir = os.path.join(PATH, '3.packet_classification')
    os.makedirs(packet_classification_dir, exist_ok=True)

    print(f'[INFO] {time.strftime('%Y.%m.%d_%H.%M.%S', time.localtime(time.time()))} 패킷 분류 프로그램 시작')
    read_socket_data()
    print(f'[INFO] {time.strftime('%Y.%m.%d_%H.%M.%S', time.localtime(time.time()))} 패킷 분류 프로그램 종료')