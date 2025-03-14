import time
import os
import glob
import pyshark
from scapy.all import PcapWriter
from scapy.layers.l2 import Ether
from collections import defaultdict
from pathlib import Path

# ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# Setting
PATH = Path('C:/Temp/net_stat_data')              # 패킷 분류 파일 저장경로

# ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
def write_to_file(process_name, proto, packet_dict):
    for packet_info, packets in packet_dict.items():
        packet_info_sorted = sorted(list(packet_info))
        output_file = os.path.join(PATH, '4.packet_segmentation', process_name, proto, f'[{packet_info_sorted[0][0]}, {packet_info_sorted[0][1]}]---[{packet_info_sorted[1][0]}, {packet_info_sorted[1][1]}].pcap')
        
        with PcapWriter(output_file, append=True, sync=True, linktype=1) as pcap_writer:
            for packet in packets:
                raw_data = packet.get_raw_packet()
                scapy_packet = Ether(raw_data)  # Scapy 패킷 객체로 변환
                scapy_packet.time = float(packet.sniff_timestamp)
                pcap_writer.write(scapy_packet)
                
# ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
def segmentation(file_path, process_name):
    with pyshark.FileCapture(file_path, use_json = True, include_raw = True) as capture:
        tcp_packet_dict = defaultdict(list)
        udp_packet_dict = defaultdict(list)
        for packet in capture:
            # tcp, udp 확인
            proto_num = int(packet.ip.proto)
            
            # packet 정보
            proto = 'tcp' if proto_num == 6 else 'udp'
            src_ip = str(packet.ip.src)
            dst_ip = str(packet.ip.dst)
            src_port = int(packet.tcp.srcport) if proto == 'tcp' else int(packet.udp.srcport)
            dst_port = int(packet.tcp.dstport) if proto == 'tcp' else int(packet.udp.dstport)
            packet_info_set = frozenset([(src_ip, src_port), (dst_ip, dst_port)])
            
            if proto == 'tcp':  tcp_packet_dict[packet_info_set].append(packet)
            else:  udp_packet_dict[packet_info_set].append(packet)
                
        write_to_file(process_name, 'TCP', tcp_packet_dict)
        write_to_file(process_name, 'UDP', udp_packet_dict)

# ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
def read_classification_file():
    file_paths = sorted(glob.glob(f'{PATH}/3.packet_classification/*.pcap'))

    for file_path in file_paths:
        file_name = os.path.basename(file_path)
        process_name = file_name.split('(')[1].split(')')[0]
        process_segmentation_dir = os.path.join(PATH, f'4.packet_segmentation/{process_name}')
        tcp_dir = os.path.join(process_segmentation_dir, 'TCP')
        udp_dir = os.path.join(process_segmentation_dir, 'UDP')
        os.makedirs(process_segmentation_dir, exist_ok = True)
        os.makedirs(tcp_dir, exist_ok = True)
        os.makedirs(udp_dir, exist_ok = True)
        
        print(f'[INFO] {file_name} 처리중...')
        segmentation(file_path, process_name)
        print(f'[INFO] {file_name} 처리 완료!')

# ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
if __name__ == '__main__':
    # 폴더 생성
    packet_segmentation_dir = os.path.join(PATH, '4.packet_segmentation')
    os.makedirs(packet_segmentation_dir, exist_ok=True)

    print(f'[INFO] {time.strftime('%Y.%m.%d_%H.%M.%S', time.localtime(time.time()))} 패킷 세분화 프로그램 시작')
    read_classification_file()
    print(f'[INFO] {time.strftime('%Y.%m.%d_%H.%M.%S', time.localtime(time.time()))} 패킷 세분화 프로그램 종료')