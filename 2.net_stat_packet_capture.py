import time
import os
import threading
import pyshark
import asyncio
from scapy.all import PcapWriter
from scapy.layers.l2 import Ether
from queue import Queue
from pathlib import Path

# ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# Setting
PCAP_INTERVAL =  1 * 60  # sec
INTERFACE = '이더넷'
PATH = Path('C:/Temp/net_stat_data')   # pcap 파일 저장 경로

PACKET_QUEUE = Queue()
            
# ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
def capture_packets():
    loop = asyncio.new_event_loop()  # 새 이벤트 루프 생성
    asyncio.set_event_loop(loop)  # 현재 스레드에 이벤트 루프 설정
    
    capture = None
    try:
        # 실시간 캡처 객체 생성
        capture = pyshark.LiveCapture(interface = INTERFACE, use_json = True, include_raw = True)
        
        # 패킷 처리 루프
        for packet in capture.sniff_continuously():
            PACKET_QUEUE.put(packet)
    finally:
        if capture is not None:
            capture.close()
        
# ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
def write_with_queue():
    flag = True
    pcap_writer = None
    prev_packet_t = 0.0
    curr_packet_t = 0.0
    
    try:
        while True:
            # 큐에서 패킷을 가져와 파일로 저장
            try:
                packet = PACKET_QUEUE.get(timeout = 1) # 큐에서 대기 중인 패킷을 가져옴
            except Exception:
                continue
            
            prev_packet_t = curr_packet_t
            curr_packet_t = float(packet.sniff_timestamp)
            
            # pcap 파일 저장 시점 확인
            if int(prev_packet_t) % PCAP_INTERVAL != 0 and int(curr_packet_t) % PCAP_INTERVAL == 0:
                pcap_writer.close()            # .pcap 파일로 저장
                print(f'[INFO] packets_{timestamp}.pcap 저장 완료!')
                
                flag = True
            
            # 새 pcap 파일 생성
            if flag:
                timestamp = time.strftime('%Y.%m.%d_%H.%M.%S', time.localtime(curr_packet_t - (curr_packet_t % PCAP_INTERVAL)))
                file_name = os.path.join(PATH, f'2.packet_data/{INTERFACE}/packets_{timestamp}.pcap')
                
                print(f'[INFO] packets_{timestamp}.pcap 저장 시작...')
                pcap_writer = PcapWriter(file_name, append = True, sync = True)
                flag = False
            
            # packet data 입력
            raw_data = bytes(packet.get_raw_packet())   # Raw 데이터를 추출
            scapy_packet = Ether(raw_data)  # Scapy 패킷 객체로 변환
            scapy_packet.time = curr_packet_t
            pcap_writer.write(scapy_packet)
    finally:
        if pcap_writer is not None:
            pcap_writer.close()            # .pcap 파일로 저장
            print(f'[INFO] packets_{timestamp}.pcap 저장 완료!')
            
# ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
if __name__ == '__main__':
    # 폴더 생성
    packet_data_dir = os.path.join(PATH, '2.packet_data')
    interface_dir = os.path.join(packet_data_dir, INTERFACE)
    os.makedirs(packet_data_dir, exist_ok = True)
    os.makedirs(interface_dir, exist_ok = True)
    
    # 파일 저장 스레드 생성
    capture_thread = threading.Thread(target = capture_packets)
    capture_thread.start()
    
    print(f'[INFO] {time.strftime('%Y.%m.%d_%H.%M.%S', time.localtime(time.time()))} 패킷 캡처 프로그램 시작')
    try:
        write_with_queue()
    except KeyboardInterrupt:
        print('[INFO] Ctrl-C 입력됨! 프로그램을 종료합니다.')
        
    print(f'[INFO] {time.strftime('%Y.%m.%d_%H.%M.%S', time.localtime(time.time()))} 패킷 캡처 프로그램 종료')