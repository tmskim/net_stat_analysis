0.
import psutil
import time
import socket
import os
from pathlib import Path
from collections import defaultdict, namedtuple

# ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# Setting
TXT_INTERVAL =  1 * 60  # sec
DETECTION_INTERVAL = 1        # sec
PATH = Path('C:/Temp/net_stat_data')   # txt 파일 저장 경로
LOCAL_IP = socket.gethostbyname(socket.gethostname())         # Do not touch!

# ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# Class Definition
class ProcessTimeInformation:
    def __init__(self):
        self.process_name = 'No_Process_Name'
        self.time_information = []
        
    def input_start_time(self, now):
        self.time_information.append([now, 'None', 'None'].copy())
        
    def input_end_time(self, now):
        self.time_information[-1][1] = now
        
    def calculate_duration_time(self):
        last_time_information = self.time_information[-1]
        duration_time = last_time_information[1] - last_time_information[0]
        last_time_information[2] = duration_time
    
    def input_process_name(self, process_dict, pid):
        self.process_name = process_dict.get(pid, 'No_Process_Name')
        
    def clear_time_information(self):
        while len(self.time_information) > 1:
            del self.time_information[0]
        
PTI = ProcessTimeInformation

# ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
def write_to_file(txt_name, path, record_dict):            
    file = open(f'{PATH}/{path}/sockets_{txt_name}.txt', 'w')
    for socket_info, info_class in record_dict.items():
        if socket_info.proto == 'UDP':
            file.write(f'({info_class.process_name}, PID: {socket_info.pid}) [{socket_info.local.ip}:{socket_info.local.port}] <-({socket_info.proto})->\n')
        elif socket_info.remote == 'LISTEN':
            file.write(f'({info_class.process_name}, PID: {socket_info.pid}) [{socket_info.local.ip}:{socket_info.local.port}] <-({socket_info.proto})-> [{socket_info.remote}]\n')
        else:
            file.write(f'({info_class.process_name}, PID: {socket_info.pid}) [{socket_info.local.ip}:{socket_info.local.port}] <-({socket_info.proto})-> [{socket_info.remote.ip}:{socket_info.remote.port}]\n')                   
        
        for time_info in info_class.time_information:
            start_time_str = time.strftime('%Y.%m.%d_%H.%M.%S', time.localtime(time_info[0]))
            if time_info[1] == 'None':
                end_time_str = 'None'
                duration_time_str = 'None'
            else:
                end_time_str = time.strftime('%Y.%m.%d_%H.%M.%S', time.localtime(time_info[1]))
                duration_time_int = round(time_info[2])
                duration_time_str = f'{duration_time_int//3600:02d}.{(duration_time_int%3600)//60:02d}.{duration_time_int%60:02d}'
            
            file.write(f'{start_time_str:19s} --> {end_time_str:19s}    {duration_time_str}\n')
        file.write('\n')
    file.close()

# ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
def get_socket_information():
    socket_information_set = set()
    Socket_info = namedtuple('socket_info', ['proto', 'pid', 'local', 'remote'])
    Ip_Port_info = namedtuple('ip_port_info', ['ip', 'port'])
    
    for conn in psutil.net_connections(kind='inet4'):   # IPv4
        if conn.pid == 0 or conn.pid == 1:  continue    # Skip System Idle Process
        if conn.laddr.ip == '127.0.0.1':    continue    # Skip local communication
        if conn.type not in [socket.SOCK_DGRAM, socket.SOCK_STREAM]:    continue    # UDP, TCP
        
        if conn.type == socket.SOCK_DGRAM:  # UDP
            local_ip = LOCAL_IP if conn.laddr.ip == '0.0.0.0' else conn.laddr.ip
            local_info = Ip_Port_info(ip = local_ip, port = conn.laddr.port)
            socket_information_set.add(Socket_info(proto = 'UDP', pid = conn.pid, local = local_info, remote = 'None'))
        elif conn.raddr == tuple():         # TCP, LISTEN
            local_ip = LOCAL_IP if conn.laddr.ip == '0.0.0.0' else conn.laddr.ip
            local_info = Ip_Port_info(ip = local_ip, port = conn.laddr.port)
            socket_information_set.add(Socket_info(proto = 'TCP', pid = conn.pid, local = local_info, remote = 'LISTEN'))
        else:                               # TCP, CONNECTED
            local_info = Ip_Port_info(ip = conn.laddr.ip, port = conn.laddr.port)
            remote_info = Ip_Port_info(ip = conn.raddr.ip, port = conn.raddr.port)
            socket_information_set.add(Socket_info(proto = 'TCP', pid = conn.pid, local = local_info, remote = remote_info))
                
    return socket_information_set

# ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
def update_timestamps(now, record_dict, socket_opened_set, socket_closed_set):    
    # open time 입력
    for socket_opened in socket_opened_set:
        record_dict[socket_opened].input_start_time(now)
    
    # close time 입력 및 duration time 계산
    for socket_closed in socket_closed_set:
        record_dict[socket_closed].input_end_time(now)
        record_dict[socket_closed].calculate_duration_time()

# ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
def update_process_name(record_dict):
    process_dict = {proc.pid: proc.name() for proc in psutil.process_iter(['pid', 'name'])}
    for socket_info in record_dict:
        if record_dict[socket_info].process_name != 'No_Process_Name':  continue
            
        record_dict[socket_info].input_process_name(process_dict, socket_info.pid)

# ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
def classify_and_write_records(txt_name, record_dict):
    socket_dict = {}
    error_dict = {}

    for socket_info, info_class in record_dict.items():
        if info_class.process_name == 'No_Process_Name':
            error_dict[socket_info] = info_class
        else:
            socket_dict[socket_info] = info_class
    
    print(f'[INFO] sockets_{txt_name}.txt 작성중...')
    if socket_dict:
        write_to_file(txt_name, '1.socket_data', dict(sorted(socket_dict.items(), key=lambda x: x[1].process_name)))
    if error_dict:
        write_to_file(txt_name, '1.socket_data/error', dict(sorted(error_dict.items(), key=lambda x: x[1].process_name)))
    print(f'[INFO] sockets_{txt_name}.txt 작성 완료!')
    
# ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
def select_next_records(record_dict):
    next_record_dict = defaultdict(PTI)
    for socket_info, info_class in record_dict.items():
        time_info = info_class.time_information[-1]
        if time_info[1] == 'None':
            next_record_dict[socket_info] = info_class
            next_record_dict[socket_info].clear_time_information()
                    
    return next_record_dict

# ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
def detection():
    record_dict = defaultdict(PTI)
    prev_sockets = set()
    curr_sockets = set()
    now = time.time()
    txt_name = time.strftime('%Y.%m.%d_%H.%M.%S', time.localtime(now - (now % TXT_INTERVAL)))
    
    while True:
        now = time.time()
        
        if int(now) % TXT_INTERVAL == 0:
            classify_and_write_records(txt_name, record_dict)
            record_dict = select_next_records(record_dict)
            txt_name = time.strftime('%Y.%m.%d_%H.%M.%S', time.localtime(now))
        
        prev_sockets = curr_sockets
        curr_sockets = get_socket_information()
        socket_opened_set = curr_sockets - prev_sockets
        socket_closed_set = prev_sockets - curr_sockets
        
        update_timestamps(now, record_dict, socket_opened_set, socket_closed_set)
        update_process_name(record_dict)

        time.sleep(max(0, DETECTION_INTERVAL-(time.time()-now)))

# ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
if __name__ == '__main__':
    socket_data_dir = os.path.join(PATH, '1.socket_data')
    error_dir = os.path.join(socket_data_dir, 'error')
    os.makedirs(socket_data_dir, exist_ok=True)
    os.makedirs(error_dir, exist_ok=True)
    
    print(time.strftime('[INFO] %Y.%m.%d_%H.%M.%S', time.localtime(time.time())), '소켓 데이터 수집 프로그램 시작')
    try:
        detection()
    except KeyboardInterrupt:
        print('[INFO] Ctrl-C 입력됨! 프로그램을 종료합니다.')
        print(time.strftime('[INFO] %Y.%m.%d_%H.%M.%S', time.localtime(time.time())), '소켓 데이터 수집 프로그램 종료')