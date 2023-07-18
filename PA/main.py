from scapy.all import *
import threading
import socket
import json
import copy

server_ip = "192.168.124.221"
server_port = 10112
listen_num = 5
target_ip = "192.168.124.222"
target_port = 7011
buffer_size = 4096

isAnalyzing = False
packets_count = 0


def call_back(packet):
    tcp_data_send = MakeSendData(packet)
    tcp_client.send(tcp_data_send.encode())
    print('send tcp_data_send', tcp_data_send)

def MakeSendData(packet):
    tcp_data_send = {}
    json_data = {}
    packet_save = copy.deepcopy(packet)
    header_list = []
    
    tcp_data_send["type"] = "analyze_res"
    
    while(not type(packet).__name__ == "NoPayload"):
        header_list.append(type(packet).__name__)
        packet = packet.payload
    
    if hasattr(packet_save, "proto"):
        json_data["proto"] = packet_save.proto
    else:
        json_data["proto"] = ""
    json_data["header_list"] = header_list
    
    packet = copy.deepcopy(packet_save)
    for i in header_list:
        tmp = {}
        for j in packet.fields_desc:
            if j.name == "flags":
                tmp[j.name] = getattr(packet_save[i], j.name).value
            elif type(getattr(packet_save[i], j.name)) == type(b"tmp"):
                tmp[j.name] = repr(getattr(packet_save[i], j.name))
            elif type(getattr(packet_save[i], j.name)) == type(1) or type(getattr(packet_save[i], j.name)):
                tmp[j.name] = getattr(packet_save[i], j.name)
        json_data[i] = tmp
        packet = packet.payload
    
    tcp_data_send["data"] = json_data
    print(tcp_data_send)
    tcp_data_send = json.dumps(tcp_data_send)
    return tcp_data_send

def analyze():
    global isAnalyzing, packets_count
    while(True):
        if(isAnalyzing):
            packets = sniff(prn = call_back, count = 1, store = 0)
            packets_count += len(packets)


"""
def server():
    global isSendedReq
    tcp_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_server.setsockopt(socket.SOL_SOCKET	, socket.SO_REUSEADDR, 1)
    tcp_server.bind((server_ip, server_port))
    client_init()
    while(True):
        tcp_server.listen(listen_num)
        client, address = tcp_server.accept()
        global tcp_data_rec
        tcp_data_rec = client.recv(buffer_size).decode()
        isSendedReq = True
        client.close()
"""


def client():
    global tcp_data_send, tcp_client, isAnalyzing
    
    data = {}
    data["type"] = "init"
    data["user"] = "packet_analyzer"
    data["port"] = server_port
    
    tcp_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp_client.connect((target_ip, target_port))
    tcp_client.send(json.dumps(data).encode())
    
    while True:
        tcp_data_rec = tcp_client.recv(buffer_size).decode()
        if len(tcp_data_rec) != 0:
            tcp_data_rec = json.loads(tcp_data_rec)
            if tcp_data_rec["type"] == "analyze_req":
                isAnalyzing = True
            if tcp_data_rec["type"] == "analyze_finish":
                isAnalyzing = False

if __name__ == "__main__":
    client_thread = threading.Thread(target = client)
    analyze_thread = threading.Thread(target = analyze)
    client_thread.start()
    analyze_thread.start()
    client_thread.join()
    analyze_thread.join()
