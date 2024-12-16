import socket
import threading
from flask import Flask
from flask_socketio import SocketIO, emit
from socketio import Client as SocketIOClient

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app, cors_allowed_origins="*")

# trojan需要同时作为socketio的客户端连接server，以及作为本地服务器转发内部连接的数据
SERVER_URL = 'http://127.0.0.1:5000'

sio = SocketIOClient()

# session_id到内部连接的映射
session_to_internal_conn = {}

@sio.event
def connect():
    print("Connected to server")
    sio.emit('trojan_register', {})

@sio.event
def trojan_registered(data):
    print("Registered as trojan:", data)

@sio.event
def disconnect():
    print("Disconnected from server")
    # 清理内部连接
    for s_id, conn in session_to_internal_conn.items():
        conn.close()
    session_to_internal_conn.clear()

@sio.on('establish_internal_conn')
def on_establish_internal_conn(data):
    # server要求trojan建立内网连接
    session_id = data.get('session_id')
    target_host = data.get('target_host')
    target_port = data.get('target_port')
    # 尝试连接内网目标
    try:
        c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        c.connect((target_host, target_port))
        session_to_internal_conn[session_id] = c
        # 启动线程读取内网返回的数据并转发给server
        threading.Thread(target=read_internal_data, args=(session_id, c), daemon=True).start()
    except Exception as e:
        print("Failed to connect internal target:", e)

@sio.on('close_internal_conn')
def on_close_internal_conn(data):
    session_id = data.get('session_id')
    conn = session_to_internal_conn.get(session_id)
    if conn:
        conn.close()
        del session_to_internal_conn[session_id]

@sio.on('data_from_server')
def on_data_from_server(data):
    # server转发来的数据，发送给内部连接
    session_id = data.get('session_id')
    payload = data.get('payload', b'')
    conn = session_to_internal_conn.get(session_id)
    if conn:
        conn.sendall(payload)

def read_internal_data(session_id, conn):
    while True:
        try:
            data = conn.recv(4096)
            if not data:
                break
            # 将数据发送回server
            sio.emit('data_from_trojan', {
                'session_id': session_id,
                'payload': data
            })
        except:
            break
    # 连接结束
    conn.close()
    if session_id in session_to_internal_conn:
        del session_to_internal_conn[session_id]
    sio.emit('data_from_trojan', {
        'session_id': session_id,
        'payload': b''  # 表示连接结束
    })

def start_sio_client():
    sio.connect(SERVER_URL)
    sio.wait()

if __name__ == '__main__':
    # trojan不需要另外的HTTP端口监听，因为它主要是socketio客户端和本地socket转发
    # 如果需要在trojan上再启动一个WS服务，可自行添加
    start_sio_client()
