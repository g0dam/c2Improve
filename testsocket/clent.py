import socket
import threading
from flask import Flask
from flask_socketio import SocketIO, emit

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app, cors_allowed_origins="*")

# 假设本地有应用程序通过localhost:7777与我们通信，我们将建立本地TCP服务器监听7777端口，然后将数据通过WebSocket发给Server
LOCAL_LISTEN_PORT = 7777
SERVER_WS_URL = 'http://127.0.0.1:5000'  # server的地址和端口

# 用于标识不同的会话连接，比如多个 SOCKS5 会话
# key: local_conn (socket对象), value: session_id
session_map = {}
session_id_counter = 1000

from socketio import Client as SocketIOClient
sio = SocketIOClient()

@sio.event
def connect():
    print("Connected to server")

@sio.event
def connect_error(data):
    print("Failed to connect to server:", data)

@sio.event
def disconnect():
    print("Disconnected from server")

@sio.on('response_from_server')
def on_server_response(data):
    # 从server返回的数据，包含session_id和实际payload
    session_id = data.get('session_id')
    payload = data.get('payload', b'')
    # 根据session_id找到对应的本地连接，将数据写回
    for conn, sid in session_map.items():
        if sid == session_id:
            conn.sendall(payload)

def start_ws_client():
    # 连接server的WS
    sio.connect(SERVER_WS_URL)
    sio.wait()


def handle_local_connection(conn, addr):
    global session_id_counter
    session_id_counter += 1
    this_session_id = session_id_counter
    session_map[conn] = this_session_id

    # 假设从应用数据中我们能得知目标host(此处举例为'target_host'标识符)
    # 实际需要从SOCKS5握手和请求阶段解析目标host和port
    target_host = "127.0.0.1"
    target_port = 8000

    # 通知server建立对应的session
    sio.emit('start_session', {
        'session_id': this_session_id,
        'target_host': target_host,
        'target_port': target_port
    })

    print(f"Session {this_session_id} started with target {target_host}:{target_port}")

    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            # 将数据通过WS转发给server
            sio.emit('data_from_client', {
                'session_id': this_session_id,
                'payload': data
            })
    except Exception as e:
        print("Local connection error:", e)
    finally:
        # 关闭会话
        sio.emit('end_session', {'session_id': this_session_id})
        conn.close()
        del session_map[conn]


def start_local_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('0.0.0.0', LOCAL_LISTEN_PORT))
    s.listen(5)
    print("Local SOCKS5-like proxy listening on port", LOCAL_LISTEN_PORT)
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_local_connection, args=(conn, addr)).start()


if __name__ == '__main__':
    # 启动本地监听线程
    threading.Thread(target=start_local_server, daemon=True).start()
    # 启动与server通信的WS客户端
    start_ws_client()
