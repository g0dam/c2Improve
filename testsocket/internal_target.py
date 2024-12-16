import socket
import threading

HOST = '127.0.0.1'  # 内部目标服务器的地址
PORT = 8000         # 内部目标服务器的端口

def handle_client(conn, addr):
    print(f"Connected by {addr}")
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            print(f"Received from {addr}: {data}")
            conn.sendall(data)  # 回显数据
    except Exception as e:
        print(f"Connection error with {addr}: {e}")
    finally:
        conn.close()
        print(f"Connection closed with {addr}")

def start_internal_target_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"Internal target echo server listening on {HOST}:{PORT}")
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == '__main__':
    start_internal_target_server()
