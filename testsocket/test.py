import socket
import time
from base64 import b64decode, b64encode
PROXY_HOST = '127.0.0.1'  # client.py 监听的地址
PROXY_PORT = 7777         # client.py 监听的端口
TEST_MESSAGE = b'Hello through proxy!'

def test_proxy():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        print(f"Connecting to proxy at {PROXY_HOST}:{PROXY_PORT}")
        s.connect((PROXY_HOST, PROXY_PORT))
        print("Connected to proxy.")

        print(f"Sending test message: {TEST_MESSAGE}")
        s.sendall(TEST_MESSAGE)

        # 等待响应
        s.settimeout(5.0)  # 设置超时时间为5秒
        try:
            data = s.recv(4096)
            if data:
                print(f"Received echo: {data}")
                data = b64decode(data)
                if data == TEST_MESSAGE:
                    print("Test passed: Echoed data matches sent data.")
                else:
                    print("Test failed: Echoed data does not match sent data.")
            else:
                print("Test failed: No data received.")
        except socket.timeout:
            print("Test failed: No response received (timeout).")

if __name__ == '__main__':
    # 等待几秒以确保所有服务都已启动
    print("Waiting for services to initialize...")
    time.sleep(5)
    test_proxy()
