from base64 import b64decode
from hashlib import md5
from json import loads
from random import randint
import os

class BaseSer():
    def __init__(self) -> None:
        self.keys_set = set()
        self.temp_keys = set()
        self.aes_keys = dict()
        self.temp_aes_keys = dict()
        self.tasks_dict = dict()
        self.rst_list = list()
        self.online_list = list()
        self.staged_keys = dict()
        self.staged_files = {}  # 用于存储正在传输的文件
        self.hostkey_to_filename = {} 
        self.file_names_dict = {}

    def get_all_keys(self) -> dict:

        return {**self.aes_keys, **self.temp_aes_keys}
    

    def update_aes_key(self, key: str, new_aes_key: str) -> bool:

        if key in self.keys_set:  
            self.aes_keys[key] = new_aes_key
            return True
        elif key in self.temp_keys:  
            self.temp_aes_keys[key] = new_aes_key
            return True
        else:
            return False

    def update_key(self, old_key: str, new_key: str) -> bool:
     
      if old_key in self.keys_set:
          
          self.keys_set.remove(old_key)
          self.keys_set.add(new_key)
         
          self.aes_keys[new_key] = self.aes_keys.pop(old_key)
          
          if old_key in self.tasks_dict:
              self.tasks_dict[new_key] = self.tasks_dict.pop(old_key)
          
          for i in range(len(self.online_list)):
              if self.online_list[i]['key'] == old_key:
                  self.online_list[i]['key'] = new_key
          for i in range(len(self.rst_list)):
              if self.rst_list[i]['key'] == old_key:
                  self.rst_list[i]['key'] = new_key
          return True
      elif old_key in self.temp_keys:
          self.temp_keys.remove(old_key)
          self.temp_keys.add(new_key)
          self.temp_aes_keys[new_key] = self.temp_aes_keys.pop(old_key)
          
          if old_key in self.tasks_dict:
              self.tasks_dict[new_key] = self.tasks_dict.pop(old_key)
          return True
      else:
          return False

    def getkeys(self) -> str:
        if len(self.temp_keys) > 100: 
            self.temp_keys.clear() 
        if len(self.temp_aes_keys) > 100: 
            self.temp_aes_keys.clear() 
        md5_key = md5((str((randint(1,65535)))+"pkcn").encode("utf-8")).hexdigest() 
        aes_key = md5((str((randint(1,65535)))+"pkcn").encode("utf-8")).hexdigest()[:16] 
        self.temp_keys.add(md5_key) 
        self.temp_aes_keys[md5_key] = aes_key 
        self.tasks_dict[md5_key] = {"sleeptime":"","cdm":"getlive"} 
        return md5_key+":"+aes_key 
    
    def get_all_keys(self) -> dict:

        return {**self.aes_keys, **self.temp_aes_keys}

    def add_task(self, key: str, payloads: dict) -> bool:
        print(f"[DEBUG] 添加任务 - key: {key}")
        print(payloads)
        print("添加响应任务", len(self.tasks_dict))
        
        if isinstance(key, str) and payloads:
            try:
                if isinstance(payloads, dict):
                    self.tasks_dict[key] = payloads

                    # 如果 cdm 是 'send_file'，则提取文件名并保存到 file_names_dict
                    if payloads.get('cdm') == 'send_file' and 'file_path' in payloads:
                        file_path = payloads['file_path']
                        file_name = os.path.basename(file_path)  # 获取文件名（不包括路径）
                        
                        # 维护文件名字典，key 是任务的 key，value 是文件名
                        self.file_names_dict[key] = file_name
                        print(f"[DEBUG] 文件名已保存: {key} -> {file_name}")

                    return True
                else:
                    print(f"[ERROR] 无效的任务数据类型: {type(payloads)}")
                    return False
            except Exception as e:
                print(f"[ERROR] 添加任务失败: {e}")
                return False
        return False

    def get_payloads(self, key: str) -> dict:
        print(f"[DEBUG] 获取任务 - key: {key}")
        
        try:
            if key in self.tasks_dict:
                task = self.tasks_dict.pop(key)
                return task
            else:
                print(f"[DEBUG] 未找到对应任务")
                return {}
        except Exception as e:
            print(f"[ERROR] 获取任务失败: {e}")
            return {}

    def checkpwd(self,key:str) -> bool:

        if isinstance(key,str) and ({key} & self.keys_set == {key} or {key} & self.temp_keys == {key}):
            return True
        else:
            return False

    def add_rst(self, rst: dict) -> bool:
        print(f"[DEBUG] Adding result to list - {rst}")
        if isinstance(rst, dict):
            data = rst.get('data', {})
            
            # 处理上线信息
            if data.get('cdm') == 'getlive':
                if {rst.get('key')} & self.temp_keys == {rst.get('key')}:
                    self.keys_set.add(rst.get('key'))
                    self.temp_keys.remove(rst.get('key'))
                    self.aes_keys[rst.get('key')] = self.temp_aes_keys[rst.get('key')]
                    del self.temp_aes_keys[rst.get('key')]
                    self.online_list.append(rst)
                    return True
            
            # 处理文件下载结果
            elif data.get('cdm') == 'download_file':
                print("[DEBUG] Found file download result")
                print(f"[DEBUG] File data size: {len(data.get('file_data', ''))}")
                self.rst_list.append(rst)
                return True
            
            # 处理其他结果
            else:
                self.rst_list.append(rst)
                return True
            
        return False

    def get_rst(self, pwd: str) -> dict:
        if pwd == self.pwd:
            rst = {}
            if self.rst_list:
                for i in self.rst_list:
                    if isinstance(i, dict):
                        rst[i.get('key')] = i
                self.rst_list = []
                print(f"[DEBUG] Returning results: {rst}")
                return rst
        return {}

    def del_host_info(self,key:str) -> bool:

        rst = False
        if isinstance(key,str) and key != "":
            if {key} & self.keys_set == {key}:
                self.keys_set.remove(key)
                del self.aes_keys[key]
                try:
                    del self.tasks_dict[key]
                except KeyError:
                    pass
                count = 0
                for i in self.online_list:
                    if i.get("key") == key:
                        del self.online_list[count]
                        rst = True
                    count += 1
            else:
                pass
        else:
            pass
        return rst
