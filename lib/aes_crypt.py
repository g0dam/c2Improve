from Crypto.Cipher import AES
from binascii import a2b_hex, b2a_hex

# class DataAesCrypt:

#     def __init__(self,keys:str,data:str) -> None:
#         self.keys = keys[:16].encode("utf-8")
#         self.data = data

#     def encrypt(self):
#         text = self.data + (16 - (len(self.data) % 16)) * "="
#         aes = AES.new(self.keys, AES.MODE_ECB)
#         en_text = b2a_hex(aes.encrypt(text.encode("utf-8")))
#         return en_text.decode("utf-8")
    
#     def decrypt(self):
#         aes = AES.new(self.keys, AES.MODE_ECB)
#         text = aes.decrypt(a2b_hex(self.data.encode("utf-8")))
#         return text.decode("utf-8").split("=")[0] 

class DataAesCrypt:
    def __init__(self, keys: str, data: str) -> None:
        self.keys = keys[:16].encode("utf-8")
        self.data = data

    def encrypt(self):
        text = self.data + (16 - (len(self.data) % 16)) * "="
        aes = AES.new(self.keys, AES.MODE_ECB)
        en_text = b2a_hex(aes.encrypt(text.encode("utf-8")))
        return en_text.decode("utf-8")
    
    def decrypt(self):
        aes = AES.new(self.keys, AES.MODE_ECB)
        decrypted_data = aes.decrypt(a2b_hex(self.data.encode("utf-8")))
        
        # 直接去除填充符号
        text = decrypted_data.decode("utf-8").rstrip("=")
        return text
