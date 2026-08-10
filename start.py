import webview
from app import app
import sys
import threading
import uuid
import socket
from werkzeug.serving import make_server

def get_free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port

class ServerThread(threading.Thread):
    def __init__(self, app, port):
        threading.Thread.__init__(self)
        self.server = make_server('127.0.0.1', port, app)
        self.ctx = app.app_context()
        self.ctx.push()

    def run(self):
        self.server.serve_forever()

    def shutdown(self):
        self.server.shutdown()

if __name__ == '__main__':
    # Generate a secure token to restrict access to the wrapper
    secure_token = str(uuid.uuid4())
    app.config['SECURE_TOKEN'] = secure_token
    app.secret_key = str(uuid.uuid4()) # override with a new random one
    
    port = get_free_port()
    
    server = ServerThread(app, port)
    server.start()
    
    url = f'http://127.0.0.1:{port}/?token={secure_token}'
    
    # Start PyWebView pointing to the local server URL
    webview.create_window('Firewall Rule Review', url, width=1280, height=800, background_color='#0b1220')
    webview.start()
    
    server.shutdown()
    sys.exit(0)
