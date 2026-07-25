import webview
from app import app
import sys

if __name__ == '__main__':
    # Start the PyWebView application wrapping the Flask app
    webview.create_window('Firewall Rule Review', app, width=1280, height=800, background_color='#0b1220')
    webview.start()
