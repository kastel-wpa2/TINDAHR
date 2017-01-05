from flask import Flask
from flask_socketio import SocketIO, send, emit
import logging
import threading

class WebAdapter():
    def __init__(self, conn_list_instance, deauth_fn, port=8080):
        self._conn_list_instance = conn_list_instance
        
        app = Flask(__name__, static_folder='static', static_url_path=None)
        app.config['SECRET_KEY'] = 'secret!'

        @app.route("/")
        def root():
            return app.send_static_file('index.html')

        socketio = SocketIO(app)

        socketio.on_event("send_connections_list", self._send_connections_list)
        socketio.on_event("start_deauth", self._start_deauth)

        t = threading.Thread(target=lambda: socketio.run(app, port=port))
        t.daemon = True

        def start():
            t.start()
            print "Started server on localhost:%i" % (port) 

        self.start = start

    def _send_connections_list(self):
        emit("connections_list", self._conn_list_instance.get_as_popo(), json=True)

    def _start_deauth(self, _):
        pass


if __name__ == '__main__':
    adapter = WebAdapter(None)
else:
    # Prevent werkzeug from bloating cli output
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)