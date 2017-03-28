from flask import Flask
from flask_socketio import SocketIO, send, emit
import logging
import threading


class WebAdapter():

    def __init__(self, conn_list_instance, deauth_fn, port=8080):
        self._conn_list_instance = conn_list_instance
        self._deauth_fn = deauth_fn

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

    def _start_deauth(self, opts):
        print "Receveived request for deauth attack, starting..."
        results = self._deauth_fn(opts["target_mac"], opts["ap_mac"], int(
            opts["channel"]), int(opts["deauth_packets_amount"]), opts["capture_handshake"])
        print "Deauth done"
        emit("deauth_done", results, json=True)


if __name__ != '__main__':
    # Prevent werkzeug from bloating cli output
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
