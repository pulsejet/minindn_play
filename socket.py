import os
import asyncio
import urllib
import websockets
import msgpack
import secrets
import time

from .consts import Config, WSKeys
from mininet.log import error

from threading import Thread

class PlaySocket:
    conn_list: dict = {}
    executors: list = []
    AUTH_TOKEN: str | None = None

    def __init__(self):
        """Initialize the PlaySocket.
        This starts the background loop and creates the websocket server.
        Calls to UI async functions are made from this class.
        """

        self._set_auth_token()
        self.loop = asyncio.new_event_loop()
        Thread(target=self._run, args=(), daemon=True).start()

    def add_executor(self, executor):
        self.executors.append(executor)

    def send(self, websocket, msg):
        """Send message to UI threadsafe"""
        if websocket.open:
            self.loop.call_soon_threadsafe(self.loop.create_task, websocket.send(msg))

    def send_all(self, msg):
        """Send message to all UI threadsafe"""
        for websocket in self.conn_list:
            try:
                self.send(websocket, msg)
            except:
                del self.conn_list[websocket]

    def _set_auth_token(self):
        """Create auth token if it doesn't exist."""

        # Perist auth token so you don't need to refresh every time
        # Check if AUTH_FILE was modified less than a day ago
        if os.path.exists(Config.AUTH_FILE) and time.time() - os.path.getmtime(Config.AUTH_FILE) < 24 * 60 * 60:
            with open(Config.AUTH_FILE, 'r') as f:
                self.AUTH_TOKEN = f.read().strip()

        if not self.AUTH_TOKEN or len(self.AUTH_TOKEN) < 10:
            self.AUTH_TOKEN = secrets.token_hex(16)
            with open(Config.AUTH_FILE, 'w') as f:
                f.write(self.AUTH_TOKEN)

    def _run(self) -> None:
        """Runs in separate thread from main"""

        # Show the URL to the user
        ws_url = "ws://{}:{}".format(Config.SERVER_HOST_URL, Config.SERVER_PORT)
        ws_url_q = urllib.parse.quote(ws_url.encode('utf8'))
        full_url = "{}/?minindn={}&auth={}".format(Config.PLAY_URL, ws_url_q, self.AUTH_TOKEN)
        print('Open NDN Play GUI at {}'.format(full_url))

        # Start server
        asyncio.set_event_loop(self.loop)
        start_server = websockets.serve(self._serve, Config.SERVER_HOST, Config.SERVER_PORT)
        self.loop.run_until_complete(start_server)
        self.loop.run_forever()

    async def _serve(self, websocket, path):
        """Handle websocket connection"""

        try:
            auth = urllib.parse.parse_qs(urllib.parse.urlparse(path).query)['auth'][0]
            if auth != self.AUTH_TOKEN:
                raise Exception("Invalid auth token")
        except:
            print('Rejected connection from {}'.format(websocket.remote_address))
            await websocket.close()
            return

        print('Accepted connection from {}'.format(websocket.remote_address))
        self.conn_list[websocket] = 1
        while True:
            try:
                fcall = msgpack.loads(await websocket.recv())
                loop = asyncio.get_event_loop()
                loop.create_task(self._call_fun(websocket, fcall))
            except websockets.exceptions.ConnectionClosedOK:
                print('Closed connection gracefully from {}'.format(websocket.remote_address))
                break
            except websockets.exceptions.ConnectionClosedError:
                print('Closed connection with error from {}'.format(websocket.remote_address))
                break

        del self.conn_list[websocket]

    async def _call_fun(self, websocket, fcall):
        """Call function and return result to UI asynchronously"""

        # Get function from any executor
        fun = None
        for executor in self.executors:
            fun = getattr(executor, fcall[WSKeys.MSG_KEY_FUN], None)
            if fun is not None:
                break

        # Function not found
        if fun is None:
            error('Function {} not found\n'.format(fcall[WSKeys.MSG_KEY_FUN]))
            return # function not found

        # Call function
        res = await fun(*fcall[WSKeys.MSG_KEY_ARGS])
        if res is not None:
            pack = msgpack.dumps({
                WSKeys.MSG_KEY_FUN: fcall[WSKeys.MSG_KEY_FUN],
                WSKeys.MSG_KEY_RESULT: res,
            })
            await websocket.send(pack)
