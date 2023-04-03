import msgpack
import re

from time import sleep
from io import TextIOWrapper
from threading import Thread
from mininet.node import Node
from .socket import PlaySocket
from .consts import WSKeys, WSFunctions
from . import util

class LogMonitor:
    nodes: list[Node]
    logFile: str
    interval: float
    socket: PlaySocket
    filter: re.Pattern
    quit: bool = False

    def __init__(self, nodes: list, logFile: str, interval: float = 0.5, filter: str = ''):
        self.nodes = nodes
        self.logFile = logFile
        self.interval = interval
        self.filter = re.compile(filter)

    def start(self, socket: PlaySocket):
        self.socket = socket
        Thread(target=self._start).start()

    def stop(self):
        self.quit = True

    def _start(self):
        files: list[TextIOWrapper] = []
        counts: dict[str, int] = {}

        for node in self.nodes:
            path = '%s/%s' % (util.host_home(node), self.logFile)
            files.append(open(path, 'r'))
            counts[node.name] = 0

        while not self.quit:
            for i, file in enumerate(files):
                node = self.nodes[i]
                counts[node.name] = 0
                while line := file.readline():
                    if self.filter.match(line):
                        counts[node.name] += 1

            self._send(counts)
            sleep(self.interval)

        for file in files:
            file.close()

    def _send(self, counts: dict[str, int]):
        self.socket.send_all(msgpack.dumps({
            WSKeys.MSG_KEY_FUN: WSFunctions.MONITOR_COUNTS,
            WSKeys.MSG_KEY_RESULT: counts,
        }))