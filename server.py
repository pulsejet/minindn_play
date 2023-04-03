from threading import Thread
from .monitor import LogMonitor
from .socket import PlaySocket
from .net.topo import TopoExecutor
from .net.state import StateExecutor
from .term.term import TermExecutor
from .shark.shark import SharkExecutor
from mininet.net import Mininet

class PlayServer:
    net: Mininet
    repl: bool
    cli: bool
    monitors: list[LogMonitor] = []

    def __init__(self, net: Mininet, **kwargs) -> None:
        """
        Start NDN Play GUI server.
        If cli=True is specified (default), will block for the Mininet CLI.
        """

        self.net = net
        self.repl = kwargs.get('repl', False)
        self.cli = kwargs.get('cli', True)

        self.socket = PlaySocket()
        self.socket.add_executor(TopoExecutor(net))
        self.socket.add_executor(StateExecutor(net))

        self.shark_executor = SharkExecutor(net, self.socket)
        self.socket.add_executor(self.shark_executor)

        self.pty_executor = TermExecutor(net, self.socket)
        self.socket.add_executor(self.pty_executor)

    def start(self):
        if self.repl:
            Thread(target=self.pty_executor.start_repl).start()

        # Start all monitors
        for monitor in self.monitors:
            monitor.start(self.socket)

        # Blocks until Mininet CLI is closed
        if self.cli:
            self.pty_executor.start_cli()

        # Stop all monitors
        for monitor in self.monitors:
            monitor.stop()

    def add_monitor(self, monitor: LogMonitor):
        self.monitors.append(monitor)