from mininet.net import Mininet
from .. import util

class StateExecutor:
    def __init__(self, net: Mininet):
        self.net = net

    async def get_fib(self, nodeId):
        """UI Function: Get the NFDC status report and ifconfig as the fib"""
        if not util.is_valid_hostid(self.net, nodeId):
            if nodeId in self.net:
                node = self.net[nodeId]
                return { 'id': nodeId, 'fib': "Node is not a host ({})".format(node.__class__.__name__) }
            return

        node = self.net[nodeId]
        nfd_status = util.run_popen(node, "nfdc status report".split()).decode('utf-8')
        ifconfig = util.run_popen(node, "ifconfig".split()).decode('utf-8')
        output = nfd_status + "\n" + ifconfig
        return {
            'id': nodeId,
            'fib': output,
        }