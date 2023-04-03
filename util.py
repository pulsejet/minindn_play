import subprocess

from mininet import node
from mininet.net import Mininet

try:
    from mn_wifi import node as mn_wifi_node
    HAS_WIFI = True
except ImportError:
    HAS_WIFI = False

try:
    from minindn.util import getPopen
except ImportError:
    def getPopen(host, cmd, **params):
        return host.popen(cmd, cwd=host_home(host), **params)

def is_valid_hostid(net: Mininet, nodeId: str):
    """Check if a nodeId is a host"""
    if nodeId not in net:
        return False

    if not isinstance(net[nodeId], node.Host) and \
        (HAS_WIFI and not isinstance(net[nodeId], mn_wifi_node.Station)):
        return False

    return True

def run_popen(node, cmd):
    """Helper to run command on node asynchronously and get output"""
    process = getPopen(node, cmd, stdout=subprocess.PIPE)
    return process.communicate()[0]

def run_popen_readline(node, cmd):
    """Helper to run command on node asynchronously and get output line by line"""
    process = getPopen(node, cmd, stdout=subprocess.PIPE)
    while True:
        line = process.stdout.readline()
        if not line:
            break
        yield line

def host_home(node) -> str | None:
    """Get home directory for host"""
    if 'params' not in node.params or 'homeDir' not in node.params['params']:
        return None
    return node.params['params']['homeDir']