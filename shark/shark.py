import msgpack
import ipaddress

from pathlib import Path
from threading import Thread

from mininet.net import Mininet
from mininet.log import error, info
from ..socket import PlaySocket
from ..consts import Config, WSFunctions, WSKeys
from .. import util

# TShark fields
SHARK_FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "ndn.len",
    "ndn.type",
    "ndn.name",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    # "ndn.bin", # binary data
]
SHARK_FIELDS_STR = " -Tfields -e " + " -e ".join(SHARK_FIELDS) + " -Y ndn.len"

class SharkExecutor:
    def __init__(self, net: Mininet, socket: PlaySocket):
        self.net = net
        self.socket = socket
        self._ip_map = None

    def _get_pcap_file(self, name):
        return '{}{}-interfaces.pcap'.format('./', name)

    def _get_lua(self):
        luafile = str(Path(__file__).parent.parent.absolute()) + '/ndn.lua'
        return 'lua_script:' + luafile

    def _convert_to_full_ip_address(self, ip_address: str):
        try:
            ip_obj = ipaddress.ip_address(ip_address)
        except ValueError:
            return ip_address

        if isinstance(ip_obj, ipaddress.IPv6Address):
            return str(ip_obj)
        else:
            return ip_address

    def _get_hostname_from_ip(self, ip):
        """
        Get the hostname of a node given its IP address.
        node: the node to check on (e.g. for local addresses)
        This function runs once and caches the result, since we need to visit
        each node to get its list of IP addresses.
        """
        if self._ip_map is None:
            # Map of IP address to hostname
            self._ip_map = {}

            # Extract all addresses including localhost
            cmd = "ip addr show | grep -E 'inet' | awk '{print $2}' | cut -d '/' -f1"

            hosts = self.net.hosts
            hosts += getattr(self.net, 'stations', []) # mininet-wifi
            for host in hosts:
                for ip in host.cmd(cmd).splitlines():
                    if full_ip := self._convert_to_full_ip_address(ip):
                        self._ip_map[full_ip] = host.name
            info('Created IP map for PCAP (will be cached): {}\n'.format(self._ip_map))

        if full_ip := self._convert_to_full_ip_address(ip):
            return self._ip_map.get(full_ip, ip)
        return ip

    def _send_pcap_chunks(self, nodeId: str, known_frame: int, include_wire: bool):
        """
        Get, process and send chunks of pcap to UI
        Blocking; should run in its own thread.
        """

        node = self.net[nodeId]
        file = self._get_pcap_file(nodeId)

        # We don't want to load and process the entire pcap file
        # every time the user wants to recheck. Instead, use editcap
        # to cut the part the user knows

        # Look back by upto 12 frames in case the last packet was fragmented
        known_frame = max(1, known_frame - 12)

        # Get everything after known frame
        editcap_cmd = "editcap -r {} {} {}-0".format(file, "/dev/stdout", known_frame)

        # Shark using NDN dissector
        extra_fields = "-e ndn.bin " if include_wire else ""
        list_cmd = 'tshark {} {} -r {} -X {}'.format(SHARK_FIELDS_STR, extra_fields, "/dev/stdin", self._get_lua())

        # Pipe editcap to tshark
        piped_cmd = ['bash', '-c', '{} | {}'.format(editcap_cmd, list_cmd)]

        # Collected packets (one chunk)
        packets = []

        def _send_packets(last=False):
            """Send the current chunk to the UI (including empty)"""
            res = {
                'id': nodeId,
                'packets': packets,
            }
            if last:
                res['last'] = True

            self.socket.send_all(msgpack.dumps({
                WSKeys.MSG_KEY_FUN: WSFunctions.GET_PCAP,
                WSKeys.MSG_KEY_RESULT: res,
            }))

        # Iterate each line of output
        for line in util.run_popen_readline(node, piped_cmd):
            parts: list[str] = line.decode('utf-8').strip('\n').split('\t')

            if len(parts) < 8:
                error('Invalid line in pcap: {}\n'.format(parts))
                continue

            is_ipv6 = parts[7] != '' and parts[8] != ''
            from_ip = parts[7] if is_ipv6 else parts[5]
            to_ip = parts[8] if is_ipv6 else parts[6]

            packets.append([
                int(parts[0]) + known_frame - 1, # frame number
                float(parts[1]) * 1000, # timestamp
                int(parts[2]), # length
                str(parts[3]), # type
                str(parts[4]), # NDN name
                str(self._get_hostname_from_ip(from_ip)), # from
                str(self._get_hostname_from_ip(to_ip)), # to
                bytes.fromhex(parts[9]) if include_wire else 0, # packet content
            ])

            if len(packets) >= Config.PCAP_CHUNK_SIZE:
                _send_packets()
                packets = []

        # Send the last chunk
        _send_packets(last=True)

    async def get_pcap(self, nodeId: str, known_frame: int, include_wire=False):
        """UI Function: Get list of packets for one node"""
        if not util.is_valid_hostid(self.net, nodeId):
            return

        # Run processing in separate thread
        t = Thread(target=self._send_pcap_chunks, args=(nodeId, known_frame, include_wire), daemon=True)
        t.start()

    async def get_pcap_wire(self, nodeId, frame):
        """UI Function: Get wire of one packet"""
        if not util.is_valid_hostid(self.net, nodeId):
            return
        file = self._get_pcap_file(nodeId)

        # chop the file to the frame
        # include the last 12 frames in case of fragmentation
        start_frame = max(1, frame - 12)
        new_frame = frame - start_frame + 1

        try:
            # Get last 12 frames
            editcap_cmd = "editcap -r {} {} {}-{}".format(file, "/dev/stdout", start_frame, frame)

            # Filter for this packet only
            wire_cmd = 'tshark -r {} -e ndn.bin -Tfields -X {} frame.number == {}'.format('-', self._get_lua(), new_frame)

            # Pipe editcap to tshark
            piped_cmd = ['bash', '-c', '{} | {}'.format(editcap_cmd, wire_cmd)]
            hex = util.run_popen(self.net[nodeId], piped_cmd).decode('utf-8').strip()
            return bytes.fromhex(hex)
        except Exception:
            error('Error getting pcap wire for {}'.format(nodeId))