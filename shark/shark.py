import msgpack

from pathlib import Path
from threading import Thread

from mininet.net import Mininet
from mininet.log import error
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
    # "ndn.bin", # binary data
]
SHARK_FIELDS_STR = " -Tfields -e " + " -e ".join(SHARK_FIELDS) + " -Y ndn.len"

class SharkExecutor:
    def __init__(self, net: Mininet, socket: PlaySocket):
        self.net = net
        self.socket = socket

    def _get_pcap_file(self, name):
        return '{}{}-interfaces.pcap'.format('./', name)

    def _get_lua(self):
        luafile = str(Path(__file__).parent.absolute()) + '/ndn.lua'
        return 'lua_script:' + luafile

    def _get_ip_map(self):
        """Get IP address map for all links in net"""
        addresses = {}
        def addIntf(intf):
            if isinstance(intf, str):
                # TODO: maybe "wifiAdhoc"; what then?
                return
            addresses[intf.ip] = intf.node.name

        for link in self.net.links:
            addIntf(link.intf1)
            addIntf(link.intf2)

        return addresses

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

        # Map for source and destination nodes
        ip_map = self._get_ip_map()

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
            line = line.decode('utf-8').strip().split()

            if len(line) < 6:
                continue

            packets.append([
                int(line[0]) + known_frame - 1, # frame number
                float(line[1]) * 1000, # timestamp
                int(line[2]), # length
                line[3], # type
                line[4], # NDN name
                ip_map.get(line[5], line[5]), # from
                ip_map.get(line[6], line[6]), # to
                bytes.fromhex(line[7]) if include_wire else 0, # packet content
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