# minindn_play

GUI server for MiniNDN and Mininet. This is a web application that allows you to create and manage a MiniNDN network topology. It is based on the [MiniNDN](https://github.com/named-data/mini-ndn), a wrapper around Mininet, and [NDN-Play](https://github.com/pulsejet/ndn-play), a visualizer for NDN topologies.

## Installation

In your MiniNDN directory, clone this repository and install the dependencies:

```bash
# Clone the repository
git clone https://github.com/pulsejet/minindn_play
cd minindn_play

# Install the dependencies
sudo pip install -r requirements.txt

# Get the NDN packet dissector (only if you're using Tshark features)
wget https://raw.githubusercontent.com/named-data/ndn-tools/master/tools/dissect-wireshark/ndn.lua

cd ..
```

## Features

- Create and manage the Mininet topology visually in the browser.
- Perform functions such as moving nodes in mininet-wifi while the network is running.
- Gain an interactive TTY shell on individual nodes in the browser itself.
- Monitor events in the network through log files, helpful for finding hot paths.
- Monitor the network traffic using Wireshark (NDN only).
- Inspect NDN TLV packets with custom TLV types.
- Store the dump of an experiment results and replay it later.

## Usage

A full example for MiniNDN can be found in [example.py](example.py).

To start the server, add the following to your Mininet script. This will print the URL of the server. If running remotely, you must make sure to forward the port 8765 to the local machine where the browser is running (this port is used by the websocket server).

```python
from minindn_play.server import PlayServer

if __name__ == '__main__':
    ...
    PlayServer(net).start() # starts the server and blocks
```

### Wireshark

MiniNDN stores the `hosts.params['params']['homeDir']` variable for all hosts, used to identify the home directory of the nodes. The wireshark dump must be stored in `shark.log` in the `log` directory for each node. Using the app manager, this can be done as,

```python
from minindn.apps.app_manager import AppManager
from minindn.apps.tshark import Tshark

if __name__ == '__main__':
    ...
    ndn.initParams(ndn.net.hosts)
    sharks = AppManager(ndn, ndn.net.hosts, Tshark, singleLogFile=True)
```

Once setup, the dump will be visible for each node and the TLV inspector will show each packet on double-clicking it in the GUI.

### Log Monitor

The log monitor tails one or more log files on each node and shows the events on the topology visually. In the following example, the `log/my_app.log` at each host will be monitored every `200ms`, for all lines (matching the regex `.*`).

```python
from minindn_play.monitor import LogMonitor

if __name__ == '__main__':
    ...

    server = PlayServer(net)
    server.add_monitor(LogMonitor(net.hosts, "log/my_app.log", interval=0.2, filter=".*"))
    server.start()
```
