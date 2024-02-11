# traffic-spot-rs
Automatically start and stop services based on monitored network traffic

## Important Note
Currently the start/stop commands must exit after starting/stopping the service, such as a "systemctl start" or "docker start"
This program does not support starting a long running daemon at this time.
Ports specified are UDP only at this stage.

## General info

In order to be completely transparent this program sniffs network traffic to be able to trigger the service and monitor its use without having to either proxy all the traffic or stop using the listening port immediately on service start (as this would prevent the timeout shutdown functionality which is critical)

Currently this program requires root privileges in order to sniff the network traffic. Ideally a transparent bidirectional proxy would be the solution here, however for my usecase (Palworld server start/stop) the sniffing option function well.

Partially inspired by:
https://github.com/mark-kubacki/systemd-transparent-udp-forwarderd

## Usage
Usage: traffic-spot-rs [OPTIONS] --start-command <START_COMMAND> <--port <port>|--tcp <TCP Port>|--udp <UDP Port>>

Options:
  -p, --port <PORT (tcp & udp)> - Specify both TCP/UDP port to listen on.
  -t, --tcp <TCP PORT> - Listen on specific TCP Port
  -u, --udp <UDP PORT> - Liston on specific UDP Port
  -a, --address <LOCAL IP ADDRESS> - Local IP to listen on, we will try to determine the default address if omitted.
  -s, --start-command <START_COMMAND> - Command to start the service. (Currently must exit promptly, do NOT the service executable)
  -f, --finish-command <FINISH_COMMAND> - Command to stop the service. Recommended, otherwise the service will have to stop itself. (Restarts after timeout still functions)
      --timeout <TIMEOUT in Seconds>                [default: 900]
  -d, --debug - Add extra output, shows packet counts per RATE
  -r, --rate <RATE>                      [default: 1000] - Time in MS to tally all received packets. Small values increase CPU and reduce RAM, Large values decrease CPU but increase RAM.
  -h, --help                             Print help
  -V, --version                          Print version