# traffic-spot-rs
Automatically start and stop services based on monitored network traffic

## Important Note
Currently the start/stop commands must exit after starting/stopping the service, such as a "systemctl start" or "docker start"
This program does not support starting a long running daemon at this time.

## General info

In order to be completely transparent this program sniffs network traffic to be able to trigger the service and monitor its use without having to either proxy all the traffic or stop using the listening port immediately on service start (as this would prevent the timeout shutdown functionality which is critical)

Currently this program requires root privileges in order to sniff the network traffic. Ideally a transparent bidirectional proxy would be the solution here, however for my usecase (Palworld server start/stop) the sniffing option function well.

Partially inspired by:
https://github.com/mark-kubacki/systemd-transparent-udp-forwarderd
