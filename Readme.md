# Packet_count

**This Go program utilizes eBPF (extended Berkeley Packet Filter) technology to parse network packets and count the number of packets received from each unique source IP address and port combination. It attaches an XDP (eXpress Data Path) program to a specified network interface and periodically reads packet counts from the eBPF map. Packet metadata is parsed using custom data structures, and counts are displayed or processed as needed.**

* To run, provide a iface flag value (eth0, enp2so, wlp3s0 ...)
    ```sudo ./packet_count --iface enp2s0```

* To find the network interface on your system: run on bash:$
    ```ip link show```