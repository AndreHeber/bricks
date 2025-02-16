# Overview of the tool

1. Read the pcap file: Use the gopacket library (particularly pcap.OpenOffline) to open and iterate over the packets.
2. Extract the capture period: Record the timestamp from the first and last packet so you can compute the overall duration.
3. List involved IPs and Ports: For each packet, extract the network layer (for IP addresses) and the transport layer (for TCP/UDP port numbers), storing unique values.
4. Build a packet flow diagram: For simplicity, we’ll record flows between endpoints (e.g. "10.0.0.1:443 -> 192.168.1.5:1234") along with a count of packets for each flow. This text-based diagram will show each flow and the number of packets that belong to it.
5. Print out the overview: Finally, we output the capture period, lists of unique IPs/ports, and the flow diagram in text format.