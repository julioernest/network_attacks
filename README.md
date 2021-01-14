# network_attacks

## This is a final project done for Secure Network Management course from Munich Applied Science University
![alt text](https://github.com/julioernest/network_attacks/blob/main/network.jpeg)
#### We used Scappy to deliver several attacks on a small network.

## **Reconnaisance atacks**

#### Port Scanning (port-scan.py)
Port scanning is a method of determining which ports on a network are open and could be receiving or sending data. It is also a process for sending packets to specific ports on a host and analyzing responses to identify vulnerabilities. 
Ports 1-1024 are scanned on PC1 using SYN scan.
A TCP packet with SYN flag is sent to PC1. If ACK is received, the port is open, otherwise it's closed.
If a port is open, then we send a RST to avoid leaving the connection in a half-open state

#### Operating system detection (os-probe.py)
This type of attack is useful when you want to **detect the operating system of the targeted device**. It is sometimes very difficult to determine remotely whether an available service is susceptible or patched for a certain vulnerability.
A TCP handshake is performed with PC1 on port 22. Then, another TCP packet with no flags set and a fake payload is sent.
If the response contains a ACK flag, then the os runs on a linux kernel newer than verion 2.4
Otherwise, the response will most probably contain an RST flag (indicating another OS).

#### HTTP Traffic sniffer (http-sniffer.py)
Hypertext transfer protocol is used at layer 7 of the OSI model. This is an application layer protocol that transmits the information in plain text
All HTTP traffic is caputred and displayed.
Requests and responses always apear twice (once entering the interface and once leaving the interface) due to a bug in scapy.

### Denial of Servce attacks

#### ARP table poisoning (arp-poisoning.py)
A ARP reply is sent to the R6 Router containing this PC4's MAC address and PC1's IP.
This will cause all packets intended for PC1 passing trough R6 to be directed towards PC4.

#### ARP table flooding (mac-flood.py)
Random ARP packets (with random mac's and ip's) are sent on the network. This will cause virtualbox's switch's ARP table to overflow, causing it to work like a hub, effectively allowing us to monitor every packet on the network on interface enp0s3.
The script first prepares 65536 random ARP packets and the sends them all.

#### SYN flood (syn-flood.py)
A SYN flood (half-open attack) is a type of denial-of-service (DDoS) attack which aims to make a server unavailable to legitimate traffic by consuming all available server resources. By repeatedly sending initial connection request (SYN) packets, the attacker is able to overwhelm all available ports on a targeted server machine, causing the targeted device to respond to legitimate traffic sluggishly or not at all.
SYN flood is done by preparing SYN packets intended for opening TCP conenctions and sending them, without actually folowing up with the TCP connection. This is done repeatedly. Eventually the number of connections saturates tcpMaxConn and we can no longer connect to PC1.

#### Ping of Death and IP spoofing (ping-of-death.py)
An Internet Control Message Protocol (ICMP) echo-reply message or “ping”, is a network utility used to test a network connection, and it works much like sonar – a “pulse” is sent out and the “echo” from that pulse tells the operator information about the environment. If the connection is working, the source machine receives a reply from the targeted machine.
While some ping packets are very small, IP4 ping packets are much larger, and can be as large as the maximum allowable packet size of 65,535 bytes. Some TCP/IP systems were never designed to handle packets larger than the maximum, making them vulnerable to packets above that size.

We construct a 65k byte ICMP ping packet.
Then, we construct an IP packet appearing to have been sent by PC2 towards PC3. We send this packet into the network repeatedly.
After receiving the ping request, PC3 send a ping response to PC2, effectively extending out attack. Unless the router keep logs of what packets are routed, this attack is nearly untraceable.
It is expected that not all ICMP pings arrive at the destination due to dropped IP fragments. Most networks have an MTU significantly smaller than the 65k packet size.

#### RIP poisoning (rip-poisoning.py)**man in the middle type attack**
We will attempt to izolate PC3 from the rest of the PC's by poisoning the routing tables of R1, R2 and R6.
PC4 sends RIP packages to these routers, and using IP spoofing, creates routing entries. All packets intended for PC3 are routed towards towards PC2. To achieve this, R6 is set to forward to R1 and R1 is set to forward to R2. R2 is set to forward to PC2 which is a dead end.
All packets going towards PC3 end up reaching PC2, therefore bidirectional communication between PC3 and other PC's cannot happen. If PC3 wants to access PC2, it can do this, but PC2 cannot respond back.
Any TCP handshake will not happen. UDP from PC3 to PC2 can work in one direction only.
