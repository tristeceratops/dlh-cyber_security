# Networks
## Networks type
### Local Area Network (LAN)
A LAN is a type of network that connects devices within a limited geographical area, such as a home, office building, or campus.

LAN Characteristics:
| Characteristic   | Description                                        |
|------------------|----------------------------------------------------|
| Geographic Scope | Covers a small, localized area                     |
| Ownership        | Typically owned by a single person or organization |
| Speed            | High data transfer rates                           |
| Media            | Uses Ethernet cables (wired) or Wi-Fi (wireless)   |

Example: A home Wi-Fi network connecting laptops, smartphones, smart TVs, and printers, allowing file sharing and internet access. 

### Wide Area Network (WAN)
A WAN is a large number of LANs joined together to form a bigger network. The most know WAN is The Internet. Other example of WAN is Intranet or also Airgap Network of large compagnies or government agencies. When dealing with networking, we'll often have a WAN Address and Lan Address.

WAN Characteristics:
| Characteristic   | Description                                          |
|------------------|------------------------------------------------------|
| Geographic Scope | Covers cities, countries, or continents              |
| Ownership        | Often distributed (e.g., internet service providers) |
| Speed            | Slower than LANs due to distance                     |
| Media            | Fiber optics, satellite links, leased lines          |

Example: The Internet

---

Other networks type exists, most of them will only cover a different size of area:

Nanonetwork < Body (BAN) < Personal (PAN) < Local (LAN) < Campus (CAN) < Metropolitan (MAN) < Radio (RAN) < Wide (WAN) 

### Virtual Private Networks (VPN)
There are three main types Virtual Private Networks (VPN), but all three have the same goal of making the user feel as if they were plugged into a different network.
- <h4>Site-To-Site VPN</h4>
Both the client and server are Network Devices, typically either Routers or Firewalls, and share entire network ranges. This is most commonly used to join company networks together over the Internet, allowing multiple locations to communicate over the Internet as if they were local.
- <h4>Remote Access VPN</h4>
A Remote Access VPN enables users to securely connect to a private network from an external location through an encrypted tunnel. When connected, the VPN client creates a virtual network interface and updates the system’s routing table to control how traffic is forwarded. In a Full-Tunnel configuration, all traffic passes through the VPN gateway, while a Split-Tunnel VPN only routes traffic intended for specific internal networks through the tunnel, allowing normal Internet traffic to use the local connection directly.
- <h4>SSL VPN</h4>
This is essentially a VPN that is done within our web browser and is becoming increasingly common as web browsers are becoming capable of doing anything. Typically these will stream applications or entire desktop sessions to your web browser.

| VPN Type              | Connection Type                | Main Purpose                                     | Common Devices                        | Traffic Routing                                              | Typical Use Case                                       |
| --------------------- | ------------------------------ | ------------------------------------------------ | ------------------------------------- | ------------------------------------------------------------ | ------------------------------------------------------ |
| **Site-To-Site VPN**  | Network-to-Network             | Connect multiple networks together securely      | Routers, Firewalls                    | Entire network ranges are routed through the tunnel          | Linking company branches or datacenters                |
| **Remote Access VPN** | Client-to-Network              | Allow remote users to access an internal network | User devices with VPN client software | Full-Tunnel or Split-Tunnel routing                          | Employees working remotely                             |
| **SSL VPN**           | Browser-to-Network/Application | Provide secure access through a web browser      | Web browsers, VPN gateways            | Usually limited to specific applications or desktop sessions | Web-based remote access without dedicated VPN software |

## Network Topologies

Network topology is the arrangement of nodes (devices like computers, routers) and connections (links) in a network, defining how data flows, with two key aspects: Physical Topology (actual cable layout) and Logical Topology (data path)

### Common Topologies
---

### 1. Bus Topology

```
        [PC1]      [PC2]      [PC3]      [Printer]
           |          |          |            |
===========+==========+==========+============+===========
                    Shared Backbone Cable
```
Bus is a simple design that utilizes a single length of cable, also known as the medium, with directly attached LAN stations. All stations share this cable segment. Every station on this segment sees transmissions from every other station on the cable segment; this is known as a broadcast medium. The LAN attachment stations are definite endpoints to the cable segment and are known as bus network termination points.
### 2. Star Topology

```
                 [PC1]
                    |
                    |
[PC2] --------- [Switch] --------- [PC3]
                    |
                    |
               [Printer]
```
In a star topology, all devices are connected to a central hub or switch. This central device is responsible for routing traffic between the devices on the network. Several different types of cables can be used to connect the devices to the hub, including shielded twisted-pair (STP), unshielded twisted-pair (UTP), and fiber-optic cabling. Wireless media can also be used for communications links.
### 3. Ring Topology

```
        [PC1] -----> [PC2]
           ^            |
           |            v
        [PC4] <----- [PC3]

        Message/Data Flow
```
A ring topology is a network topology in which the devices are connected in a circular fashion. This means that data travels around the ring in one direction. Ring topologies are typically implemented using FDDI, SONET, or Token Ring technology. Ring networks are most commonly wired in a ring configuration. This means that each device is connected to the next device in a continuous loop. 
