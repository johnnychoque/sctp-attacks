# SCTP attacks

For the practical implementation of attacks, specialized scripts have been developed using the Python programming language in combination with the **Scapy** library. This technological choice is justified by the flexibility that Scapy offers for low-level network packet construction and manipulation, allowing precise control over SCTP protocol header fields. The implemented scripts have the capability to intercept, analyze, and generate malicious SCTP packets, replicating the necessary parameters to spoof identities and manipulate the state of associations between components that implement SCTP. 

## Proposed testbed platform 

The experiments can be carried out using a testbed platform specifically designed for this purpose, as illustrated in Figure 6. This platform consists of three virtual machines (VMs) deployed on the VirtualBox hypervisor, all interconnected through a Host-only network with subnet address 10.0.2.0/24. 

Each virtual machine runs an Ubuntu Linux-based operating system. VM1, with IP address 10.0.2.50 and MAC address 08:00:27:46:32:df, hosts the SCTP server, which in the O-RAN architecture would be the nearRT-RIC and in 5G acts as AMF. VM2, with IP address 10.0.2.100 and MAC 08:00:27:73:d8:81, implements the SCTP client, acting as an E2 node in O-RAN and gNB in the 5G architecture. Communication between VM1 and VM2 is established through their respective virtual network interfaces enp0s3, which enable the implementation of the E2 or N2 interface, responsible for message exchange between the components of each architecture. 

Finally, VM3, configured with IP 10.0.2.150 and MAC 08:00:27:9a:72:54, represents the attacker node within the test environment. This node hosts the Python-developed scripts that carry out different types of security attacks directed at the system. This component aims to simulate malicious behaviors in the system's control plane, in order to evaluate the robustness and possible vulnerabilities of the O-RAN or 5G architecture against external attacks. 

