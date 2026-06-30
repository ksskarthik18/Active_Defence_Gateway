# **Active Defense Gateway: Proactive Network Camouflage and Deception in Software-Defined Infrastructures**

## **1\. Problem Statement**

The evolution of network security has reached a critical inflection point where traditional reactive measures are no longer sufficient to combat the sophistication of modern adversarial tactics. The fundamental architecture of current enterprise networks suffers from a condition known as Static Topology Persistence. In these environments, once an adversary breaches the initial perimeter defense, they encounter an internal landscape that is predictable, unchanging, and largely transparent.1 Servers maintain fixed IP addresses, critical services listen on standard ports, and the network graph remains consistent over long durations. This structural stability provides a significant asymmetric advantage to the attacker, who can conduct extensive reconnaissance and lateral movement with minimal risk of detection.1

Internal reconnaissance is the foundational phase of the cyber kill chain. Attackers utilize automated scanning tools to map the network, identifying live hosts, open ports, and operating system versions.3 In a static network, the information gathered during this phase remains valid indefinitely. A database server identified at a specific internal IP on port 5432 remains a target for as long as the attacker maintains a foothold.1 This "flat network" assumption, where internal nodes are often granted excessive trust, facilitates lateral movement—the process by which an attacker progressively explores an infected network to find vulnerabilities and escalate privileges toward their ultimate target.2

Current security solutions fail to address the simultaneous requirements for high-speed packet processing and deep architectural intelligence. Legacy firewalls, such as those based on iptables or simple Access Control Lists (ACLs), operate with high performance but lack the contextual awareness to detect the intent or tool signatures of an advanced adversary.1 Conversely, modern service meshes and application-layer proxies provide significant intelligence but introduce millisecond-scale latencies and heavy CPU overhead, making them unsuitable for the core of the network stack where line-rate performance is required.1 Furthermore, standard responses like "dropping" or "blocking" traffic are binary and provide zero intelligence to the defender. In many cases, blocking a probe explicitly informs the attacker that their method was detected, allowing them to refine their techniques.1

There is a critical need for a system that can actively deceive attackers at wire speed, invalidating their reconnaissance data and disrupting the lateral movement process before it can escalate into a full-scale breach. This project proposes an Active Defense Gateway (ADG) that utilizes Software-Defined Networking (SDN) and kernel-resident programs to implement "Cognitive Network Camouflage." By altering the perceived reality of the network based on the intent of the observer, the ADG aims to tilt the scales of cyber warfare back in favor of the defender.1

## **2. SDN Architecture Overview**

Software-Defined Networking (SDN) is a revolutionary paradigm that decouples the network's control logic from the underlying forwarding hardware. This separation enables a logically centralized view of the entire network, allowing for dynamic programmability and rapid adaptation to emerging security threats. Unlike traditional networks, where each switch or router must be configured individually with vendor-specific commands, SDN provides a standardized framework for managing network behavior through software.

![SDN Architecture Diagram](https://raw.githubusercontent.com/ksskarthik18/Active_Defence_Gateway/main/adg_architectureDiagram.png)

### **2.1 The Three-Plane Model**

The SDN architecture is organized into three distinct layers or "planes," each serving a specific role in the lifecycle of a network packet:

* **The Data Plane (Infrastructure Layer):** This layer consists of the physical or virtual forwarding elements, such as OpenFlow-enabled switches. These devices are designed to be as simple as possible, performing high-speed packet matching and forwarding based on rules provided by the controller.10 In this project, the data plane is further enhanced using eBPF (extended Berkeley Packet Filter) and XDP (eXpress Data Path) to achieve near-line-rate filtering at the earliest point in the network stack.16  
* **The Control Plane (Control Layer):** Often described as the "brain" of the network, the control plane resides on a centralized server. The controller maintains the global topology map and decides how traffic should be routed.10 It translates high-level security policies into low-level flow rules and pushes them to the switches via the southbound interface.14  
* **The Application Plane (Management Layer):** This top layer contains the security and management applications that leverage the controller's capabilities. Applications like the Active Defense Gateway reside here, implementing complex logic such as Moving Target Defense (MTD) algorithms, threat intelligence integration, and deception strategies.11

| Feature | Traditional Networking | Software-Defined Networking (SDN) |
| :---- | :---- | :---- |
| **Control Logic** | Distributed (On each device) | Logically Centralized (In a controller) |
| **Programmability** | Limited (Static/Manual) | High (Dynamic/API-driven) |
| **Vendor Dependency** | High (Proprietary hardware) | Low (Open standards like OpenFlow) |
| **Security Response** | Reactive/Manual | Proactive/Automated |
| **Visibility** | Fragmented/Local | Comprehensive/Global |

9

### **2.2 Communication Interfaces**

The interaction between these planes is facilitated by well-defined Application Programming Interfaces (APIs). The **Southbound Interface (SBI)** is the most critical for data plane management. The OpenFlow protocol is the industry standard for this interface, enabling the controller to program the flow tables of the switches.14 Each flow entry in a switch's table contains match fields (e.g., source IP, destination port), counters, and actions (e.g., forward, drop, modify header).20

The **Northbound Interface (NBI)** provides a way for security applications to communicate their requirements to the controller. These are typically implemented as RESTful APIs or specialized function calls within the controller framework, such as the Ryu controller's internal API.19 By using the NBI, the Active Defense Gateway can automatically update network policies in response to detected reconnaissance attempts or authenticated user requests.22

### **2.3 Programmability and Orchestration**

The true power of SDN lies in its ability to orchestrate the network as a single entity. When a switch receives a packet that does not match any existing rule in its flow table—a "table-miss"—it generates a PACKET\_IN message and sends it to the controller.12 The controller analyzes the packet and can then issue a FLOW\_MOD message to install a new rule on the switch, ensuring that subsequent packets in the same flow are handled at the hardware level without further controller intervention.12 This project exploits this reactive flow installation to implement dynamic IP shuffling and stealthy redirection to honeypots.7

## **3\. Security Threat Model**

Designing an effective Active Defense Gateway requires a deep understanding of the vulnerabilities inherent in both traditional and programmable network architectures. This threat model applies the STRIDE methodology to evaluate risks across the SDN stack, focusing on reconnaissance, denial of service, and lateral movement.29

### **3.1 Network Reconnaissance and Asset Mapping**

The initial phase of an attack involves gathering intelligence about the target environment. In a static SDN setup, an attacker can exploit the deterministic nature of the network to build a comprehensive map.4

* **Host and Service Discovery:** Using ICMP echo requests or TCP SYN probes, attackers identify live hosts and open ports.32  
* **Tool Fingerprinting:** Sophisticated scanners analyze the nuances of the TCP/IP stack implementation. By observing default Window Sizes, Maximum Segment Size (MSS) advertisements, and the order of TCP Options, an attacker can identify the operating system or the specific version of a network tool.35  
* **Controller Fingerprinting:** Attackers can even identify which SDN controller is managing the network (e.g., Ryu vs. OpenDaylight) by measuring the "flow setup latency"—the time difference between a table-miss packet and the subsequent response from the switch.38

### **3.2 Saturation and Denial of Service (DoS)**

SDN's centralized architecture introduces specific vulnerabilities related to the control-data plane interaction.

* **Volumetric Flooding:** Traditional attacks like SYN floods or UDP floods aim to exhaust link bandwidth or switch processing power.5  
* **Flow Table Overload (LOFT):** Attackers generate a massive number of unique flows (e.g., random source IPs or ports). Each unique flow triggers a PACKET\_IN event, potentially overwhelming the control channel and filling the switch's Ternary Content-Addressable Memory (TCAM), which is limited and expensive.25  
* **Low-Rate DoS (LDoS):** These attacks send traffic in periodic bursts designed to degrade network performance without triggering volumetric detection thresholds. They can be particularly effective at causing congestion on specific links identified through traceroute profiling.42

### **3.3 Lateral Movement and Post-Compromise Activity**

Once a single host is compromised, the attacker begins to move "east-west" across the network.2

* **Credential Acquisition:** Attackers use tools like Mimikatz to extract password hashes from memory or exploit administrative shares (SMB) to deploy payloads.34  
* **Internal Pivoting:** The compromised host becomes a launchpad for further internal scanning. Because internal traffic is often less scrutinized than perimeter traffic, attackers can blend in with legitimate administrative activity.2  
* **Data Exfiltration:** After reaching a high-value target, such as a database server, the attacker attempts to move sensitive data out of the network.34

| Threat Category | SDN Plane | Mechanism | Security Impact |
| :---- | :---- | :---- | :---- |
| **Spoofing** | Data | IP/MAC Forgery | Man-in-the-Middle (MitM) 23 |
| **Tampering** | Control | Flow Rule Modification | Traffic Hijacking 29 |
| **Information Disclosure** | Application | Topology Discovery | Intelligence for Exploitation 21 |
| **Denial of Service** | Control | PACKET\_IN Flooding | Controller/Network Failure 25 |
| **Elevation of Privilege** | Management | Compromised Controller App | Full Network Control 22 |

21

## **4\. Proposed Solution**

The Active Defense Gateway (ADG) is an implementable security framework designed to neutralize the threats described above by fundamentally changing the network's behavior from passive and static to active and polymorphic.1 The solution integrates the high-performance filtering capabilities of eBPF/XDP with the centralized orchestration of the Ryu SDN controller.1

### **4.1 Concept: Cognitive Network Camouflage**

The core innovation of the ADG is the concept of "Cognitive Network Camouflage." Instead of a simple binary firewall that blocks unauthorized traffic, the ADG creates a deceptive network landscape that adapts based on the identity and intent of the observer.1

1. **To an Authorized User:** The network appears transparent and performant. Authenticated users are granted access to the "Real Topology" and can communicate with production services with minimal latency.1  
2. **To an Unauthenticated/Malicious Observer:** The network appears as a vast, hallucinatory landscape of decoy hosts and service tarpits. Probes and scanning attempts are stealthily redirected to a honeypot environment where the attacker's actions can be studied.1

### **4.2 The Unified Security Shim**

The ADG is architected as a high-performance security shim that sits at the core of the network stack. It operates across two primary layers:

* **Layer 1: The Iron Gate (Data Plane \- eBPF/XDP):** Residing at the Network Interface Card (NIC) driver level, this component performs sub-microsecond packet inspection. It uses in-kernel fingerprinting to identify known scanning tools and validates cryptographic signatures for authorized access.1 Volumetric attacks are dropped here, long before they can impact the operating system or the SDN controller.5  
* **Layer 2: The Hive Mind (Control Plane \- Ryu Controller):** This component manages the global security state. It orchestrates the Moving Target Defense strategy by periodically shuffling virtual IP addresses and updating the eBPF maps with the latest threat intelligence and authorized IP lists.1

### **4.3 Moving Target Defense (MTD) and Deception**

The ADG implements MTD by continuously shifting the system’s attack surface. By changing the IP addresses and port mappings of internal hosts, the system ensures that any reconnaissance data gathered by an attacker becomes invalid within a short time frame.31 This uncertainty forces the attacker to either restart their reconnaissance, increasing their chances of being caught, or to attack blindly, which is significantly more difficult in a dynamic environment.52

To enhance the deception, the ADG does not simply fail to respond to probes. Instead, it provides realistic but fabricated responses. When an attacker scans a port that is "closed" on a real server, the ADG can redirect that probe to a honeypot that presents a vulnerable-looking service, enticing the attacker to engage with a decoy rather than the real asset.6

## **5\. Algorithms and Techniques Used**

The effectiveness of the Active Defense Gateway is predicated on the application of advanced networking and security algorithms. These techniques allow the system to operate at high speed while maintaining deep contextual awareness.

### **5.1 In-Kernel Traffic Sketching and Fingerprinting**

To detect threats without the overhead of userspace processing, the ADG utilizes traffic sketching and fingerprinting directly within the eBPF virtual machine.16

* **TCP Option Parsing:** The eBPF program parses the initial SYN packet of every incoming TCP connection. It specifically extracts the TCP Option Kind numbers, their lengths, and values.37 For instance, it looks for the Maximum Segment Size (MSS), Window Scale factor, and SACK-Permitted options.35  
* **Signature Comparison:** Automated tools like Nmap or ZMap often use a specific, non-standard order of options or unique default Window Sizes (e.g., 1024 or 2048).35 The eBPF program compares the packet's fingerprint against a known-malicious tool database.  
* **Sketch-based Detection:** To detect volumetric anomalies without storing every flow, the system uses algorithms like the "BACON Sketch" or Bloom Filters in kernel space to track packet frequencies and identify potential DDoS sources.6

### **5.2 Random Host Mutation (RHM)**

The ADG employs a sophisticated IP shuffling algorithm to invalidate reconnaissance data.7

* **Address Translation:** Each legitimate host ![][image1] is assigned a static Real IP (![][image2]) and a dynamic Virtual IP (![][image3]). All communications within the SDN network use ![][image4].28  
* **Mapping Updates:** The Ryu controller periodically (e.g., every 30 seconds) generates a new set of ![][image3] mappings using a pseudo-random number generator.  
* **Transparency:** When host A (![][image5]) sends a packet to host B (![][image6]), the edge switch, programmed by Ryu, rewrites the destination to ![][image7] and the source to ![][image8] before delivery. This ensures that the end hosts are unaware of the mutation, maintaining application transparency.7  
* **Entropy Management:** The system maximizes the entropy of the ![][image3] space to ensure that the probability of an attacker correctly guessing a valid target IP is minimized.7

### **5.3 Single Packet Authorization (SPA) and SPE**

To enforce a Zero-Trust architecture at the network layer, the ADG uses SPA for initial host authentication.1

* **Secure Packet Envelope (SPE):** A legitimate client wishing to access the network must first send a single, encrypted UDP packet. This "knock" packet contains a cryptographically signed payload including a timestamp, a device identifier, and a random nonce.1  
* **Pre-Stack Validation:** The eBPF/XDP program intercepts this UDP packet. It validates the signature and ensures that the packet is not a replay (e.g., by checking ![][image9]).1  
* **Dynamic Access Control:** Upon successful validation, the client's source IP address is added to an eBPF "Allowlist" map for a limited duration. Only packets from IPs in the allowlist are permitted to reach the real application ports; all others are redirected to the honeypot.1

### **5.4 Stealthy Redirection and Session Synchronization**

When a probe is identified as malicious, the ADG performs a redirection that is invisible to the attacker.27

* **Destination NAT:** The switch rewrites the destination IP and MAC addresses to point to a honeypot node.26  
* **Handshake Maintenance:** If the redirection occurs during a TCP handshake, the controller or a specialized eBPF program ensures that the sequence and acknowledgment numbers are adjusted to maintain session continuity with the honeypot, preventing the attacker from realizing they have been diverted.27

## **6\. Tools, Software, and Technologies**

The implementation of the ADG requires a robust and well-documented technology stack. The project leverages open-source tools that are standard in both academic research and industrial security deployments.

### **6.1 Network Emulation and Controller**

* **Mininet:** This is the primary environment for creating the virtual network topology. Mininet allows for the simulation of multiple hosts and OpenFlow switches on a single Linux kernel.63 It is essential for testing the ADG's behavior in complex, multi-switch environments.65  
* **Ryu SDN Controller:** Written in Python, Ryu provides a flexible framework for developing custom SDN applications.12 It supports OpenFlow version 1.3, which is required for advanced features like group tables and metadata matching.19  
* **Open vSwitch (OVS):** This is the industry-standard virtual switch that will serve as the data plane forwarding element. OVS implements the OpenFlow protocol and can be controlled dynamically by Ryu.15

### **6.2 High-Performance Data Plane**

* **eBPF and XDP:** The extended Berkeley Packet Filter is used to write sandboxed programs that run within the Linux kernel.69 XDP provides the hook point at the NIC driver level, allowing for high-speed packet drops and modifications before the packets reach the traditional networking stack.17  
* **Rust and Aya:** Rust is chosen for the security shim due to its strong memory safety guarantees.1 Aya is a Rust-based eBPF library that simplifies the process of loading eBPF programs and interacting with eBPF maps from userspace.1

### **6.3 Security Analysis and Adversary Simulation**

* **Scapy:** A powerful Python library for packet manipulation. It will be used to craft the custom "knock" packets for SPA and to simulate adversarial traffic such as SYN floods or spoofed reconnaissance probes.3  
* **Nmap:** The primary tool used to test the ADG's camouflage. Students will run Nmap scans against the network to evaluate if the real hosts remain hidden and if the decoys successfully distract the scanner.3  
* **Wireshark:** Essential for debugging the network behavior. Students will use Wireshark to inspect OpenFlow messages (e.g., PACKET\_IN, FLOW\_MOD) and verify that packet headers are being rewritten correctly during the IP shuffling and redirection phases.24

| Technology Category | Selected Tool | Key Role in Project |
| :---- | :---- | :---- |
| **Network Emulator** | Mininet | Virtual testbed for nodes/switches 63 |
| **SDN Controller** | Ryu | Management and MTD orchestration 12 |
| **Data Plane Hook** | XDP/eBPF | Line-rate packet filtering/fingerprinting 17 |
| **Programming Language** | Rust (Shim) / Python (App) | High-speed safety and rapid prototyping 1 |
| **Attack Simulation** | Scapy / Nmap | Validating defense effectiveness 32 |
| **State Store** | Redis | Sharing threat intelligence between components 1 |

1

## **7\. System Architecture Diagram (Explain in Words)**

The Active Defense Gateway architecture is a hierarchical system designed to process traffic through a multi-stage validation pipeline. The architecture can be conceptualized in four distinct layers, starting from the physical interface up to the high-level policy engine.

### **7.1 Layer 1: The NIC Driver Hook (The Iron Gate)**

When a packet arrives at the network interface of an ADG-enabled node, it is immediately intercepted by the **XDP Program**. This program operates in "Native" or "Generic" mode, sitting directly in the receive path of the driver.17

1. **Header Extraction:** The XDP program extracts the Layer 2 (MAC), Layer 3 (IP), and Layer 4 (TCP/UDP) headers.18  
2. **Allowlist Lookup:** It checks a high-speed eBPF **Hash Map** containing the IP addresses of currently authorized clients.  
3. **Action Determination:**  
   * If the source IP is in the allowlist, the packet is marked with XDP\_PASS and sent up to the Linux kernel.17  
   * If the packet is a UDP packet on the specific SPA port, it is passed to the SPE validator.1  
   * Otherwise, the packet is flagged for fingerprinting or dropped if it matches a known volumetric attack signature.5

### **7.2 Layer 2: The Control Plane Interface (The Hive Mind)**

The **Aya Userspace Agent** acts as the bridge between the kernel-resident programs and the SDN controller.

1. **Map Management:** The agent periodically polls the eBPF maps for traffic statistics (e.g., how many packets were dropped from a specific source).1  
2. **Intel Propagation:** If the XDP program detects a reconnaissance tool fingerprint, it sends the source IP and tool signature to the agent via a **Perf Buffer** or **Ring Buffer**.69  
3. **Policy Synchronization:** The agent receives updated vIP-to-rIP mappings from the Ryu controller and writes them into the kernel-space eBPF maps to ensure the data plane remains synchronized with the global MTD state.1

### **7.3 Layer 3: The SDN Controller (The Strategic Orchestrator)**

The **Ryu Controller** maintains the global network view. It is responsible for the heavy-lifting logic that would be too complex for the kernel.

1. **Topology Discovery:** Using LLDP packets, Ryu discovers all switches and links, maintaining a real-time graph of the network.75  
2. **MTD Engine:** Every 30 seconds, the MTD engine selects new virtual IPs from a pool of unused addresses. It generates the necessary FLOW\_MOD messages to update the NAT rules on the OpenFlow switches.7  
3. **Redirection Logic:** When the Hive Mind reports a malicious source, Ryu installs high-priority flow rules that rewrite the destination of all packets from that source to the IP of a honeypot node.26

### **7.4 Layer 4: The Deception Tarpit (The Forensic Mirror)**

The **Honeypot Nodes** are isolated virtual machines or containers running clones of production services.

1. **Engagement:** When a malicious flow is redirected here, the honeypot provides a realistic environment for the attacker.27  
2. **Logging and Forensics:** Every command typed and every packet sent by the attacker is logged. This data is streamed to a dedicated forensic server for analysis, providing the organization with high-fidelity threat intelligence.1

## **8\. Implementation Plan (Step-by-Step)**

The project is structured into a 10-step plan:

**Step 1: Lab Initialization and Baseline Connectivity**

The first task is to set up the development environment. This includes installing Ubuntu 22.04 LTS, Mininet, and the Ryu controller.63 Students should implement a basic layer-2 learning switch application to verify that the virtual switches can communicate with the controller and that hosts can ping each other.24

### **Step 2: Custom Topology Design**

Design a network graph in Mininet that represents a small corporate subnet. The topology should include:

* A **Core Switch** connected to the controller.  
* Two **Access Switches**, each with 2 legitimate hosts.  
* A dedicated **Deception Switch** housing 2 honeypot nodes.  
* An **Attacker Host** placed at one of the access switches to simulate an internal breach.60

### **Step 3: eBPF/XDP Skeleton Development**

Write the basic eBPF program in C or Rust (using Aya). The program should initially perform simple packet counting to ensure the XDP hook is correctly attached to the Mininet virtual interfaces (e.g., s1-eth1).17 Use bpftool to verify that the program is loaded and the maps are accessible.17

### **Step 4: TCP Header Parsing and Fingerprinting**

Enhance the eBPF program to parse the TCP header. Focus on extracting the **Window Size** and the **MSS** option from the first packet of a connection.18 Implement a basic comparison logic that flags packets with a Window Size of 1024 or 2048, which are common Nmap defaults.1

### **Step 5: IP Shuffling (RHM) Orchestration**

In the Ryu controller, develop the Random Host Mutation application. Implement a timer-based loop that periodically generates new virtual IP mappings.28 Use the OFPFlowMod class to push rules to the OVS switches that perform the NAT translation between virtual and real IPs.7

### **Step 6: Single Packet Authorization (SPA) Implementation**

Develop the client-side Scapy script to generate the SPE envelope.49 On the gateway side, implement the eBPF logic to decrypt and validate the "knock" packet. If valid, the source IP should be added to a "trusted\_ips" eBPF map.1

### **Step 7: Stealthy Honeypot Redirection**

Configure the honeypot nodes using a tool like Dionaea or a simple Python-based web server that mimics a production site.27 Implement the Ryu logic that, upon receiving a fingerprinting alert, installs a rule to rewrite the destination MAC and IP to the honeypot's addresses.26

### **Step 8: Volumetric Attack Mitigation**

Simulate a SYN flood using Scapy.32 Implement a "Circuit Breaker" mechanism in the XDP program: if the number of SYN packets from a single source exceeds a threshold per second, immediately drop all subsequent traffic from that IP using XDP\_DROP.1

### **Step 9: Integrated Security Testing**

Conduct a full-scale simulation of a cyber attack. The "Attacker Host" should perform:

1. An Nmap scan to discover hosts (should only see decoys).  
2. A SYN flood against a decoy (should be mitigated by XDP).  
3. An attempt to access a real service without SPA (should be redirected to the honeypot).3

### **Step 10: Forensic Analysis and Reporting**

Analyze the logs generated by the honeypot and the eBPF program. Verify that the system successfully captured the attacker's tools and intentions.6 Use Wireshark to create visual proof of the IP shuffling and redirection for the final project demo.24

## **9\. Evaluation Metrics**

The performance and efficacy of the Active Defense Gateway must be measured using objective, quantifiable metrics. These metrics demonstrate the trade-offs between enhanced security and network overhead.

### **9.1 Data Plane Performance Metrics**

| Metric | Definition | Measurement Tool | Target |
| :---- | :---- | :---- | :---- |
| **Packet Processing Latency** | Time taken for a packet to pass through the XDP hook.50 | eBPF profiling | \< 1 microsecond- |
| **Setup Latency** | Time from the first packet arrival to rule installation.23 | Cbench / Wireshark | \< 10 ms |
| **Maximum Throughput** | Maximum number of packets processed per second per CPU core.16 | Iperf3 / Pktgen | \> 15 Mpps |
| **Jitter** | Variation in packet arrival time due to MTD processing.66 | Iperf3 | \< 1 ms |

### **9.2 Security Efficacy Metrics**

* **Reconnaissance Disruption Rate:** The ratio of incorrect hosts/services identified by an attacker's Nmap scan to the total number of real hosts.53 A successful ADG should achieve a disruption rate \> 90%.  
* **Detection Precision and Recall:** Precision measures the percentage of correctly identified attack tools, while recall measures the percentage of actual attack tools detected by the fingerprinting engine.4  
* **DDoS Mitigation Efficacy:** The percentage of legitimate traffic that remains successful during an active volumetric attack.5  
* **Deception Dwell Time:** The the average time an attacker spends interacting with the honeypot before attempting to pivot back to the real network.6

## **10\. Expected Results**

Upon completion, the project team will have produced a functional prototype of a next-generation network gateway. The results will demonstrate three key security properties.

### **10.1 Obliviousness to Reconnaissance**

Testing with the "Attacker Host" will show that the network is no longer a static map. Because of IP shuffling, the IP addresses discovered in one scan will become unresponsive in the next. To the attacker, the network will appear to be populated by hundreds of "phantom" hosts that respond to pings but do not exist in reality, effectively drowning the real signals in a sea of deceptive noise.7

### **10.2 Resilience to Volumetric Attacks**

The demo will show that while a standard SDN controller would be overwhelmed by a SYN flood (due to the PACKET\_IN bottleneck), the ADG-enabled node remains fully operational. The XDP program will drop malicious packets at the driver level, maintaining low CPU utilization on the controller and ensuring that legitimate hosts can still communicate with negligible latency increases.5

### **10.3 High-Fidelity Threat Intelligence**

The system will generate detailed logs of adversarial behavior. Unlike traditional firewalls that only log a "Drop" event, the ADG will show exactly what an attacker tried to do once they were redirected to the honeypot. This allows the team to demonstrate a transition from "Defensive Security" to "Active Engagement," where the network itself acts as a sensor to inform future defense strategies.1

## **11\. Limitations**

While the ADG offers significant advantages, students should be aware of technical constraints that may impact real-world deployment:

* **TCAM Limitations:** Physical SDN switches have limited space for flow rules. A very high frequency of IP shuffling or a massive number of redirection rules could saturate the switch's flow table.25  
* **Kernel Compatibility:** eBPF and XDP features vary across Linux kernel versions. Advanced features like "Tail Calls" or certain helper functions may not be available on older kernels.69  
* **Session Persistence:** Highly aggressive IP shuffling (e.g., every 5 seconds) may disrupt long-lived TCP sessions (like large file transfers or SSH) if the session synchronization logic is not perfectly implemented.7  
* **eBPF Verifier Restrictions:** The kernel's verifier is very strict. It prohibits infinite loops and limits the complexity of programs to ensure system stability, which can make implementing complex cryptographic validation inside XDP difficult.69

## **12\. Future Enhancements**

The Active Defense Gateway is a foundation that can be extended with several advanced research topics:

* **AI-Driven Fingerprinting:** Instead of static header checks, integrate a lightweight Machine Learning model (e.g., a Random Forest or Bi-LSTM) running inside the kernel to detect zero-day attack patterns.5  
* **Hardware Offloading:** Port the XDP program to run directly on a SmartNIC or DPU (Data Processing Unit). This would allow the ADG to process 100Gbps of traffic with zero CPU utilization on the host.1  
* **Blockchain-Based State Sync:** Use a private blockchain to synchronize the authorized IP allowlists and MTD mappings across multiple distributed ADG nodes, ensuring that there is no single point of failure in the management of security state.86  
* **Application-Layer Hallucination:** Extend the deception into Layer 7 by returning "fake" JSON responses for specific API endpoints or providing fabricated database results to redirected attackers.1

## **13\. References**

The theoretical and practical foundations of this project are based on the following seminal works and modern research papers:

1. **SDN Fundamentals:** McKeown, N., et al. (2008). "OpenFlow: Enabling Innovation in Campus Networks." (Foundational paper on the OpenFlow protocol).  
2. **eBPF and XDP:** Vieira, M., et al. (2020). "Fast Packet Processing with eBPF and XDP: Concepts, Code, Tools, and Techniques.".1  
3. **Moving Target Defense:** Jajodia, S., et al. (2011). "Moving Target Defense: Creating Asymmetric Uncertainty for Cyber Threats.".1  
4. **IP Mutation:** Dunlop, M., et al. (2011). "MT6D: A Moving Target IPv6 Defense.".62  
5. **DDoS in SDN:** Karthika, P. (2023). "Simulation of SDN in Mininet and Detection of DDoS Attack.".10  
6. **Deception Systems:** Han, X., et al. (2018). "Learning to Deceive with Deception-Based Moving Target Defense.".6  
7. **Single Packet Authorization:** Rash, M. (2006). "Single Packet Authorization with fwknop.".49  
8. **Kernel-level Security:** Corbet, J. (2019). "BPF: The universal in-kernel virtual machine.".1  
9. **Controller Benchmarking:** Ontiveros, C. (2019). "A Software Defined Network Implementation Using Mininet and Ryu.".89  
10. **Threat Modeling:** Microsoft Corporation (2024). "The STRIDE Threat Model.".30

#### **Works cited**

1. FYP.docx  
2. What is a Lateral Movement? Prevention and Detection Methods \- Fortinet, accessed February 6, 2026, [https://www.fortinet.com/resources/cyberglossary/lateral-movement](https://www.fortinet.com/resources/cyberglossary/lateral-movement)  
3. Nmap & Scapy Lab Documentation \- by Mhlope Nkosikhona \- Medium, accessed February 6, 2026, [https://medium.com/@mhlopenkosikhona/nmap-scapy-lab-documentation-ef9232da8bcf](https://medium.com/@mhlopenkosikhona/nmap-scapy-lab-documentation-ef9232da8bcf)  
4. Exploring Honeypot as a Deception and Trigger Mechanism for Real-Time Attack Detection in Software-Defined Networking, accessed February 6, 2026, [https://journal.uob.edu.bh/bitstreams/d0b30f3f-8f61-4f6b-bf34-26c9200947b9/download](https://journal.uob.edu.bh/bitstreams/d0b30f3f-8f61-4f6b-bf34-26c9200947b9/download)  
5. SmartX Intelligent Sec: A Security Framework Based on Machine Learning and eBPF/XDP, accessed February 6, 2026, [https://arxiv.org/html/2410.20244v1](https://arxiv.org/html/2410.20244v1)  
6. SDN-based hybrid honeypot for attack capture \- ResearchGate, accessed February 6, 2026, [https://www.researchgate.net/publication/345445201\_SDN-based\_hybrid\_honeypot\_for\_attack\_capture](https://www.researchgate.net/publication/345445201_SDN-based_hybrid_honeypot_for_attack_capture)  
7. DDoS Defense using MTD and SDN \- University of Twente ..., accessed February 6, 2026, [https://research.utwente.nl/files/29782234/2018\_NOMS\_MTD\_sub.pdf?utm\_source=consensus](https://research.utwente.nl/files/29782234/2018_NOMS_MTD_sub.pdf?utm_source=consensus)  
8. A Survey of Network Requirements for Enabling Effective Cyber Deception \- arXiv, accessed February 6, 2026, [https://arxiv.org/html/2309.00184v3](https://arxiv.org/html/2309.00184v3)  
9. Comprehensive Analysis of DDoS Anomaly Detection ... \- IEEE Xplore, accessed February 6, 2026, [https://ieeexplore.ieee.org/iel8/6287639/10820123/10857272.pdf](https://ieeexplore.ieee.org/iel8/6287639/10820123/10857272.pdf)  
10. Simulation of SDN in mininet and detection of DDoS attack using machine learning \- Bulletin of Electrical Engineering and Informatics, accessed February 6, 2026, [https://beei.org/index.php/EEI/article/download/5232/3249](https://beei.org/index.php/EEI/article/download/5232/3249)  
11. SDN as a defence mechanism: a comprehensive survey \- ResearchGate, accessed February 6, 2026, [https://www.researchgate.net/publication/374506966\_SDN\_as\_a\_defence\_mechanism\_a\_comprehensive\_survey](https://www.researchgate.net/publication/374506966_SDN_as_a_defence_mechanism_a_comprehensive_survey)  
12. Performance Evaluation of Ryu Controller in Software Defined Networks, accessed February 6, 2026, [https://iasj.rdd.edu.iq/journals/uploads/2025/01/11/6a9d994e773b93f8c4ca5f71f7fb2093.pdf](https://iasj.rdd.edu.iq/journals/uploads/2025/01/11/6a9d994e773b93f8c4ca5f71f7fb2093.pdf)  
13. Software-Defined Networking (SDN) for Enhanced Network Security \- gas publishers, accessed February 6, 2026, [https://gaspublishers.com/wp-content/uploads/2025/07/Software-Defined-Networking-SDN-for-Enhanced-Network-Security.pdf](https://gaspublishers.com/wp-content/uploads/2025/07/Software-Defined-Networking-SDN-for-Enhanced-Network-Security.pdf)  
14. A Survey on P4 Challenges in Software Defined Networks: P4 Programming \- IEEE Xplore, accessed February 6, 2026, [https://ieeexplore.ieee.org/iel7/6287639/10005208/10130445.pdf](https://ieeexplore.ieee.org/iel7/6287639/10005208/10130445.pdf)  
15. On the Security of SDN: A Completed Secure and Scalable Framework Using the Software-Defined Perimeter \- IEEE Xplore, accessed February 6, 2026, [https://ieeexplore.ieee.org/iel7/6287639/6514899/08826550.pdf](https://ieeexplore.ieee.org/iel7/6287639/6514899/08826550.pdf)  
16. Fast In-kernel Traffic Sketching in eBPF \- UCL Discovery, accessed February 6, 2026, [https://discovery.ucl.ac.uk/10188362/1/eBPF\_sketch\_paper\_\_for\_RPS\_.pdf](https://discovery.ucl.ac.uk/10188362/1/eBPF_sketch_paper__for_RPS_.pdf)  
17. eBPF XDP: The Basics and a Quick Tutorial | Tigera \- Creator of Calico, accessed February 6, 2026, [https://www.tigera.io/learn/guides/ebpf/ebpf-xdp/](https://www.tigera.io/learn/guides/ebpf/ebpf-xdp/)  
18. Hands-On with XDP: eBPF for High-Performance Networking | iximiuz Labs, accessed February 6, 2026, [https://labs.iximiuz.com/tutorials/ebpf-xdp-fundamentals-6342d24e](https://labs.iximiuz.com/tutorials/ebpf-xdp-fundamentals-6342d24e)  
19. OpenFlow and Ryu in SDN Explained | PDF | Computer Network \- Scribd, accessed February 6, 2026, [https://www.scribd.com/document/854850499/openflow-and-ryu-controller-overview](https://www.scribd.com/document/854850499/openflow-and-ryu-controller-overview)  
20. OpenFlow \- the Software-defined Networking Protocol \- Penzzer, accessed February 6, 2026, [https://www.we-fuzz.io/blog/openflow---the-software-defined-networking-protocol](https://www.we-fuzz.io/blog/openflow---the-software-defined-networking-protocol)  
21. A review of security, threats and mitigation approaches for SDN architecture \- ResearchGate, accessed February 6, 2026, [https://www.researchgate.net/publication/332034463\_A\_review\_of\_security\_threats\_and\_mitigation\_approaches\_for\_SDN\_architecture](https://www.researchgate.net/publication/332034463_A_review_of_security_threats_and_mitigation_approaches_for_SDN_architecture)  
22. Software-Defined Networking (SDN) for Scalable Security | Key Concepts Every CISSP Needs to Master, accessed February 6, 2026, [https://destcert.com/resources/software-defined-networking-sdn/](https://destcert.com/resources/software-defined-networking-sdn/)  
23. An Overview of SDN Issues—A Case Study and Performance Evaluation of a Secure OpenFlow Protocol Implementation \- MDPI, accessed February 6, 2026, [https://www.mdpi.com/2079-9292/14/16/3244](https://www.mdpi.com/2079-9292/14/16/3244)  
24. Exercises \- Ryu and OpenFlow \- HackMD, accessed February 6, 2026, [https://hackmd.io/@raphaelvrosa/rJEq6q-fI](https://hackmd.io/@raphaelvrosa/rJEq6q-fI)  
25. FloRa: Flow Table Low-Rate Overflow Reconnaissance and Detection in SDN \- arXiv, accessed February 6, 2026, [https://arxiv.org/pdf/2410.19832](https://arxiv.org/pdf/2410.19832)  
26. OpenFlow v1.3 Messages and Structures — Ryu 4.34 documentation, accessed February 6, 2026, [https://ryu.readthedocs.io/en/latest/ofproto\_v1\_3\_ref.html](https://ryu.readthedocs.io/en/latest/ofproto_v1_3_ref.html)  
27. Cyber Deception Reactive: TCP Stealth Redirection to On-Demand Honeypots \- arXiv, accessed February 6, 2026, [https://arxiv.org/html/2402.09191v2](https://arxiv.org/html/2402.09191v2)  
28. Towards Enhancing the Endpoint Security using Moving Target Defense (Shuffle-based Approach) in Software Defined Networking, accessed February 6, 2026, [https://pdfs.semanticscholar.org/c0dd/d0791e0cf797f824ab29faf3cf4d92d780c2.pdf](https://pdfs.semanticscholar.org/c0dd/d0791e0cf797f824ab29faf3cf4d92d780c2.pdf)  
29. A Survey of the Main Security Issues and Solutions for the SDN Architecture \- IEEE Xplore, accessed February 6, 2026, [https://ieeexplore.ieee.org/iel7/6287639/6514899/09527257.pdf](https://ieeexplore.ieee.org/iel7/6287639/6514899/09527257.pdf)  
30. Security Evaluation in Software-Defined Networks \- arXiv, accessed February 6, 2026, [https://arxiv.org/html/2408.11486v1](https://arxiv.org/html/2408.11486v1)  
31. A Survey on Moving Target Defense for Networks: A Practical View \- MDPI, accessed February 6, 2026, [https://www.mdpi.com/2079-9292/11/18/2886](https://www.mdpi.com/2079-9292/11/18/2886)  
32. Nmap And Scapy Lab. Introduction | by Robert Dzogah | Jan, 2026 \- Medium, accessed February 6, 2026, [https://medium.com/@dzogahr/nmap-and-scapy-lab-05f16bba5632](https://medium.com/@dzogahr/nmap-and-scapy-lab-05f16bba5632)  
33. ‍♀️ Nmap & Scapy on Kali: A Beginner-Friendly Packet Adventure \- DEV Community, accessed February 6, 2026, [https://dev.to/ldwit/nmap-scapy-on-kali-a-beginner-friendly-packet-adventure-4dio](https://dev.to/ldwit/nmap-scapy-on-kali-a-beginner-friendly-packet-adventure-4dio)  
34. What Is Lateral Movement? Detect and Prevent It | Exabeam, accessed February 6, 2026, [https://www.exabeam.com/explainers/what-are-ttps/what-is-lateral-movement-and-how-to-detect-and-prevent-it/](https://www.exabeam.com/explainers/what-are-ttps/what-is-lateral-movement-and-how-to-detect-and-prevent-it/)  
35. Description of Windows TCP features \- Windows Server \- Microsoft Learn, accessed February 6, 2026, [https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/description-tcp-features](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/description-tcp-features)  
36. Network Analysis: TCP Window Size, accessed February 6, 2026, [https://www.networkcomputing.com/network-management/network-analysis-tcp-window-size](https://www.networkcomputing.com/network-management/network-analysis-tcp-window-size)  
37. TCP Header : TCP Options ⋆ Window Scaling | MSS | ACK \- IPCisco, accessed February 6, 2026, [https://ipcisco.com/lesson/tcp-header-tcp-options/](https://ipcisco.com/lesson/tcp-header-tcp-options/)  
38. Fingerprinting OpenFlow controllers: The first step to attack an SDN control plane \- arXiv, accessed February 6, 2026, [https://arxiv.org/pdf/1611.02370](https://arxiv.org/pdf/1611.02370)  
39. cipher0411/OpenFlow-SDN-with-Ryu-Controller-Integrated-with-Snort.-Using-GNS3, accessed February 6, 2026, [https://github.com/cipher0411/OpenFlow-SDN-with-Ryu-Controller-Integrated-with-Snort.-Using-GNS3](https://github.com/cipher0411/OpenFlow-SDN-with-Ryu-Controller-Integrated-with-Snort.-Using-GNS3)  
40. Flow Table Security in SDN: Adversarial Reconnaissance and Intelligent Attacks \- Quinn Burke, accessed February 6, 2026, [https://www.quinnburke.net/papers/2021\_ton\_\_flow\_reconn.pdf](https://www.quinnburke.net/papers/2021_ton__flow_reconn.pdf)  
41. Flow Table Saturation Attack against Dynamic Timeout Mechanisms in SDN \- MDPI, accessed February 6, 2026, [https://www.mdpi.com/2076-3417/13/12/7210](https://www.mdpi.com/2076-3417/13/12/7210)  
42. Mitigating Crossfire Attacks Using SDN-Based Moving Target Defense \- FIU, accessed February 6, 2026, [https://acyd.fiu.edu/wp-content/uploads/Mitigating-Crossfire-Attacks-using-SDN-based-Moving-Target-Defense.pdf](https://acyd.fiu.edu/wp-content/uploads/Mitigating-Crossfire-Attacks-using-SDN-based-Moving-Target-Defense.pdf)  
43. Kernel-level LDoS attack detection in SDN networks: an eBPF/XDP framework with dynamic thresholding | Request PDF \- ResearchGate, accessed February 6, 2026, [https://www.researchgate.net/publication/398702067\_Kernel-Level\_LDoS\_Attack\_Detection\_in\_SDN\_Networks\_An\_eBPFXDP\_Framework\_with\_Dynamic\_Thresholding](https://www.researchgate.net/publication/398702067_Kernel-Level_LDoS_Attack_Detection_in_SDN_Networks_An_eBPFXDP_Framework_with_Dynamic_Thresholding)  
44. Lateral Movement Update: 3 Ways to Stop the Sideways Steal of Data Across Your Network, accessed February 6, 2026, [https://www.tanium.com/blog/lateral-movement-update-3-ways-to-stop-the-sideways-steal-of-data-across-your-network/](https://www.tanium.com/blog/lateral-movement-update-3-ways-to-stop-the-sideways-steal-of-data-across-your-network/)  
45. Lateral movement: How attackers silently spread in 48 minutes \- Vectra AI, accessed February 6, 2026, [https://www.vectra.ai/topics/lateral-movement](https://www.vectra.ai/topics/lateral-movement)  
46. Understanding Lateral Movement: Insights & Prevention \- Fidelis Security, accessed February 6, 2026, [https://fidelissecurity.com/cybersecurity-101/learn/lateral-movement/](https://fidelissecurity.com/cybersecurity-101/learn/lateral-movement/)  
47. Defending blind DDoS attack on SDN based on moving target defense \- ResearchGate, accessed February 6, 2026, [https://www.researchgate.net/publication/286292731\_Defending\_blind\_DDoS\_attack\_on\_SDN\_based\_on\_moving\_target\_defense](https://www.researchgate.net/publication/286292731_Defending_blind_DDoS_attack_on_SDN_based_on_moving_target_defense)  
48. SDN-Based Cyber Deception Deployment for Proactive Defense Strategy Using Honey of Things and Cyber Threat Intelligence | Request PDF \- ResearchGate, accessed February 6, 2026, [https://www.researchgate.net/publication/374859181\_SDN-Based\_Cyber\_Deception\_Deployment\_for\_Proactive\_Defense\_Strategy\_Using\_Honey\_of\_Things\_and\_Cyber\_Threat\_Intelligence](https://www.researchgate.net/publication/374859181_SDN-Based_Cyber_Deception_Deployment_for_Proactive_Defense_Strategy_Using_Honey_of_Things_and_Cyber_Threat_Intelligence)  
49. Dynamic Anonymous Access Control Based on Dual-Mode Single-Packet Authentication, accessed February 6, 2026, [https://www.preprints.org/manuscript/202501.0527](https://www.preprints.org/manuscript/202501.0527)  
50. eBPF Tutorial by Example 21: Programmable Packet Processing with XDP \- eunomia-bpf, accessed February 6, 2026, [https://eunomia.dev/tutorials/21-xdp/](https://eunomia.dev/tutorials/21-xdp/)  
51. Dynamic moving target defense strategy based on adaptive port hopping in SDN | Request PDF \- ResearchGate, accessed February 6, 2026, [https://www.researchgate.net/publication/371882786\_Dynamic\_moving\_target\_defense\_strategy\_based\_on\_adaptive\_port\_hopping\_in\_SDN](https://www.researchgate.net/publication/371882786_Dynamic_moving_target_defense_strategy_based_on_adaptive_port_hopping_in_SDN)  
52. ACM Workshop on Moving Target Defense (MTD) – In conjunction with the ACM Conference on Computer and Communications Security (CCS), accessed February 6, 2026, [https://mtd.mit.edu/](https://mtd.mit.edu/)  
53. SDN-Based IP Shuffling Moving Target Defense with Multiple SDN Controllers | Request PDF \- ResearchGate, accessed February 6, 2026, [https://www.researchgate.net/publication/335352196\_SDN-Based\_IP\_Shuffling\_Moving\_Target\_Defense\_with\_Multiple\_SDN\_Controllers](https://www.researchgate.net/publication/335352196_SDN-Based_IP_Shuffling_Moving_Target_Defense_with_Multiple_SDN_Controllers)  
54. dynamic honeypot deployment in sdn: integrating moving target defense and deception mechanisms for enhanced cybersecurity \- ResearchGate, accessed February 6, 2026, [https://www.researchgate.net/publication/392159485\_DYNAMIC\_HONEYPOT\_DEPLOYMENT\_IN\_SDN\_INTEGRATING\_MOVING\_TARGET\_DEFENSE\_AND\_DECEPTION\_MECHANISMS\_FOR\_ENHANCED\_CYBERSECURITY](https://www.researchgate.net/publication/392159485_DYNAMIC_HONEYPOT_DEPLOYMENT_IN_SDN_INTEGRATING_MOVING_TARGET_DEFENSE_AND_DECEPTION_MECHANISMS_FOR_ENHANCED_CYBERSECURITY)  
55. Cyber-Physical Deception Through Coordinated IoT Honeypots \- USENIX, accessed February 6, 2026, [https://www.usenix.org/system/files/conference/usenixsecurity25/sec25cycle1-prepub-815-guan.pdf](https://www.usenix.org/system/files/conference/usenixsecurity25/sec25cycle1-prepub-815-guan.pdf)  
56. In-Kernel Traffic Sketching for Volumetric DDoS Detection \- Temple CIS, accessed February 6, 2026, [https://cis.temple.edu/\~jiewu/research/publications/Publication\_files/ICC25\_In-Kernel%20Traffic%20Sketching%20for%20Volumetric%20DDoS%20Detection-final.pdf](https://cis.temple.edu/~jiewu/research/publications/Publication_files/ICC25_In-Kernel%20Traffic%20Sketching%20for%20Volumetric%20DDoS%20Detection-final.pdf)  
57. TCP — Ryu 4.34 documentation \- Read the Docs, accessed February 6, 2026, [https://ryu.readthedocs.io/en/latest/library\_packet\_ref/packet\_tcp.html](https://ryu.readthedocs.io/en/latest/library_packet_ref/packet_tcp.html)  
58. ryu/ryu/lib/packet/tcp.py at master · faucetsdn/ryu \- GitHub, accessed February 6, 2026, [https://github.com/osrg/ryu/blob/master/ryu/lib/packet/tcp.py](https://github.com/osrg/ryu/blob/master/ryu/lib/packet/tcp.py)  
59. Understanding Ryu OpenFlow Controller, mininet, WireShark and tcpdump \- Stack Overflow, accessed February 6, 2026, [https://stackoverflow.com/questions/37998065/understanding-ryu-openflow-controller-mininet-wireshark-and-tcpdump](https://stackoverflow.com/questions/37998065/understanding-ryu-openflow-controller-mininet-wireshark-and-tcpdump)  
60. Towards Enhancing the Endpoint Security using Moving Target Defense (Shuffle-based Approach) in Software Defined Networking \- ResearchGate, accessed February 6, 2026, [https://www.researchgate.net/publication/354054260\_Towards\_Enhancing\_the\_Endpoint\_Security\_using\_Moving\_Target\_Defense\_Shuffle-based\_Approach\_in\_Software\_Defined\_Networking](https://www.researchgate.net/publication/354054260_Towards_Enhancing_the_Endpoint_Security_using_Moving_Target_Defense_Shuffle-based_Approach_in_Software_Defined_Networking)  
61. CPU Utilization Research Articles \- Page 5 | R Discovery, accessed February 6, 2026, [https://discovery.researcher.life/topic/cpu-utilization/1177341?page=5](https://discovery.researcher.life/topic/cpu-utilization/1177341?page=5)  
62. The SDN Shuffle: Creating a Moving-Target Defense using Host-based Software-Defined Networking \- Computer Science, accessed February 6, 2026, [https://web.cs.wpi.edu/\~cshue/research/mtd15.sdn.pdf](https://web.cs.wpi.edu/~cshue/research/mtd15.sdn.pdf)  
63. Tutorial on Software Defined Networking using Mininet \- GitHub, accessed February 6, 2026, [https://github.com/azkiflay/mininet](https://github.com/azkiflay/mininet)  
64. Getting Started With SDN. This tutorial will help you get to get… | by Abhishek Agarwal | Medium, accessed February 6, 2026, [https://medium.com/@click4abhishekagarwal/getting-started-with-sdn-597663e5caef](https://medium.com/@click4abhishekagarwal/getting-started-with-sdn-597663e5caef)  
65. Using the OpenDaylight SDN Controller with the Mininet Network Emulator, accessed February 6, 2026, [https://brianlinkletter.com/2016/02/using-the-opendaylight-sdn-controller-with-the-mininet-network-emulator/](https://brianlinkletter.com/2016/02/using-the-opendaylight-sdn-controller-with-the-mininet-network-emulator/)  
66. Implementation of Network Traffic Monitoring using Software Defined Networking Ryu Controller \- WSEAS, accessed February 6, 2026, [https://www.wseas.org/multimedia/journals/control/2021/a465103-007(2021).pdf](https://www.wseas.org/multimedia/journals/control/2021/a465103-007\(2021\).pdf)  
67. ryu Documentation, accessed February 6, 2026, [https://media.readthedocs.org/pdf/ryu-docs/latest/ryu-](https://media.readthedocs.org/pdf/ryu-docs/latest/ryu-)  
68. Mininet Lab 2: SDN \- HackMD, accessed February 6, 2026, [https://hackmd.io/@pmanzoni/SyWm3n0HH](https://hackmd.io/@pmanzoni/SyWm3n0HH)  
69. What is eBPF? An Introduction and Deep Dive into the eBPF Technology, accessed February 6, 2026, [https://ebpf.io/what-is-ebpf/](https://ebpf.io/what-is-ebpf/)  
70. eBPF Security: Top 5 Use Cases, Challenges & Best Practices, accessed February 6, 2026, [https://www.oligo.security/academy/ebpf-security-top-5-use-cases-challenges-and-best-practices](https://www.oligo.security/academy/ebpf-security-top-5-use-cases-challenges-and-best-practices)  
71. eBPF Security Threat Model \- Linux Foundation, accessed February 6, 2026, [https://www.linuxfoundation.org/hubfs/eBPF/ControlPlane%20%E2%80%94%20eBPF%20Security%20Threat%20Model.pdf](https://www.linuxfoundation.org/hubfs/eBPF/ControlPlane%20%E2%80%94%20eBPF%20Security%20Threat%20Model.pdf)  
72. eBPF: A new frontier for malware \- Red Canary, accessed February 6, 2026, [https://redcanary.com/blog/threat-detection/ebpf-malware/](https://redcanary.com/blog/threat-detection/ebpf-malware/)  
73. Network packet manipulation in Python, or how to get started with the Scapy library \- an interview with Capt. Damian Ząbek | NEWS \- ECSC, accessed February 6, 2026, [https://ecsc.mil.pl/en/news/network-packet-manipulation-in-python-or-how-to-get-started-with-the-scapy-library-an-interview-with-capt-damian-zabek/](https://ecsc.mil.pl/en/news/network-packet-manipulation-in-python-or-how-to-get-started-with-the-scapy-library-an-interview-with-capt-damian-zabek/)  
74. Scapy, accessed February 6, 2026, [https://scapy.net/](https://scapy.net/)  
75. Shortest Path forwarding with Openflow on RYU \- Flavio Castro, accessed February 6, 2026, [https://castroflavio.com/posts/shortest-path-forwarding-with-openflow-on-ryu/](https://castroflavio.com/posts/shortest-path-forwarding-with-openflow-on-ryu/)  
76. learn-sdn-with-ryu/ryu\_part8.md at master \- GitHub, accessed February 6, 2026, [https://github.com/knetsolutions/learn-sdn-with-ryu/blob/master/ryu\_part8.md](https://github.com/knetsolutions/learn-sdn-with-ryu/blob/master/ryu_part8.md)  
77. The First Application — Ryu 4.34 documentation \- Read the Docs, accessed February 6, 2026, [https://ryu.readthedocs.io/en/latest/writing\_ryu\_app.html](https://ryu.readthedocs.io/en/latest/writing_ryu_app.html)  
78. Switching Hub — Ryubook 1.0 documentation \- GitHub Pages, accessed February 6, 2026, [https://osrg.github.io/ryu-book/en/html/switching\_hub.html](https://osrg.github.io/ryu-book/en/html/switching_hub.html)  
79. Case Study: SuperNetflow – Reinventing Network Observability with eBPF, accessed February 6, 2026, [https://ebpf.foundation/case-study-supernetflow-reinventing-network-observability-with-ebpf/](https://ebpf.foundation/case-study-supernetflow-reinventing-network-observability-with-ebpf/)  
80. Flow setup latency in SDN networks | Request PDF \- ResearchGate, accessed February 6, 2026, [https://www.researchgate.net/publication/327786707\_Flow\_setup\_latency\_in\_SDN\_networks](https://www.researchgate.net/publication/327786707_Flow_setup_latency_in_SDN_networks)  
81. 2-Survey of SDN Lastedit | PDF | Machine Learning | Quality Of Service \- Scribd, accessed February 6, 2026, [https://www.scribd.com/document/967382794/2-Survey-of-SDN-Lastedit](https://www.scribd.com/document/967382794/2-Survey-of-SDN-Lastedit)  
82. SDN-based solutions for Moving Target Defense network protection \- Semantic Scholar, accessed February 6, 2026, [https://www.semanticscholar.org/paper/SDN-based-solutions-for-Moving-Target-Defense-Kampanakis-Perros/be77fc5937248b2728799ba88eeae6ab7b9bbe30](https://www.semanticscholar.org/paper/SDN-based-solutions-for-Moving-Target-Defense-Kampanakis-Perros/be77fc5937248b2728799ba88eeae6ab7b9bbe30)  
83. sdn intrusion detection using machine learning method \- arXiv, accessed February 6, 2026, [https://www.arxiv.org/pdf/2411.05888](https://www.arxiv.org/pdf/2411.05888)  
84. Chapter 3\. Getting started with XDP and eBPF | Configuring firewalls and packet filters | Red Hat Enterprise Linux, accessed February 6, 2026, [https://docs.redhat.com/en/documentation/red\_hat\_enterprise\_linux/10/html/configuring\_firewalls\_and\_packet\_filters/getting-started-with-xdp-and-ebpf](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/configuring_firewalls_and_packet_filters/getting-started-with-xdp-and-ebpf)  
85. In-Kernel Intrusion Detection Systems using eBPF/XDP | LSM Lab.@NAIST, accessed February 6, 2026, [https://www-lsm.naist.jp/en/project/ebpf-based-ids/](https://www-lsm.naist.jp/en/project/ebpf-based-ids/)  
86. Efficient Blockchain-Based Mutual Authentication and Session Key Agreement for Cross-Domain IIoT | Request PDF \- ResearchGate, accessed February 6, 2026, [https://www.researchgate.net/publication/377287644\_Efficient\_Blockchain-Based\_Mutual\_Authentication\_and\_Session\_Key\_Agreement\_for\_Cross-Domain\_IIoT](https://www.researchgate.net/publication/377287644_Efficient_Blockchain-Based_Mutual_Authentication_and_Session_Key_Agreement_for_Cross-Domain_IIoT)  
87. Network Security Projects for Final Year Students \- PHD Services \-, accessed February 6, 2026, [https://phdservices.org/network-security-projects-for-final-year-students/](https://phdservices.org/network-security-projects-for-final-year-students/)  
88. SDN-Enabled IoT Security Frameworks—A Review of Existing Challenges \- MDPI, accessed February 6, 2026, [https://www.mdpi.com/2227-7080/13/3/121](https://www.mdpi.com/2227-7080/13/3/121)  
89. A SOFTWARE DEFINED NETWORK IMPLEMENTATION USING MININET AND RYU \_\_\_\_\_\_ A Project Presented to the Faculty of California \- Department of Computer Science, accessed February 6, 2026, [https://csc.csudh.edu/btang/thesis/carlos-sdn.pdf](https://csc.csudh.edu/btang/thesis/carlos-sdn.pdf)

[image1]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABIAAAAaCAYAAAC6nQw6AAAA20lEQVR4Xu2RPw4BYRBHf65AKDTcgDgBd5AIoaDSuAyR+NNIFKJUqFxCoeICiDswY+bLrjHo8ZKXrO8NdneAn6FNbhwb2u05W9P2QI4skwPySlb0c0o7Xw+1ncgumdTmMoMMe4wgbW6Dxx6vf2gHaR0bLHXI4NEGogVpBxs8wjtY2kBMIW1ig8cW0b/aDV20hS2+JA0ZZKuQLcUNLcvD7+hDBhc2KNzG9tAjPFbPBoUbv/C3ZBDdetE0JvS8OX8irP1MJkxjmviw9gKiO4m7JkvOObu6f/PPn6/nBowURl6mErgLAAAAAElFTkSuQmCC>

[image2]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACIAAAAaCAYAAADSbo4CAAABeUlEQVR4Xu2UvStGYRjGb0WKxMIgSplIFh+rj2IRKTH5GyRlo1gsyoQsFjaLkpKwGwiD/Ad2GYSB63af95zb1fMe5z2jzq9+9Z77vnqe857nQ6TgHzECLwIe+RBod72Qx3AhTuegGQ7DWfgFV6Ln/iTyQz2cFsuoS2I5dQoeRvU6i+dnEn7CBm44xsUme4E11FNu4DoXK2UTnnGR0En0RU65EXECL7moa+ppo2dPk9gEfdwg3sRyg9wA3WK9CV+cgQ9iG65D7B9cw12X8cyJDVLFDUIzr7CaG2BPrB+joUe4GDWeYQ+8E9sDocm2hQYpg2Z4+XrhPvwQ2+gxY/BAksGXo7r+Pi+FCH3JrC/CPsEN2OVyv9DQPRcDlI6kfvI0huC72DGuCB18h4sBtsSyeimlsQqvuJgFHXyeiwF0E2t2jeqMHstcd4QO3spFokWStR6lnqdWbFnSMkEGxD55ORrFBuaNp6fLc+t63k4f+ou0q7qgoKCgICvf4oliEa99LtoAAAAASUVORK5CYII=>

[image3]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACMAAAAaCAYAAAA9rOU8AAABlUlEQVR4Xu2UPShGYRTHj4+Uj0HZlHwMFItSTKJMFAYDi8nCIrLZ2GyKUCxkkY9NlEnKx2JQJovBwmAgyiD+/869r+ee+8R9XybdX/2Gc87/fe7X87wiKf+YKXjkcdINgVpn5nMHjmTSOdIAO+EHfIa9QV2TSShlcFA0R0dFc3QA7gb9Qo3/Di60b5uGftHcPcw3szx4C8dMPyd4kQnbNMyJ5rbsIOAcbtpmIyw2vWrRu/cxDO9s08Ob6M002QHoEJ21us1y0c30JHqREAYXndplDW7Ypgeu8SjxT0R4Tc4jbMOiYHDo9FmfObUL30qSk8A1uFFDCmCz6Gd7gePOTFrgMewT/eGyMzuFe04dUimarbcDD8xZr+EMrHNyEV7hg0SP2TrsceqQBfG8Xg9dok+f9dHl4iumx+NYYnrkSpLdzCw8sM0kcHF385JVU5MK+XrdP3ECp20zCVy83fSqTU2GRLP85/2OUvgu8TUTwSPMzzIPL+BSdCzdEt+IN5GEcinxHOWmzwo+TRussoOUlJSUlD/mE7D0ZJss3gK2AAAAAElFTkSuQmCC>

[image4]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACwAAAAaCAYAAADMp76xAAACE0lEQVR4Xu2WT0hUURTGT2FQZBGBEAZSUrsgLKzQFmItciUiFOSqXRbUJlRoIeWuINFahhuFiIJWSVYLhdpEhQiu2xWKlBEUJaHf13mvOe+b8c9AQ5v3gx94zrlz731z7zuOWU7OP+EYfFHCrXEQGAk1dQIOwQN/R1eQ3fA0XE4chCczI5zjsAW+hU+Tv1Ovw4/wCzzFwZXmhBU2vC9byrAZfoadWgAXzD8/p4VK0Ge+2IwWhCPm42q0ANqs8NBlcxBWS64WbpFcyk/zhbjoWjyw1Tf0zLzGO63wZOrNH3iT1GwnfAR/wKtJ7kwSTyaxwoW46e1aED5Z6Q0fhb/gAtwvNTILx+Ed+Epq9tD8Kb7C6SR33nyhpaSmsDapSeGQ+bjfkt8D5+GU+ckqdbAjxDctXCl+5W/M31xO/iQtgFH4IcQRjh3QpHDJCnc0ugjPmR97Kfrh3hDzpa0K8R/YXr7DHSHH1tMT4pRW84XjWIWnwm+R47qkth5Nln3A+9myw8JjybF/HpYcuQHfa1JIuwPlFSgXni7bXTpHEUxeCXEjfB3iCN/qu5oUrpnPuV7bi2wzvw63Qu6yrbHh9hAPw+YQp7ArsHuc1YLAN5xzcp6NctH8M99CriHJFXHbvMXcgy+tuDOwBcV7lar/VtmGdEzJBVehF76DY/A57M6Ws/DHC3/YsGH/b3ZpIicnJycnp2xWAHK+hB/9IAJ9AAAAAElFTkSuQmCC>

[image5]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACwAAAAZCAYAAABKM8wfAAACAElEQVR4Xu2WP0hVcRTHT0oo+AcRBHGy0DkwUMOGUoea2kpQsC1IsM0/uChtCknSIAg6OEhUtFRoOggNgUhDq4NTCSIYgYo61PfLuT/veUfve4o+ELkf+MD7nXPuvb/3fr/fuU8kJeVCaISLJ1hsi8C0yXkX4GtYd1SdRyphO/wXOQ7vZlQoTfAeXIWfo8/BIfgbbsM2FuebAdHJ/vQJR4NoXZVPgIcSf+m881X0QaM+4eiR5An1yjkmXA9LXawGXnexwL7og/grZWNOkic0L5rjnj4T5fAd3IMvotiDaLwcjT18ECdd4hOODTl5wrfhAdyCN1wuK9xjK6IHgTf+aHKzcN2MLax96YOO5xIvufUPfAIL4tJjsK7WB0kzbIGTokVdJvcUfjDjANvXabbDW9G6KZ/IQaHodWyfibC97MIyE2Pr6TPjQKvoDW2t5xrcFK3rdLlchMPIbZkIC967GPvnLRcjI/CHDzpCO6PVLpcNnqcvotd1u1wGLHhkxhOiW8XDQ8bD+NgnHOGhvM9puQnfRJ95bdaWyYJ+M+aLwcNlfibx/k1qeRVwR7RuWHJ3kgBXOLxgDuGMyR1jTLTF8BsuiU7OwhYUltjqX6uvTM6aiw74XeL/Gn/hp4yKS0QRvONibK+/XOxSMCi6smsSv2m5l8OW+gbvR/GUlJSUq8Z/H3SAntP8VyYAAAAASUVORK5CYII=>

[image6]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACwAAAAaCAYAAADMp76xAAACLElEQVR4Xu2WO2gUURSGj4Ig+CgEQaw0KDY+QFEDCoYkRVIpCAZiZamFFj4QrCSkUVCi1jYWISSQNAZFhSjYhJCIlZ2F4gvxUaioiPn/nLk7Z/5ssllxI8h88MHec87eOztz79kxKyn5K+yB96q4PBaBmyGn3oV9cFOluoGsge3wd+ZVuL9Q4eyFLXAC3s4+Jy/AV/AjbGNxo2m2/II3FFMFlsIP8LAmwDHz77/VRCM4b77YU00IO83r1moCdFr+o+tmM1wpsfVwmcQS380X4qLz0W9zX9Ad8xz3dF2shoPwGzyVxTqy8Vg2VrgQL3qFJoTXVv2Cd8Ef8D3cKLmaDMAl8DN8ksW6zRf6meUU5sY0KGw1r/sl8XXwHXxo/mTrgnts3PzkcvLhkLsFn4dxhLU9GhROWL5Ho59gl/mBTGjbo+wsp22Obcn28hWuCjG2nnNhnGg1XzjWKnwqvIusOyq5aqRu0ivxKfhMYjNw4iGJsX/ukBi5CCc1KKTuQLkFarHdvJb9PcG1uZ0uhVgFFp8M493wcRhH+Liua1A4Yz5nrbaXOG7FQ3zI/M7yCVc7QzOTHwzja3BfGCc4IbvHEU0Io+Zzcp6FwPPyxvL9y+5yxWa32gqXzVvMDXjfZv8qtiA9PFT/VrmI1tBasOaAxEbMu1Q8nAX48sIXmyZNLAK8IfHliXf2pf3Bn8pi8UjGfJv7ArdJ/J9zFj6ALyzfvxyzB28JdSUlJSX/I9NRzo3Zt+dE0QAAAABJRU5ErkJggg==>

[image7]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACwAAAAZCAYAAABKM8wfAAAB+UlEQVR4Xu2Vz0tUURTHj5IolCKuXLiokKKFiC40BUkqAjduWvYHBAVupIU7RRRUKHQXgitL3VVQBNEiUIQIAt24CQRBRaLciJSIfs+c9+ad+XZnphJ/IO8DH5h7zpn77ru/nkhKypFpgR8CVvgiMOVyIcdhfbb6GKmBnfAg8lnUZlrF4l/E6vR37G24Dn/CO1p8EuggljhINEvyYkyXJDl9uWNHHzTKQeKxWN08J0CPJAP+r61xmdpXqe0pF3uQzlIhZsTqxjgB3ovldD//M93wM3wH6+CsWEdvYImri7kHf8GLnCA2xAZ1nxPgN/wOr3CiGLrpX8ARsc6Ho7j+XoYXorbnExzkIPFIkiX3bsOXsDQpzbw43yJvYS8sc3UZ2mEbXBDr8FoU74C1cZFDry+d3WLbYU6sv0lO5EG3yKJr3xR7jl5/QfbhJgcD6JWkA6nkBLElVveAE3n4AYco9hWuUCyLdj7NwQADYrXFiLdAaJVCaO1d124Um8S8N5H+4QYHCd1ru/L3A57gYAF0df0efgov5VQ49Ou1xkFCb4uHkszcH4cholrsIGtNvxS/SWL4EK/C1xTL0gSfc9BRJclAvfxZ1VnhGrXPFwXQlb1FsVdwT3JvkzODXmEePdA7sIHip84T+FFsFeK9q+1v8LqrS0lJSTmvHAKCuIAAS29omgAAAABJRU5ErkJggg==>

[image8]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACsAAAAaCAYAAAAue6XIAAAB7UlEQVR4Xu2WTyhlcRTHT1EGyWoof0siG4qS5aPsTSxkZ2EzCzULShKavZqxsRWilAVJzMJKkVjMiJpSFmYtKZIF3+/73ffemfPue/c+9UTdT33q/c4593fPu7/f/b0nEhHxKnrgLx9XdBGoUzk/N+DXZHWeqIAxOAif4YQ3bk+VxCn14qyho96Y9sFVL/4pXp1nvsAHWGITBjZ0AwtsApyJ+7J5Zw5u2aAPbJZL7sce3LTBMNSacbUZa7gV2ESrTRi4xKzrsAlxMea6bSKIAfgbrsF6uA0P4U9dpBgSd6MgYvAWFpo4WZZwc/wHJzqH38Rd/A+2iGv+XtVpFiTcjaYkfZnb4BJ8hOMml6AB1tgg6YWL4p4iGxjz4vycaU/+kXDN7krqNEh4Ab/DJlVnuYSTNqjhRCc26EO/uNo7mzDwPGZdkU0EUAmvxD39jHDieRv04Ye42h2bMMxKuKdvYQ9H4lYlI5yYL04Qx+JquR+zsS+5N9sorlluv6yrzImrbNDAJUrsvWxHDn+9+ALl2uw6/CxuC1ybXJJOcYd8JsoldXNtsy4CpyqnrddFPhTDA0n9b+BLyOvYuC9lNvCGzMAuNR4R12zQj86bE5P0N59/dNgsj9V3Aw9+NvUEh1U8sQ3+wmkVj4iIiPhovABZvnh5isP4GAAAAABJRU5ErkJggg==>

[image9]: <data:image/png;base64,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>
