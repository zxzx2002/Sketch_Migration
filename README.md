# PSM Sketch_Migration
Source code for PSM sketch migration (IWQoS 2026).
## Paper
PSM: Timely and Resource-Efficient Sketch Migration in Network Measurement
## Abstract
Sketches can achieve resource-efficient and high-accurate Network Measurement (NM) with configurable resource-performance trade-offs. Due to network dynamics, network measurement points (i.e., the switches deployed with sketches) need to reallocate dynamically to cover full traffic. However, using existing approaches to migrate sketches leads to unacceptable latency and resource overhead. In this paper, we propose PSM, a framework for timely and resource-efficient sketch migration. For timeliness, PSM utilizes a protocol that is able to access sketch counters and migrate them in parallel using background traffic. To ensure migration without direct traffic, we leverage programmable switches' mirroring and recirculation functions to generate packets. For resource efficiency, PSM uses bitmap structures and hardware-friendly computations to track the migration progress and verify integrity. We implement the PSM framework on Intel Tofino2 switches and compare PSM with three state-of-the-art approaches through extensive experiments. Results indicate that PSM achieves timely and resource-efficient sketch migration.
## Source Code Usage
### Overview
We have provided seven folders with similar structures. The five folders named with sketch algorithms are the main program sections (i.e., "bloomfilter/", "cmsketch/", "countsketch/", "mvsketch/", and "sketchlearn/"), containing the sketch migration codes for our PSM method and the comparison methods. We take the "bloomfilter/" folder as an example to introduce the file structure within each folder. And the other two folders are utilized for program testing
and data processing, which will be discussed after the "bloomfilter" section.
#### bloomfilter/
There are a total of 6 folders, each corresponding to a different method of migration. The "1201MR - Tofino/" folder represents the mirror and recirculation (MR) method proposed by our PSM. The number "1201" is the date when this program was completed (i.e., 12/01/2024). Similarly, the "1211BF- Tofino/" folder represents the background flow (BF) method proposed by our PSM. The "1214SwingState - Tofino/" folder represents the SwingState method. The "1225redplane - Tofino/" folder represents the RedPlane method. The "1229p4sync - Tofino/" folder represents the P4Sync method. And the "bloomfilter/" folder represents the bloomfilter without sketch migration methods.    
     
In each folder, the P4 format files, together with the "include/" folder (i.e., includes the "header.p4" and "parser.p4" files) are the programs running on the programmable switch. The Python format files are the files used on the server to send packets and conduct tests during the migration process. Specifically, "myTunnel_header.py" contains the format definition of our custom migration protocol. The "send_migration.py" is used to send migration packets on the server. The "send_sketch.py" is used to generate a series of background traffic, thereby obtaining the data for sketch network measurement in the switch registers.
#### _recirculation_time/
It contains the P4 program for data plane packet recirculation, which is a unique packet processing method specific to programmable switches. It enables the designated packets to be continuously mirrored and circulated within the switch without being forwarded. This recirculation process is relatively complex. To assist users in quickly understanding the usage method, we provide this folder.    
Similarly, in this folder the the P4 format files are utilized for running the recirculation process in the programmable switch, and the Python format files are used for sending packets from the server.
#### _timestamp/
This folder contains the program for processing the timestamps of packets. Since the protocols we adopted for each sketch migration method are not completely consistent, the process of extracting experimental data will be rather cumbersome. Therefore, we further provide a program for handling timestamp data in Python format.
### Setup Instructions
As for the Python programs, we utilize Python 3.8 in the Dell R740 server.   
As for the data plane P4 program, we utilize bf-sde-9.10.0 with Intel Tofino switch.

