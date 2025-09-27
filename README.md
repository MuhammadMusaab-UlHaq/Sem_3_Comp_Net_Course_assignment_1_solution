 # PCAP File Parser

 This tool parses a `.pcap` file, counts TCP/UDP destination ports, and prints results to standard output.

 ### Learnings & Challenges:

 We learned to use the Scapy library in Python to parse network capture files.
 A key learning was how to iterate through packets and access specific protocol layers like IP, TCP, and UDP to extract headers such as destination port and IP.
 We also practiced using dictionaries for frequency counting, which is very   efficient.
 A challenge was setting up the environment and understanding how to access
 Scapy's layered packet objects, but this became clear once we saw scapy documentation [https://scapy.readthedocs.io/].
 Implementing command-line arguments with `argparse` was a new skill that made our script much more professional and reusable.

 ## Setup

 1. Create virtual environment:
    ```powershell
    python -m venv venv
    ```
 2. Activate (PowerShell):
    ```powershell
    .\venv\Scripts\Activate.ps1
    ```
 3. Install dependencies:
    ```powershell
    pip install -r requirements.txt
    ```

 ## Usage

 ```powershell
 python parse_pcap.py <input.pcap>
 ```

 or if you want to save the output in a file:

  ```powershell
 python parse_pcap.py <input.pcap> > <output.txt>
 ```

 ### Examples:
 ```powershell
 python parse_pcap.py tests/my_own_wireshark.pcap > result.txt
 python parse_pcap.py tests/slowdownload.pcap > slow.txt
 ```

 ## Team

 - Hamza Muhammad Iqbal (503052)
 - Muhammad Musaab Ul Haq (501739)
