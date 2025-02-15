```markdown
# Distributed Password Cracker 🔓💻

A distributed password cracking system using Raspberry Pis and a router. This project allows you to crack password hashes by distributing the workload across multiple Raspberry Pi clients. The server provides a professional web interface for managing clients, starting cracking tasks, and monitoring results.

---

## **Features** ✨

- **Distributed Cracking:** Distribute password cracking tasks across multiple Raspberry Pi clients.
- **Web Interface:** Professional web interface for managing clients and tasks.
- **Auto Client Scanning:** Automatically detect and add clients on the network.
- **Hash Identification:** Automatically identify hash types using HashID.
- **Multiple Tools:** Supports Hashcat and John the Ripper for cracking.
- **Real-Time Updates:** Monitor task progress and client status in real-time.

---

## **Hardware Requirements** 🖥️

- 5 Raspberry Pis (1 server, 4 clients)
- A router for network connectivity
- Power supplies and microSD cards for each Raspberry Pi
- Ethernet cables or Wi-Fi adapters

---

## **Software Requirements** 📦

- Raspbian OS (or any compatible OS)
- Python 3
- Flask (for the web interface)
- Hashcat or John the Ripper
- HashID (for hash identification)
- arp-scan (for auto client scanning)

---

## **Installation** 🛠️

### **1. Clone the Repository**
```bash
git clone https://github.com/your-username/distributed-password-cracker.git
cd distributed-password-cracker
```

### **2. Install Dependencies**
On the **server** and **clients**, run:
```bash
sudo apt-get update
sudo apt-get install arp-scan hashcat python3-pip
pip3 install flask
```

### **3. Configure the Network**
Assign static IP addresses to each Raspberry Pi by editing `/etc/dhcpcd.conf`:
```bash
interface eth0
static ip_address=192.168.1.10/24
static routers=192.168.1.1
static domain_name_servers=192.168.1.1
```

---

## **Usage** 🚀

### **1. Start the Server**
On the **server Raspberry Pi**, run:
```bash
python3 server.py
```
The web interface will be available at `http://<server_ip>:5000`.

### **2. Start the Clients**
On each **client Raspberry Pi**, run:
```bash
python3 client.py
```

### **3. Access the Web Interface**
- Open your browser and navigate to `http://<server_ip>:5000`.
- Use the **Crack Password** tab to start cracking tasks.
- Use the **Client Management** tab to add/remove clients and scan the network.
- Use the **Settings** tab to configure default options.

---

## **Screenshots** 📸

![Web Interface](screenshots/web-interface.png)
*Web Interface for Managing Clients and Tasks*

---

## **Contributing** 🤝

Contributions are welcome! Please open an issue or submit a pull request.

---

## **License** 📜

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## **Acknowledgments** 🙏

- [Hashcat](https://hashcat.net/hashcat/) for password cracking.
- [Flask](https://flask.palletsprojects.com/) for the web interface.
- [arp-scan](https://github.com/royhills/arp-scan) for network scanning.

---

## **Support** 💬

If you have any questions or issues, please open an issue on GitHub.

```

---

## **Linux Terminal Guide** 🐧

### **1. Install Dependencies**
```bash
sudo apt-get update
sudo apt-get install arp-scan hashcat python3-pip
pip3 install flask
```

### **2. Assign Static IP Addresses**
Edit `/etc/dhcpcd.conf` on each Raspberry Pi:
```bash
sudo nano /etc/dhcpcd.conf
```
Add the following (adjust IP addresses as needed):
```bash
interface eth0
static ip_address=192.168.1.10/24
static routers=192.168.1.1
static domain_name_servers=192.168.1.1
```

### **3. Start the Server**
```bash
python3 server.py
```

### **4. Start the Clients**
```bash
python3 client.py
```

### **5. Access the Web Interface**
Open your browser and navigate to:
```bash
http://<server_ip>:5000
```

---

### **Commands Cheat Sheet** 📋

| Command                          | Description                                      |
|----------------------------------|--------------------------------------------------|
| `python3 server.py`              | Start the server.                                |
| `python3 client.py`              | Start a client.                                  |
| `sudo apt-get install arp-scan`  | Install arp-scan for network scanning.           |
| `pip3 install flask`             | Install Flask for the web interface.             |
| `sudo nano /etc/dhcpcd.conf`     | Edit network configuration.                      |

---

### **Troubleshooting** 🔧

- **Client Not Found:** Ensure the client is connected to the network and running `client.py`.
- **Hash Identification Failed:** Install HashID using `pip3 install hashid`.
- **Web Interface Not Loading:** Check if the server is running and accessible on the network.

---

This README and terminal guide provide a comprehensive overview of the project, making it easy for users to set up and use the distributed password cracking system. 🎉#   R e d F o x  
 #   R e d F o x  
 