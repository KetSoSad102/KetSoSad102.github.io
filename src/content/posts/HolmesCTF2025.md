---
title: Holmes CTF 2025
published: 2025-09-30
tags: [Forensics]
category: Writeup CTF Challenge
draft: false
---

# Holmes CTF 2025

## The Tunnel Without Walls
>A memory dump from a connected Linux machine reveals covert network connections, fake services, and unusual redirects. Holmes investigates further to uncover how the attacker is manipulating the entire network!
>Difficult: Hard
### Q1: What is the Linux kernel version of the provided image? (string)

Sử dụng plugins `banner` để kiểm tra version.
![image](https://hackmd.io/_uploads/rkP-UwHnle.png)

**Answer: 5.10.0-35-amd64**

### Q2: The attacker connected over SSH and executed initial reconnaissance commands. What is the PID of the shell they used? (number)

Dùng plugins `bash` để xem lại các command cũ
![image](https://hackmd.io/_uploads/Bk1CPvS2le.png)

Ta thấy PID là 13608 là những command đầu tiên như kiểu của câu hỏi, tiếp tục kiểm tra tiến trình thì thấy trước PID này là ssh.

![image](https://hackmd.io/_uploads/B1H49Drnlg.png)

**Answer: 13608**

### Q3: After the initial information gathering, the attacker authenticated as a different user to escalate privileges. Identify and submit that user's credentials. (user:password)

![image](https://hackmd.io/_uploads/Sy9QI_rneg.png)

Ta có thể thấy có command `su jm` để chuyển sang user tên là `jm`. 
Để tìm pass thì em dùng strings grep để tìm ra hash rồi crack với rockyou.

![image](https://hackmd.io/_uploads/HJI58dBnee.png)
`$1$` là hash md5crypt.

Crack hashcat với mode 500(md5crypt)
```
(venv) ketsosad@MSI:~/CTF/Crack$ echo 'jm:$1$jm$poAH2RyJp8ZllyUvIkxxd0' > hashcat.txt
(venv) ketsosad@MSI:~/CTF/Crack$ hashcat -m 500 -a 0 --username hashcat.txt rockyou.txt
```
![image](https://hackmd.io/_uploads/Sk5RLOrheg.png)

**Answer: jm:WATSON0**

### Q4: The attacker downloaded and executed code from Pastebin to install a rootkit. What is the full path of the malicious file? (/path/filename.ext)

Em xài command sau để tìm các file được nghi ngờ là mal đang ẩn trên hệ thống.
![image](https://hackmd.io/_uploads/rk1ZEKrhex.png)
![image](https://hackmd.io/_uploads/B1tV4Yr3ex.png)

**Answer: /usr/lib/modules/5.10.0-35-amd64/kernel/lib/Nullincrevenge.ko**

### Q5: What is the email account of the alleged author of the malicious file? (user@example.com)

Sử dụng command sau để dump file mal ra:
`vol -f memdump.mem linux.pagecache.InodePages --find /usr/lib/modules/5.10.0-35-amd64/kernel/lib/Nullincrevenge.ko --
dump`

Sau đó strings grep để tìm thông tin.
![image](https://hackmd.io/_uploads/ryx5_pLhee.png)

**Answer: i-am-the@network.now**

### Q6: The next step in the attack involved issuing commands to modify the network settings and installing a new package. What is the name and PID of the package? (package name,PID)

Đối tượng đã thực hiện tải về gói **dnsmasq**
![image](https://hackmd.io/_uploads/HJ7GqpLhll.png)
**Dnsmasq** là một phần mềm mã nguồn mở cung cấp bộ nhớ đệm Hệ thống tên miền (DNS) và máy chủ DHCP, hoạt động hiệu quả cho các mạng nhỏ như mạng gia đình hoặc mạng văn phòng nhỏ.

Sau đó em dùng pslist để tìm lại PID của việc tải gói này.
![image](https://hackmd.io/_uploads/H1g2Ya82xx.png)

**Answer: dnsmasq,38687**

### Q7: Clearly, the attacker's goal is to impersonate the entire network. One workstation was already tricked and got its new malicious network configuration. What is the workstation's hostname?

![image](https://hackmd.io/_uploads/HyoO3T8hlx.png)
Em dump ra file lease(lưu trữ thông tin về các địa chỉ IP mà nó đã cấp phát động) của **dnsmasq** và có đáp án.

**Answer: Parallax-5-WS-3**

### Q8: After receiving the new malicious network configuration, the user accessed the City of CogWork-1 internal portal from this workstation. What is their username? (string)

Em dùng tool `Bulk extractor` để dump ra file pcap.
![image](https://hackmd.io/_uploads/Hy15QTPhgg.png)

**Answer: mike.sullivan**
### Q9: Finally, the user updated a software to the latest version, as suggested on the internal portal, and fell victim to a supply chain attack. From which Web endpoint was the update downloaded?

Em dump toàn bộ json được docker lưu lại của **access.log** ra rồi grep phương thức `GET` và có được đáp án.

![image](https://hackmd.io/_uploads/r17bF0Ihxx.png)
![image](https://hackmd.io/_uploads/rysEYA83ge.png)

**Answer: /win10/update/CogSoftware/AetherDesk-v74-77.exe**

### Q10: To perform this attack, the attacker redirected the original update domain to a malicious one. Identify the original domain and the final redirect IP address and port. (domain,IP:port)

Em dump ra 2 file `default.conf` và `dnsmasq.conf` thì có được domain ban đầu ở file `dnsmasq.conf`.

Nhìn qua `default.conf` ta thấy nó chuyển hướng sang http://13.62.49.86:7477/;
![image](https://hackmd.io/_uploads/BJSRq0I3ee.png)

**Answer: updates.cogwork-1.net,13.62.49.86:7477**

## The Card
>Holmes receives a breadcrumb from Dr. Nicole Vale - fragments from a string of cyber incidents across Cogwork-1. Each lead ends the same way: a digital calling card signed JM.
>Difficult: Easy
### Q1: Analyze the provided logs and identify what is the first User-Agent used by the attacker against Nicole Vale's honeypot. (string)

Kiểm tra trong `access.log` và có đáp án.
![image](https://hackmd.io/_uploads/Skgw-kw3ex.png)

**Answer: Lilnunc/4A4D - SpecterEye**

### Q2: It appears the threat actor deployed a web shell after bypassing the WAF. What is the file name? (filename.ext)

![image](https://hackmd.io/_uploads/HkUyf1D3le.png)
Sau khi vượt tường lửa file web shell đã được tạo là đáp án được log ghi lại.

**Answer: temp_4A4D.php**

### Q3: The threat actor also managed to exfiltrate some data. What is the name of the database that was exfiltrated? (filename.ext)

![image](https://hackmd.io/_uploads/S15qzyPhle.png)

**Answer: database_dump_4A4D.sql**

### Q4: During the attack, a seemingly meaningless string seems to be recurring. Which one is it? (string)

Em thấy hầu hết tên các file dữ liệu bị đánh cắp và gửi về đều kết thúc bằng `4A4D`

**Answer: 4A4D**

### Q5: OmniYard-3 (formerly Scotland Yard) has granted you access to its CTI platform. Browse to the first IP:port address and count how many campaigns appear to be linked to the honeypot attack.

![image](https://hackmd.io/_uploads/S1KYPJw2eg.png)

**Answer: 5**

### Q6: How many tools and malware in total are linked to the previously identified campaigns? (number)

Câu này em brute force ra đáp án là 9 :((

### Q7: It appears that the threat actor has always used the same malware in their campaigns. What is its SHA-256 hash? (sha-256 hash)

![image](https://hackmd.io/_uploads/ByCuqyPhxe.png)

Ở cuối đồ thị có mã hash 256 và đó là đáp án.

**Answer: 7477c4f5e6d7c8b9a0f1e2d3c4b5a6f7e8d9c0b1a2f3e4d5c6b7a8f9e0d17477**

### Q8: Browse to the second IP:port address and use the CogWork Security Platform to look for the hash and locate the IP address to which the malware connects. (Credentials: nvale/CogworkBurning!)

![image](https://hackmd.io/_uploads/B1Pmsyvhle.png)
![image](https://hackmd.io/_uploads/SyYrokD2ee.png)
Đăng nhập vào rồi paste mã sha256 trên và có đáp án.

**Answer: 74.77.74.77**

### Q9: What is the full path of the file that the malware created to ensure its persistence on systems? (/path/filename.ext)

![image](https://hackmd.io/_uploads/ryM02kv3ll.png)

**Answer: /opt/lilnunc/implant/4a4d_persistence.sh**

### Q10: Finally, browse to the third IP:port address and use the CogNet Scanner Platform to discover additional details about the TA's infrastructure. How many open ports does the server have?

![image](https://hackmd.io/_uploads/Hy-zRyP3xg.png)

Có 11 cổng đang mở

**Answer: 11**

### Q11: Which organization does the previously identified IP belong to? (string)

![image](https://hackmd.io/_uploads/B1eZv0Jw2ex.png)

**Answer: SenseShield MSP**

### Q12: One of the exposed services displays a banner containing a cryptic message. What is it? (string)

Vào mục `Services` rồi em tìm ra được dòng khá sus, sub thử thì đúng.
![image](https://hackmd.io/_uploads/S1eregPhge.png)

**Answer: He's a ghost I carry, not to haunt me, but to hold me together - NULLINC REVENGE**


