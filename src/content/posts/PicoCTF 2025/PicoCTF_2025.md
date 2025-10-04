---
title: Pico CTF 2025
published: 2025-03-25
tags: [Forensics]
image: "./pico.png"
category: Writeup CTF Challenge
draft: false
---


# Introduction
Giải này mình chơi với team **aespaFanClub** và mình may mắn clear được cả 6 challenges Forensics của giải. Sau đây sẽ là writeup của mình về 6 challenges này.

# Ph4nt0m 1ntrud3r
> A digital ghost has breached my defenses, and my sensitive data has been stolen! 😱💻 Your mission is to uncover how this phantom intruder infiltrated my system and retrieve the hidden flag.
To solve this challenge, you'll need to analyze the provided PCAP file and track down the attack method. The attacker has cleverly concealed his moves in well timely manner. Dive into the network traffic, apply the right filters and show off your forensic prowess and unmask the digital intruder!
Find the PCAP file here Network Traffic PCAP file and try to get the flag.
Hints:
Filter your packets to narrow down your search.
Attacks were done in timely manner.
Time is essential
Author: Prince Niyonshuti N.

Challenge này cho ta 1 file pcap như sau:
![image](https://hackmd.io/_uploads/r1qug0cskg.png)

Nhìn vào, ta thấy có gói tin **[TCP Out-Of-Order] [Illegal Segments]** nó nghĩa là gói tin này đã được nhận sai thứ tự, và có nhiều gói tin được gửi lại. Dựa vào hint thứ 3 và các thông tin trên, ta nhận thấy rằng các gói tin này được chụp nhưng sai thứ tự thời gian, giờ việc của ta sẽ là lọc lại nội dung được gửi đi rồi ghép lại theo trình tự thời gian.
Dùng lệnh tshark sau:
**tshark -r myNetworkTraffic.pcap -Y "tcp" -T fields -e frame.time_epoch -e tcp.payload | sort -n | cut -f2**

Lệnh trên có tác dụng in ra các payload được gửi ở gói tcp và sắp xếp theo thứ tự thời gian.
Sau khi có được nội dung payload, ta sang cyberchef decode nó là có được flag.
![image](https://hackmd.io/_uploads/rJ__DR9jJe.png)
**Flag: picoCTF{1t_w4snt_th4t_34sy_tbh_4r_2e1ff063}**

# RED
>RED, RED, RED, RED
Download the image: red.png
Hints:
The picture seems pure, but is it though?
Red?Ged?Bed?Aed?
Check whatever Facebook is called now.
Author: Shuailin Pan (LeConjuror)

Ở challenge này, nó cho ta một bức ảnh, nhìn bằng mắt thường thì ta chỉ thấy toàn màu đỏ.

Kiểm tra nó bằng lệnh file và strings, ta được:
![image](https://hackmd.io/_uploads/BJv3KC5oJg.png)

Ta biết được hình ảnh này có 4 kênh màu, mỗi kênh màu 8 bit, và có 1 đoạn văn có vẻ khá bí ẩn. Ở hint thứ 2 có vẻ như nó đang nói tới RGBA là 4 kênh màu trong bức ảnh. Ta nhìn kĩ đoạn văn một chút, để ý vào các chữ cái đầu tiên của đoạn văn thì nó có nghĩa là **CHECKLSB**. Hiểu được ý nghĩa nó cộng thêm hint thứ 2, ta sẽ lên cyberchef trích xuất lsb của 4 kênh màu.
![image](https://hackmd.io/_uploads/H1uh9AqsJl.png)
Khi trích xuất xong lsb ta thấy các mã base64, gán thêm decode base64 vào và ta được flag của challenge này.

**Flag: picoCTF{r3d_1s_th3_ult1m4t3_cur3_f0r_54dn355_}**

# flags are stepic
>A group of underground hackers might be using this legit site to communicate. Use your forensic techniques to uncover their message
Additional details will be available after launching your challenge instance.
Hints:
In the country that doesn't exist, the flag persists
Author: Ricky

Challenges này cho ta một trang web chứa tất cả các lá cờ của các đất nước trên thế giới.

![image](https://hackmd.io/_uploads/rkxRsR9syx.png)

Đọc hint, người ta nói ở đất nước không tồn tại, cờ vẫn tồn tại, có thể là trong số các lá cờ trên trang web có thể có 1 lá cờ không phải quốc kì của 1 đất nước.

Sau một lúc tìm kiếm thì em đã tìm ra nó.
![image](https://hackmd.io/_uploads/HJJwnAciyl.png)

Đây không phải là một đất nước thật, sau đó em tải hình ảnh lá cờ này về để phân tích.
Sau một hồi lâu phân tích metadata, lsb, msb,... thì em chẳng khai thác được gì :)))
Đọc kĩ lại đề bài thì đề bài ghi là flags are stepic, google một chút thì đây stepic là một thư viện python dùng để giấu tin vào hình ảnh PNG. Giờ việc của ta đơn giản là giải mã nó.
```python=
import stepic
from PIL import Image

img = Image.open("upz.png")
hidden_data = stepic.decode(img)
print(hidden_data)
```
![image](https://hackmd.io/_uploads/rySV0R9skg.png)

**Flag: picoCTF{fl4g_h45_fl4g9a81822b}**

# Bitlocker-1
>Jacky is not very knowledgable about the best security passwords and used a simple password to encrypt their BitLocker drive. See if you can break through the encryption!
Download the disk image here
Hints:
Hash cracking
Author: Venax

Challenge này cho ta 1 file disk đã bị mã hóa bitlocker. Để có thể xem nội dung của file disk này ta cần có mật khẩu và như hint của bài ta có thể crack nó và em đã sử dụng hashcat và wordlist rockyou.txt để crack file disk này. Cụ thể các bước làm như sau:

Đầu tiên em chuyển file disk sang mã hash bằng **bitlocker2john** của **john the ripper**
![image](https://hackmd.io/_uploads/SkEI_rjjkg.png)

Tiếp theo, sử dụng hashcat để crack nó.
Dùng lệnh sau:
**hashcat -m 22100 -a 0 bitlocker_hash.txt rockyou.txt --force --show**
![image](https://hackmd.io/_uploads/SkDXFBiikx.png)

Crack thành công với password là **jacqueline**

Sau khi crack, ta sẽ sử dụng disloker để giải mã. Dùng lệnh sau:
**sudo dislocker -V bitlocker-1.dd -u"jacqueline" -- /home/ketsosad/CTF/bitlocker_unlocked**

Cơ chế của dislocker đó là nó sẽ tạo file ảo(disloker-file) và chưa thể truy cập trước tiếp được và ta cần phải mount nó qua một thư mục khác để xem được nội dung. Sử dụng lệnh sau để mount nó vào thư mục khác:
**sudo mount -o ro,loop /home/ketsosad/CTF/bitlocker_unlocked/dislocker-file /home/ketsosad/CTF/bitlocker_mount**
![image](https://hackmd.io/_uploads/HkW3RBookl.png)
Mount thành công, tiếp theo ta sẽ truy cập vào thư mục được mount và xem nội dung bên trong.
![image](https://hackmd.io/_uploads/BkT0RSoj1l.png)
Bên trong nó như thế này, xem **flag.txt** và ta có được flag.

**Flag: picoCTF{us3_b3tt3r_p4ssw0rd5_pl5!_3242adb1}**

# Event-Viewing
>One of the employees at your company has their computer infected by malware! Turns out every time they try to switch on the computer, it shuts down right after they log in. The story given by the employee is as follows:
They installed software using an installer they downloaded online
They ran the installed software but it seemed to do nothing
Now every time they bootup and login to their computer, a black command prompt screen quickly opens and closes and their computer shuts down instantly.
See if you can find evidence for the each of these events and retrieve the flag (split into 3 pieces) from the correct logs!
Download the Windows Log file here
Hints:
Try to filter the logs with the right event ID.
What could the software have done when it was ran that causes the shutdowns every time the system starts up?

Ở Challenge này, ta biết rằng máy tính của nạn nhân đã bị nhiễm malware và máy của anh ta sau mỗi lần khởi động sẽ lại tắt và chall cho ta1 file log evtx, giờ ta sẽ mở nó lên để tìm bằng chứng cho sự kiện này.

Đầu tiên, ta biết được rằng nạn nhân đã tải một phần mềm về máy, ta sẽ kiểm tra xem anh ta đã cài đặt gì, lọc file log theo ID 1033 và 11707 để kiểm tra.
![image](https://hackmd.io/_uploads/BydRrLsoJx.png)

Thấy có mã base64 ta decode nó thì được part 1 của flag.
**Part1: picoCTF{Ev3nt_vi3wv3r_**
Qua gói log này, ta biết được nạn nhân đã cài đặt malware có tên là **Totally_Legit_Software** và có thể nó đã thực hiện thay đổi hệ điều hành của máy nạn nhân và có thể là registry, lọc theo ID 4657 ta được như sau:
![image](https://hackmd.io/_uploads/Hy1Ppgjnye.png)

Và ta đã có part2 của flag sau khi decode mã base64.
**Part2: 1s_a_pr3tty_us3ful_**

Ta được biết khi khởi động máy thì nó sẽ bị tắt đi, ta sẽ lọc theo các ID 1074, 109, 4608 để kiểm tra các tiến trình thực hiện shutdown máy. Và ta tìm được part 3 của flag ở đây.
![image](https://hackmd.io/_uploads/SyM7yWihyx.png)

**Part3: t00l_81ba3fe9}**

**Flag: picoCTF{Ev3nt_vi3wv3r_1s_a_pr3tty_us3ful_t00l_81ba3fe9}**


# Bitlocker-2
>Jacky has learnt about the importance of strong passwords and made sure to encrypt the BitLocker drive with a very long and complex password. We managed to capture the RAM while this drive was opened however. See if you can break through the encryption!
Download the disk image here and the RAM dump here
Hints:
Try using a volatility plugin
Author: Venax

Challenge này là cải tiến của Bitlocker-1 khi không thể crack được **user password**,thay vào đó ta đã có được file RAM dump khi ổ đĩa này đang được mở, ta sẽ khai thác file RAM dump này để mở khóa bitlocker.

Có nhiều cách để mở khóa một file disk bitlocker ví dụ như dùng user password, recovery key hay FVEK. Và trong challenge này, khi đã có file RAM dump, ta có thể dùng plugin bitlocker của volatility để in ra các FVEK tiềm năng, từ đó ta sẽ thử từng key được in ra và mở khóa file disk bitlocker.

Tuy nhiên, plugin này không có sẵn ở link repo volatily mà ta phải cài đặt thêm nó vào volatility.

Chi tiết ở link sau:https://github.com/breppo/Volatility-BitLocker

Ở link này, ta có source của plugin bitlocker và ta biết được nó dùng cho volatility2(mình đã không đọc code trước nên đã tốn kha khá thời gian vì cài nó vào vol 3 rồi không hiểu vì sao nó không chạy được), sau đó công việc của ta đơn giản là đưa source này vào thư mục plugin của vol 2 là có thể thực thi nó.

Ta sẽ kết hợp với dislocker để giải mã các khóa được in ra.

Sử dụng lệnh sau: **python2 vol.py -f memdump.mem bitlocker --profile={Windows_Profile} --dislocker {vị trí lưu key được in ra}**

![image](https://hackmd.io/_uploads/ByrRSsnjyg.png)

Ta được các FVEK như sau, sau đó ta sẽ thử từng FVEK, với mỗi FVEK sai, sau khi thử xong ta cần phải unmount thư mục được mount với dislocker rồi bằng lệnh sau:
**sudo fusermount -u {đường dẫn thư mục}**

![image](https://hackmd.io/_uploads/BJlt_jnjyg.png)
Đây là 1 trong những thao tác xử lí FVEK sai.

Và sau khi tìm được password đúng thì tương tự như bitlocker-1 ta vào thư mục được mount và lấy flag.

**Flag: picoCTF{B1tl0ck3r_dr1v3_d3crypt3d_9029ae5b}**
