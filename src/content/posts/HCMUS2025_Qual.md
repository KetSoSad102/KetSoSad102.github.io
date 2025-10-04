---
title: HCMUS CTF Qual 2025
published: 2025-03-25
tags: [Forensics]
category: Writeup CTF Challenge
draft: false
---

# Introduction

Sau đây là writeup của mình cho 4 câu Forensics mình giải được ở giải HCMUS-CTF 2025 vừa qua.

# Forensics/TLS Challenge
> Can you extract the flag from encrypted HTTPS?
> Author: Walky
![image](https://hackmd.io/_uploads/SJLNDZ0Ilx.png)

Ở bài này, ta có 1 file pcap và 1 file keylog. Ta sử dụng file keylog để decrypt HTTPS đã bị mã hóa TLS. 

![image](https://hackmd.io/_uploads/H1g4svWRUxe.png)
![image](https://hackmd.io/_uploads/rJfaP-RLle.png)

**Flag: HCMUS-CTF{tls_tr@ffic_@n@lysis_ch@ll3ng3}**

# Forensics/Trashbin
> Someone’s been treating my computer like a trash bin, constantly dumping useless files into it. But it seems he got careless and dropped a really important one in there. Even though he deleted it afterward, it might have been too late—hehe😏.
> Author: bachtam2001
![image](https://hackmd.io/_uploads/SkEgd-C8el.png)

Tiếp tục được cho 1 file pcap, ta mở nó lên để phân tích.
![image](https://hackmd.io/_uploads/H1UpuWCIee.png)

Ta thấy các file liên tục được gửi qua bằng giao thức SMB, ở des có nói đó là người gửi đã gửi nhầm 1 file quan trọng và sau đó cố xóa nó.

![image](https://hackmd.io/_uploads/BygGY-RUle.png)

Ta thấy status: CANCELLED => có vẻ như file bị gửi nhầm chính là file **flagishere_228.zip**, trích xuất nó ra và có được flag.

**Flag: HCMUS-CTF{pr0t3ct_y0ur_SMB_0r_d1e}**

# Forensics/Disk Partition
> Too many flags... but only one is real.
> Author: Walky
![image](https://hackmd.io/_uploads/Bkwe9ZR8xx.png)

Ta được cho 1 file disk, sử dụng autopsy để phân tích nó.

![image](https://hackmd.io/_uploads/H1cvj-0Lgx.png)

Ở phân vùng thứ 2 có 50 file và có vẻ như đều là fake flag.
Kiểm tra qua phân vùng thứ 3 thì có được flag real.
![image](https://hackmd.io/_uploads/HyQjjZ0Ulg.png)

**Flag: HCMUS-CTF{1gn0r3_+h3_n01$3_f1nd_m@c}**

# Forensics/File Hidden
> Relax and chill with this lo-fi track... but listen caffuly — there might be something hidden in the sound waves.
> Author: Walky
![image](https://hackmd.io/_uploads/rydl2-AIlg.png)

Ta được cho 1 file wav bài Thiên Lý Ơi của J97, mình đã thử sử dụng **Audacity** và **Sonic Visualiser** để phân tích nhưng không mang lại kết quả gì, mở lên nghe thử cũng không thấy gì có vẻ khả nghi.

Sau đó khi mình thử trích xuất LSB và bỏ qua 44 byte header thì có được thứ sau:
![image](https://hackmd.io/_uploads/SJu7sMC8gl.png)

Đây là code mình dùng để trích xuất:

```python=
with open("JACK_J97_｜_THIÊN_LÝ_ƠI.wav", "rb") as file:
    data = file.read()

with open("output.txt", "w") as f:
    for byte in range(44, len(data)):
        f.write(str(data[byte] & 1))
```

![image](https://hackmd.io/_uploads/ryjV9fCLgx.png)

Ở trên có vẻ chính là header của file zip `50 43 03 04`, sau đó mình điều chỉnh một chút rồi trích xuất file zip về và có được flag.

![image](https://hackmd.io/_uploads/ByIlnfCLel.png)

**Flag: HCMUS-CTF{Th13nLy_0i_J4ck_5M1ll10n}**