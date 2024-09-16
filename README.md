
# **Báo cáo LAB về IDS/IPS**


### ***Mục lục***

[1. Giới thiệu về IDS/IPS ](#1)

[2. Mục tiêu ](#2)

[3.	Thiết lập mạng và hệ thống thử nghiệm](#3)

[4. Kịch bản tấn công và ngăn chặn](#4)

- [4.1.	Ping of Death](#4.1)

- [4.2.	Scanning Port ](#4.2)

- [4.3. Connection SSH ](#4.3)

- [4.4. UDP Testing ](#4.4)

- [4.5. HTTP Test ](#4.5)

- [4.6. Các kịch bản tấn công TCP/UDP ](#4.6)

- [4.7. SYN Flood ](#4.7)

- [4.8. SQL injection ](#4.8)


---

<a name = '1'></a>
# 1. Giới thiệu về IDS/IPS

- **Intrusion Detection System (IDS)** giám sát và phát hiện các hành vi xâm nhập hoặc tấn công mạng.
- **Intrusion Prevention System (IPS)** có khả năng phát hiện và ngăn chặn ngay lập tức các cuộc tấn công vào hệ thống mạng.
- **Snort** là công cụ IDS/IPS mã nguồn mở được triển khai trên **pfsense**, cho phép phát hiện và ngăn chặn các cuộc tấn công từ xa.

---
<a name = '2'></a>
# 2. Mục tiêu thí nghiệm

- Cài đặt và cấu hình **Snort IDS/IPS** trên **pfsense**.
- Thực hiện các kịch bản tấn công từ attacker đến victim và sử dụng Snort để phát hiện, ngăn chặn các cuộc tấn công đó.
- Đưa ra các kịch bản tấn công khác nhau như **Ping of Death**, **Scanning Port**, và **Brute Force Attack** để đánh giá hệ thống bảo mật.

---
<a name = '3'></a>
# 3. Thiết lập mạng và hệ thống thử nghiệm
![image](https://github.com/user-attachments/assets/6ffb855d-4f53-42e2-b54c-a1b669fdd82a)


| **Thiết bị**   | **Hệ điều hành**    | **Địa chỉ IP**      | **Mô tả**          |
|----------------|---------------------|---------------------|--------------------|
| Kali Linux     | Kali Linux           | 192.168.11.129/24   | Máy tấn công       |
| pfsense        | pfsense              | 192.168.11.139/24 (WAN) | IDS/IPS           |
|                |                      | 192.168.10.100/24 (LAN) |                 |
|                |                      | 192.168.20.10/24 (DMZ) |                 |
| Victim         | Ubuntu 8.04          | 192.168.20.19       | Máy nạn nhân       |
| User           | Windows 10           | 192.168.10.8        | Máy người dùng     |

Các hệ thống này được kết nối qua môi trường mạng ảo, mô phỏng một hệ thống mạng thực tế. **Snort** được triển khai trên **pfsense** để giám sát và bảo vệ các máy chủ trong mạng.

**Kiểm tra kết nối giữa các máy**
![image](https://github.com/user-attachments/assets/58a8c985-f744-4503-9bd5-bac86c44c192)
![image](https://github.com/user-attachments/assets/448c30ce-5dd8-48cd-9308-9fab562f4ba5)
![image](https://github.com/user-attachments/assets/8733b0de-6de3-4356-9cbd-58d086506a99)

**Cài đặt Snort trên pfsense**
System -> package manager
![image](https://github.com/user-attachments/assets/71549be8-3e4c-4a4e-9dfd-6d5221d1627c)
-> Available Packages
![image](https://github.com/user-attachments/assets/7cb2cef5-3c19-4526-a9de-b28c6799826f)

---
<a name = '4'></a>
# 4. Kịch bản tấn công và ngăn chặn

<a name = '4.1'></a>
## 4.1 Ping of Death

- **Mô tả**: Tấn công làm tê liệt máy nạn nhân bằng cách gửi các gói tin ICMP quá lớn.
- **Công cụ**: **ping**
- **Lệnh tấn công**:
    ```bash
    ping 192.168.20.19 -s 10000
    ```
  Lưu lượng ICMP trên Wireshark của máy Victim
![image](https://github.com/user-attachments/assets/1062c6e9-5434-460a-b768-c4af6d7b0865)

- **Rule Snort**:
    ```bash
    alert icmp any any -> $HOME_NET any (msg:"--> Ping of death attack!"; dsize:>10000; gid:1000001; sid:1000001; rev:1;)
    ```
![image](https://github.com/user-attachments/assets/8d440fe8-978a-45b2-a1f7-c7a9a1a75dba)

 ```bash
    drop icmp any any -> $HOME_NET any (msg:"--> chan Ping of death attack!"; dsize:>10000; gid:1000002; sid:1000002;rev:1;)
```
![image](https://github.com/user-attachments/assets/5bb8152e-f832-44af-ab77-1c625a282430)

---

<a name = '4.2'></a>
## 4.2 Scanning Port

- **Mô tả**: Quét các cổng mở trên máy nạn nhân để tìm lỗ hổng bảo mật.
- **Công cụ**: **nmap**
- **Lệnh tấn công**:
    ```bash
    nmap -p- 192.168.20.19
    ```
![image](https://github.com/user-attachments/assets/ba6de1e2-7206-47da-abe7-5174d4b91970)

- **Rule Snort**:
    ```bash
    alert tcp any any -> 192.168.20.19 81 (msg:"Scanning Port 81"; sid:1000005; rev:1;)
    ```
![image](https://github.com/user-attachments/assets/f4843d2f-34a9-4181-9ceb-f5f4845f98c6)

 ```bash
    drop tcp any any -> 192.168.20.19 81 (msg:"Scanning Port 81"; sid:1000006; rev:1;)
```

![image](https://github.com/user-attachments/assets/ddf48850-8d55-445b-8e99-28a0477058f0)

---
<a name = '4.3'></a>
## 4.3 Connection SSH

- **Mô tả**: Connect vào dịch vụ SSH chạy trên cổng 22 của máy nạn nhân.
- **Lệnh tấn công**:
    ```bash
    telnet 192.168.20.19 22
    ```
- **Rule Snort**:
    ```bash
    alert tcp any any -> any 22 (msg:"ssh connection=>Attempt"; sid:1000004;)
    ```
![image](https://github.com/user-attachments/assets/10815315-77e3-4e49-8354-7d99c636e375)

 ```bash
    drop tcp any any -> any 22 (msg:"chan ssh connection=>Attempt"; sid:1000004;)
 ```
![image](https://github.com/user-attachments/assets/ea236aa5-1f3b-400f-9fb0-9f7d9f947a4d)

---
<a name = '4.4'></a>
## 4.4 UDP Testing

- **Mô tả**: Tấn công bằng các gói tin UDP để kiểm tra mức độ phản ứng của hệ thống nạn nhân.
![image](https://github.com/user-attachments/assets/744e1f36-3f65-4e3b-9f47-b6cdf5cf7778)

- **Rule Snort**:
    ```bash
    alert udp any any -> any any (msg:"UDP Test Attack Detected"; sid:1000006; rev:1;)
    ```
![image](https://github.com/user-attachments/assets/9da55051-1e1f-401a-90e1-73b539a1a723)

- **Rule ngăn chặn**:
    ```bash
    drop udp any any -> any any (msg:"Blocking UDP Test"; sid:1000006; rev:1;)
    ```
![image](https://github.com/user-attachments/assets/4c3bedaa-865e-4c4a-9da1-0ecbc2856362)

---
<a name = '4.5'></a>
## 4.5 HTTP Test

- **Mô tả**: Gửi các yêu cầu HTTP độc hại nhằm tấn công vào dịch vụ web của nạn nhân.
![image](https://github.com/user-attachments/assets/19bf78fa-498a-4b93-81a4-24cbba33ac51)

- **Rule Snort**:
    ```bash
    alert tcp any any -> $HOME_NET 80 (msg:"HTTP Test Attack Detected"; sid:1000005; rev:1;)
    ```
![image](https://github.com/user-attachments/assets/a4456ada-ea64-42f0-8dcd-270c792eb85a)
- **Rule ngăn chặn**:
    ```bash
    drop tcp any any -> $HOME_NET 80 (msg:"Blocking HTTP Test"; sid:1000005; rev:1;)
    ```

![image](https://github.com/user-attachments/assets/f25fceb7-3807-497f-8c0f-564e5e9908b3)

---
<a name = '4.6'></a>
## 4.6 Các kịch bản tấn công TCP/UDP

- **TCP Connect Attack**:
![image](https://github.com/user-attachments/assets/2f7249b5-35a7-4eb1-a072-d21634a588ca)

    ```bash
    alert tcp any any -> $HOME_NET any (msg:"TCP Connect Scan Detected"; sid:1000001; rev:1;)
    ```

![image](https://github.com/user-attachments/assets/bc730fbb-8b40-4b5f-a3b5-6fac8105614f)

   ```bash
    drop tcp any any -> $HOME_NET any (msg:"TCP Connect Scan Detected"; sid:1000001; rev:1;)
   ```

![image](https://github.com/user-attachments/assets/93b1132e-540d-4946-a307-e6058db4581f)


- **TCP SYN Attack**:
  ![image](https://github.com/user-attachments/assets/0eb12695-98eb-44c2-9d6c-efc45ce5bf02)

    ```bash
    alert tcp any any -> $HOME_NET any (msg:"TCP SYN Scan Detected"; sid:1000002; rev:1;)
    ```
![image](https://github.com/user-attachments/assets/e976c91c-defd-42e2-8844-a7d0ed37dd3d)

 ```bash
   drop tcp any any -> $HOME_NET any (msg:"chan TCP SYN Scan Detected"; flags:S; sid:1000002; rev:1;)
 ```
![image](https://github.com/user-attachments/assets/ce16b1ef-334b-4d5d-a7f0-3baab8001c5d)


- **TCP ACK Attack**:
  ![image](https://github.com/user-attachments/assets/f023c03a-aa49-4f64-8069-698243631c07)

    ```bash
    alert tcp any any -> $HOME_NET any (msg:"TCP ACK Scan Detected"; flags:A; sid:1000004; rev:1;)
    ```
![image](https://github.com/user-attachments/assets/6e658c74-b7e8-40b9-bdf5-65341fd647f4)
 ```bash
    drop tcp any any -> $HOME_NET any (msg:"chan TCP ACK Scan Detected"; flags:A; sid:1000009; rev:1;)
 ```
![image](https://github.com/user-attachments/assets/e6ca4a90-f03b-4182-ad98-5b043a5cc746)

- **UDP Connect Attack**:
  ![image](https://github.com/user-attachments/assets/41730883-0381-486b-959c-c50daad3acf6)
   ```bash
    alert udp any any -> $HOME_NET any (msg:"UDP Connect Scan Detected"; sid:1000005; rev:1;)
    ```
![image](https://github.com/user-attachments/assets/69d73928-9d36-4361-8b23-bd3e3aa151b8)

   ```bash
    drop udp any any -> $HOME_NET any (msg:"chan UDP Connect Scan Detected"; sid:1000008; rev:1;)
   ```
![image](https://github.com/user-attachments/assets/a4d6b8d1-ff43-4d68-8eb0-70a4147aa722)

<a name = '4.7'></a>
## 4.7 SYN Flood
 **Mô tả**: Sử dụng công hping3 đế tấn công SYN Flood.
- **Công cụ**: **hping3**
- **Lệnh tấn công**:
  ```bash
    sudo hping3 --flood --rand-source -S -p 80 192.168.20.19
   ```
![image](https://github.com/user-attachments/assets/7338df79-1211-40a4-8bf0-0a88e1341f18)

   ```bash
    alert tcp any any -> $HOME_NET any (msg:"Syn Flood Detected"; flags:S; threshold:type threshold, track by_src, count 100, seconds 10; sid:1000008; rev:1;)
   ```
![image](https://github.com/user-attachments/assets/69639b4e-4b6e-45b5-8af9-0e1788fcd04d)

 ```bash
    drop tcp any any -> $HOME_NET any (msg:"chan Syn Flood Detected"; flags:S; threshold:type threshold, track by_src, count 100, seconds 10; sid:1000008; rev:1;)
   ```

![image](https://github.com/user-attachments/assets/09484c54-5270-47f1-9fc4-84c7048d75a8)

---
<a name = '4.8'></a>
## 4.8. SQL Injection
1.	Tạo payload.txt 
2.	Tạo testsqlinjection.sh
3.	Cấu hình file

```bash
#!/bin/bash
#URL của trang web bạn muốn kiểm thử
url="http://192.168.20.19/dvwa/login.php"
 Đọc từng dòng trong tệp payloads.txt và gửi yêu cầu POST
while IFS= read -r payload
do
#Gửi yêu cầu HTTP POST với payload
response=$(curl -s -o /dev/null -w "%{http_code}" -X POST -d "username=${payload}&password=anypassword" "$url")
#Kiểm tra mã trạng thái HTTP và hiển thị phản hồi
echo "Payload: $payload => HTTP Status: $response"
done < "payloads.txt"
```

5.	Chạy file 
![image](https://github.com/user-attachments/assets/7c40c9d2-a958-41c6-b76f-ee47fe0aca49)

-> hiển thị cảnh báo
![image](https://github.com/user-attachments/assets/67f4c099-bf83-488a-a114-0fd1c930159c)

```bash
drop tcp any any -> any 80 (msg:"chan SQL Injection Attempt"; flow:to_server,established; content:"'"; nocase; content:" or "; nocase; pcre:"/(\%27)|(\')|(\-\-)|(\%23)|(#)/i"; classtype:web-application-attack; sid:1000001; rev:1;)
```
![image](https://github.com/user-attachments/assets/ace81c16-771e-4752-acd8-5dd22bf39c8e)
