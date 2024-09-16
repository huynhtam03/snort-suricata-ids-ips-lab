Here is the consolidated **README.md** based on the content provided from your lab report file:

---

# **Báo cáo LAB về IDS/IPS**

## **Mục lục**

1. [Giới thiệu về IDS/IPS](#giới-thiệu-về-idsips)
2. [Mục tiêu thí nghiệm](#mục-tiêu-thí-nghiệm)
3. [Thiết lập mạng và hệ thống thử nghiệm](#thiết-lập-mạng-và-hệ-thống-thử-nghiệm)
4. [Kịch bản tấn công và ngăn chặn](#kịch-bản-tấn-công-và-ngăn-chặn)
    - 4.1 [Tấn công Ping of Death](#41-tấn-công-ping-of-death)
    - 4.2 [Tấn công Scanning Port](#42-tấn-công-scanning-port)
    - 4.3 [Tấn công Brute Force vào PORT 22](#43-tấn-công-brute-force-vào-port-22)
    - 4.4 [Phát hiện và ngăn chặn tấn công UDP Testing](#44-phát-hiện-và-ngăn-chặn-tấn-công-udp-testing)
    - 4.5 [Cảnh báo và ngăn chặn HTTP Test](#45-cảnh-báo-và-ngăn-chặn-http-test)
    - 4.6 [Các kịch bản tấn công TCP/UDP](#46-các-kịch-bản-tấn-công-tcpudp)
5. [Cấu hình Snort trên pfsense](#cấu-hình-snort-trên-pfsense)
6. [Kết luận](#kết-luận)

---

## **1. Giới thiệu về IDS/IPS**

- **Intrusion Detection System (IDS)** giám sát và phát hiện các hành vi xâm nhập hoặc tấn công mạng.
- **Intrusion Prevention System (IPS)** có khả năng phát hiện và ngăn chặn ngay lập tức các cuộc tấn công vào hệ thống mạng.
- **Snort** là công cụ IDS/IPS mã nguồn mở được triển khai trên **pfsense**, cho phép phát hiện và ngăn chặn các cuộc tấn công từ xa.

---

## **2. Mục tiêu thí nghiệm**

- Cài đặt và cấu hình **Snort IDS/IPS** trên **pfsense**.
- Thực hiện các kịch bản tấn công từ attacker đến victim và sử dụng Snort để phát hiện, ngăn chặn các cuộc tấn công đó.
- Đưa ra các kịch bản tấn công khác nhau như **Ping of Death**, **Scanning Port**, và **Brute Force Attack** để đánh giá hệ thống bảo mật.

---

## **3. Thiết lập mạng và hệ thống thử nghiệm**

| **Thiết bị**   | **Hệ điều hành**    | **Địa chỉ IP**      | **Mô tả**          |
|----------------|---------------------|---------------------|--------------------|
| Kali Linux     | Kali Linux           | 192.168.11.129/24   | Máy tấn công       |
| pfsense        | pfsense              | 192.168.11.139/24 (WAN) | IDS/IPS           |
|                |                      | 192.168.10.100/24 (LAN) |                 |
|                |                      | 192.168.20.10/24 (DMZ) |                 |
| Victim         | Ubuntu 8.04          | 192.168.20.19       | Máy nạn nhân       |
| User           | Windows 10           | 192.168.10.8        | Máy người dùng     |

Các hệ thống này được kết nối qua môi trường mạng ảo, mô phỏng một hệ thống mạng thực tế. **Snort** được triển khai trên **pfsense** để giám sát và bảo vệ các máy chủ trong mạng.

---

## **4. Kịch bản tấn công và ngăn chặn**

### **4.1 Tấn công Ping of Death**

- **Mô tả**: Tấn công làm tê liệt máy nạn nhân bằng cách gửi các gói tin ICMP quá lớn.
- **Công cụ**: **ping**
- **Lệnh tấn công**:
    ```bash
    ping 192.168.20.19 -s 10000
    ```
- **Rule Snort**:
    ```bash
    alert icmp any any -> $HOME_NET any (msg:"--> Ping of death attack!"; dsize:>10000; gid:1000001; sid:1000001; rev:1;)
    ```

---

### **4.2 Tấn công Scanning Port**

- **Mô tả**: Quét các cổng mở trên máy nạn nhân để tìm lỗ hổng bảo mật.
- **Công cụ**: **nmap**
- **Lệnh tấn công**:
    ```bash
    nmap -p- 192.168.20.19
    ```
- **Rule Snort**:
    ```bash
    alert tcp any any -> 192.168.20.19 81 (msg:"Scanning Port 81"; sid:1000005; rev:1;)
    ```

---

### **4.3 Tấn công Brute Force vào PORT 22**

- **Mô tả**: Tấn công brute-force vào dịch vụ SSH chạy trên cổng 22 của máy nạn nhân.
- **Công cụ**: **Hydra**
- **Lệnh tấn công**:
    ```bash
    hydra -l admin -P passwords.txt 192.168.20.19 ssh
    ```
- **Rule Snort**:
    ```bash
    alert tcp any any -> any 22 (msg:"SSH connection attempt"; sid:1000004; rev:1;)
    ```

---

### **4.4 Phát hiện và ngăn chặn tấn công UDP Testing**

- **Mô tả**: Tấn công bằng các gói tin UDP để kiểm tra mức độ phản ứng của hệ thống nạn nhân.
- **Rule Snort**:
    ```bash
    alert udp any any -> any any (msg:"UDP Test Attack Detected"; sid:1000006; rev:1;)
    ```
- **Rule ngăn chặn**:
    ```bash
    drop udp any any -> any any (msg:"Blocking UDP Test"; sid:1000006; rev:1;)
    ```

---

### **4.5 Cảnh báo và ngăn chặn HTTP Test**

- **Mô tả**: Gửi các yêu cầu HTTP độc hại nhằm tấn công vào dịch vụ web của nạn nhân.
- **Rule Snort**:
    ```bash
    alert tcp any any -> $HOME_NET 80 (msg:"HTTP Test Attack Detected"; sid:1000005; rev:1;)
    ```
- **Rule ngăn chặn**:
    ```bash
    drop tcp any any -> $HOME_NET 80 (msg:"Blocking HTTP Test"; sid:1000005; rev:1;)
    ```

---

### **4.6 Các kịch bản tấn công TCP/UDP**

- **TCP Connect Attack**:
    ```bash
    drop tcp any any -> $HOME_NET any (msg:"TCP Connect Scan Detected"; sid:1000001; rev:1;)
    ```

- **TCP SYN Attack**:
    ```bash
    alert tcp any any -> $HOME_NET any (msg:"TCP SYN Scan Detected"; sid:1000002; rev:1;)
    ```

- **UDP Connect Attack**:
    ```bash
    alert udp any any -> $HOME_NET any (msg:"UDP Connect Scan Detected"; sid:1000005; rev:1;)
    ```

---

## **5. Cấu hình Snort trên pfsense**

1. **Cài đặt Snort**:
   - Truy cập vào **System -> Package Manager -> Available Packages**, sau đó tìm kiếm và cài đặt **Snort**.
  
2. **Thêm các rule phát hiện và ngăn chặn**:
   - Ví dụ: Rule ngăn chặn tấn công brute-force vào SSH:
    ```bash
    drop tcp any any -> any 22 (msg:"Blocking SSH Brute Force"; sid:1000004; rev:1;)
    ```

---

## **6. Kết luận**

Trong lab này, chúng ta đã thiết lập thành công hệ thống **IDS/IPS** trên **pfsense** với công cụ **Snort** để phát hiện và ngăn chặn các cuộc tấn công mạng phổ biến. Hệ thống đã được kiểm tra qua các kịch bản tấn công như **Ping of Death**, **Brute Force Attack**, và **HTTP Test**.

---

This **README.md** summarizes the complete lab setup, including network configuration, Snort installation, attack scenarios, and Snort rules for detecting and preventing various network attacks.
