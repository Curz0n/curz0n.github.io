---
layout: post
title: 聊聊Websocket协议与另类的抓包方法
date: 2020-04-10 17:33:00 +0800
categories: Web安全
tag: 协议研究  
---

* content
{:toc}

{%raw%}  

## 0x00 背景  

某应用使用Websocket协议，且数据报文做了加密处理，使用burp抓包如下:  

![](/assets/images/2020-04-10-pyshark-websocket/1.png)  

本来以为可以根据以往套路直接写burp插件对报文进行解密操作，通过一番API文档查阅和测试，发现burp扩展不支持对Websocket协议的报文进行操作。[burp官方论坛](https://forum.portswigger.net/thread/websocket-api-07e77f9ee3dd58552eb770)在18年就有用户提出了需求，但API却迟迟没有更新开放。  

## 0x01 使用pyshark抓包  

[pyshark](https://github.com/KimiNewt/pyshark)是tshark的封装，而tshark就是神器Wireshark的命令行工具。根据背景需求，我们可以利用pyshark来嗅探Websocket数据包，拿到数据以后，再通过脚本对数据报文进行自定义操作。代码实现如下:  

```python
import pyshark


'''数据包嗅探'''
def capture(net,bpf):
    cap = pyshark.LiveCapture(interface=net, bpf_filter=bpf)
    for packet in cap.sniff_continuously():
        packet.tcp.raw_mode = True
        try:
            tcpPayload = packet.tcp.payload
        except AttributeError as e:
            pass
        port = packet.tcp.srcport
        #通过端口区分请求和响应
        if port == "0050":
            print("响应包:" + tcpPayload)
        else:
            print("请求包:" + tcpPayload)

def main():
    #网卡
    interface = 'en0'
    #bpf过滤器
    bpf_filter = "host **.**.**.**"
    capture(interface,bpf_filter)


if __name__ == '__main__':
	main()
```

以[Echo Test](http://websocket.org/echo.html)为例，如下所示，发送Websocket测试数据"hi websocket":  

![](/assets/images/2020-04-10-pyshark-websocket/2.png)  

运行脚本，效果如下  

![](/assets/images/2020-04-10-pyshark-websocket/3.png)  

同时使用burp抓取请求和响应包，请求包如下:  

![](/assets/images/2020-04-10-pyshark-websocket/4.png)  

响应包:  

![](/assets/images/2020-04-10-pyshark-websocket/5.png)  

通过对比分析发现，burp抓取的请求报文已经被自动解析，hex和脚本嗅探的流量不一样，响应报文同样也有所差异，脚本嗅探的报文头多了`0x81和0x0c`这段hex。  

## 0x02 解析Websocket协议  

要想搞清楚脚本嗅探的数据报文和burp抓取的报文为什么有差异，就需要先了解清楚Websocket协议的格式，
先看看Websocket数据帧格式:  

```
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-------+-+-------------+-------------------------------+
 |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
 |I|S|S|S|  (4)  |A|     (7)     |             (16/63)           |
 |N|V|V|V|       |S|             |   (if payload len==126/127)   |
 | |1|2|3|       |K|             |                               |
 +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
 |     Extended payload length continued, if payload len == 127  |
 + - - - - - - - - - - - - - - - +-------------------------------+
 |                               |Masking-key, if MASK set to 1  |
 +-------------------------------+-------------------------------+
 | Masking-key (continued)       |          Payload Data         |
 +-------------------------------- - - - - - - - - - - - - - - - +
 :                     Payload Data continued ...                :
 + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
 |                     Payload Data continued ...                |
 +---------------------------------------------------------------+
```  

具体含义如下  

域 | 说明 |
-|-
FIN | 1bit，是否为信息的最后一帧 |
RSV 1-3 | 1bit，备用，默认为0 |
opcode | 4bit，帧类型 |
MASK | 1bit 掩码，是否加密数据。<br>客户端发送给服务端时，mask必须为1，否则断开连接。<br>服务端发送给客户端时，mask必须为0，否则断开连接。 |
payload length | 7bit，传输数据长度，以字节为单位。<br>当7bit数字等于126时，其后的2个字节也表示数据长度。<br>当7bit数字等于127时，其后的8个字节也表示数据长度。 |
Masking-key | 0或32 bit掩码值(Mask为1时才有) |
Playload data | 长度为Payload len的数据，如果有掩码，需要用Masking-Key来异或解密 |  

根据Websocket协议格式，实现Websocket协议解析代码如下:  

```python  
'''解析websocket协议'''
def parseWebsocket(tcpPayload):
    #获取websocket数据段长度
    payload_len = tcpPayload[1] & 0x7F
    mask_flag = tcpPayload[1] & 0x80
    #客户端发送给后端时，mask必须为1
    if mask_flag:
        if payload_len == 126:
            extend_payload_len = tcpPayload[2:4]
            mask = tcpPayload[4:8]
            data = tcpPayload[8:]
        elif payload_len == 127:
            extend_payload_len = tcpPayload[2:10]
            mask = tcpPayload[10:14]
            data = tcpPayload[14:]
        else:
            extend_payload_len = None
            mask = tcpPayload[2:6]
            data = tcpPayload[6:]
        decodeData = bytearray()
        for i in range(len(data)):
            chunk = data[i] ^ mask[i % 4]
            decodeData.append(chunk)
        return decodeData
    #服务器发送给前端时，mask必须为0
    else:
        if payload_len == 126:
            extend_payload_len = tcpPayload[2:4]
            data = tcpPayload[4:]
        elif payload_len == 127:
            extend_payload_len = tcpPayload[2:10]
            data = tcpPayload[10:]
        else:
            data = tcpPayload[2:]
        return data
```  

结合解析代码，运行脚本，效果如下，成功拿到了使用Websocket协议传输的数据报文:  

![](/assets/images/2020-04-10-pyshark-websocket/6.png)  

## 0x03 结语  

通过这次协议分析，对Websocket协议有了进一步的认识，同时了解到使用脚本抓包的另类方式，笔者水平有限，文章内容如有错误的地方，还请不吝赐教。  

**References:**  

[Websocket协议解析](https://blog.csdn.net/tianhai110/article/details/68059473)  


**版权声明：转载请注明出处，谢谢。[https://github.com/curz0n](https://github.com/curz0n)**  

{%endraw%}  