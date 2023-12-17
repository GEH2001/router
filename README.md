# router

## Usage
> 启动pox
```bash
$ /opt/pox/pox.py --verbose ucla_cs118
```

> 启动Mininet
```bash
$ chmod +x run.py
$ sudo ./run.py
```

> 启动router
```bash
$ make
$ ./router
```

> 自动化评测, 先启动pox和router
```bash
$ chmod +x autograde.py
$ sudo ./autograde.py
```

## TODO
- [x] handleArp
- [x] handleIp
- [x] sendIpDatagram
- [x] sendIcmpType3
- [x] sendIcmpEchoReply
- [x] lookup
- [x] handle ARP cache events
- [ ] traceroute


## Problems
1. ICMP消息从哪个接口发出？假如以太网帧F1到达路由器接口A，解封装得
   到IP数据报，发现TTL为0/1，那么返回一个ICMP（超时消息），将其封
   装在以太网帧F2发出，F2的帧头和F1应该对应吗，还是应该通过路由表和
   ARP表查询得到应该从哪个接口发出，然后再设置对应的帧头
2. `ticker`中`periodic...`死锁，因为后者可能调用router.sendIpDatagram
   其中lookup会请求锁，即导致死锁
3. `periodic...`如果发送超过5次，返回ICMP消息，新的IP数据报设为A，封装后的以太网帧设为E，A的源IP地址如何？E的源MAC地址如何？

## 校验和
计算校验和之前都应该先将`checksum`字段置为0，因为这个字段不参与校验和计算

## IP

只有IP头部参与校验和计算

`version`和`header length`2个字段分别为4和5，在构建IP数据报的时候必须赋值

`total length`是整个IP数据报的长度

## ICMP
路由器生成ICMP消息时，IP数据报的源地址字段可以是路由器任意接口的ip地址

ICMP头部 + ICMP数据 都参与校验和计算

以下所说的 Echo Reply/Request 指的是ICMP报文，不包含IP头部

Echo Reply 数据部分应该和 Echo Request 对应，因为有时间戳用于计算time

Echo Reply 头部的id和seq需要和Echo Request对应，用于发送方区分ICMP报文

Echo Reply 和 Echo Request 不同的字段只有 ICMP头部的 type 和 checksum



## Reference
[cs118-router-THSS](https://github.com/finall1008/cs118-router-THSS/)

[cs118-router-project](https://github.com/zbw970527/cs118-router-project)