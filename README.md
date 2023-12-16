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


## Problems
1. ICMP消息从哪个接口发出？假如以太网帧F1到达路由器接口A，解封装得
   到IP数据报，发现TTL为0/1，那么返回一个ICMP（超时消息），将其封
   装在以太网帧F2发出，F2的帧头和F1应该对应吗，还是应该通过路由表和
   ARP表查询得到应该从哪个接口发出，然后再设置对应的帧头
2. `ticker`中`periodic...`死锁，因为后者可能调用router.sendIpDatagram
   其中lookup会请求锁，即导致死锁
3. `periodic...`如果发送超过5次，返回ICMP消息，新的IP数据报设为A，封装后的以太网帧设为E，A的源IP地址如何？E的源MAC地址如何？

## Reference
[cs118-router-THSS](https://github.com/finall1008/cs118-router-THSS/)

[cs118-router-project](https://github.com/zbw970527/cs118-router-project)