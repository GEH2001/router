# router

## Usage
> debug

分别在3个命令行窗口启动 pox mininet router, 然后在mininet窗口发送指令如`client ping server1`



> autograge

先启动 pox router，然后执行脚本

```bash
$ chmod +x autograde.py
$ sudo ./autograde.py
```



**启动pox**

```bash
$ /opt/pox/pox.py --verbose ucla_cs118
```



**启动Mininet**

```bash
$ chmod +x run.py
$ sudo ./run.py
```

如果`sudo ./run.py`提示错误信息如下

```
/usr/bin/env: 'python\r': No such file or directory
```
这是因为autograde.py文件可能在windows上打开过，导致其换行符变为了CRLF

但是在linux系统文件的换行符为LF

解决办法是转变换行符格式，linux命令行输入`dos2unix autograde.py`



**启动router**

```bash
$ make
$ ./router
```


## TODO
- [x] handleArp
- [x] handleIp
- [x] sendIpDatagram
- [x] sendIcmpType3
- [x] sendIcmpEchoReply
- [x] lookup
- [x] handle ARP cache events


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

第一个写的比较好，第二个很多case都没考虑到