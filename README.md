# router

## 目录结构
```
router
├─ 2020010548.tar.gz			# 作业提交压缩文件
├─ README.md					
├─ code							# 源代码
└─ doc
       ├─ project_spec.pdf		# 作业要求
       ├─ report.md				# 作业文档
       ├─ screenshot.md			# 程序运行截图
```

## Usage
> debug

分别在3个命令行窗口启动 pox mininet router, 然后在mininet窗口发送指令如`client ping server1`



> autograde

先启动 pox router，然后执行脚本

```bash
$ chmod +x autograde.py
$ sudo ./autograde.py
```

如果`sudo ./autograde.py`提示错误信息如下

```
/usr/bin/env: 'python\r': No such file or directory
```
这是因为run.py文件可能在windows上打开过，导致其换行符变为了CRLF

但是在linux系统文件的换行符为LF

解决办法是转变换行符格式，linux命令行输入`dos2unix autograde.py`


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
这是因为run.py文件可能在windows上打开过，导致其换行符变为了CRLF

但是在linux系统文件的换行符为LF

解决办法是转变换行符格式，linux命令行输入`dos2unix run.py`



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



## Reference
[cs118-router-THSS](https://github.com/finall1008/cs118-router-THSS/)

[cs118-router-project](https://github.com/zbw970527/cs118-router-project)

第一个写的比较好，第二个很多case都没考虑到