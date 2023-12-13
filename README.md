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
- [ ] handleIp
- [ ] lookup