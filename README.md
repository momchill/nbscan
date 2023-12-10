nbscan
===

**nbscan** is a NetBIOS discovery tool written in Go.

## Download

Binary packages are available [here](https://github.com/momchill/nbscan/releases/latest).

## Install

If you have Go installed, you can build your own binary by running:
```
$ go build nbscan.go
```

## Usage

```
Usage: nbscan [options] <net to scan> ...

Options:
	-json	Output json format
	-m   	Print MAC address
	-q    	Suppress error messages
	-r   	Set the maximum packets per second rate. 0 disables rate limiter (default 250)
	-t   	Set the maximum timeout / wait time for response in seconds (default 1)
	-v    	Log more info to stderr
```
	
### Local Network Discovery
Identify computers on the local network.
	
```
$ nbscan 192.168.0.0/24
```

Show MAC addresses and vendor of the LAN card:

```
$ nbscan -m 192.168.0.0/24
```

Fast scan network, without throttle:

```
$ nbscan -m -r 0 192.168.0.0/24
```

Example output:
```
192.168.0.1    bc:5f:f4:c7:93:72  (ASRock Incorporati) WORKGROUP\PETER
192.168.0.2    88:d7:f6:c4:56:e6  (ASUSTek COMPUTER I) WORKGROUP\JOHN [10.15.20.39]
192.168.0.3    50:eb:f6:22:64:47  (ASUSTek COMPUTER I) WORKGROUP\SERVER1
192.168.0.4    1c:6f:65:d7:85:c5  (GIGA-BYTE TECHNOLO) WORKGROUP\SERVER2 [10.15.20.80 172.23.64.1]
192.168.0.5    3c:2a:f4:fa:59:8b  (Brother Industries) WORKGROUP\PRINTER1
192.168.0.6    f8:32:e4:a2:5e:1a  (ASUSTek COMPUTER I) WORKGROUP\BROWN [172.29.32.1 172.18.32.1]
192.168.0.7    14:da:e9:0e:a6:6f  (ASUSTek COMPUTER I) WORKGROUP\PRINTER2 [10.15.20.48 192.168.96.1]
```