nbscan
===

nbscan is a NetBIOS discovery tool written in Go.

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
$ nbscan -m 192.168.0.0/24
```
