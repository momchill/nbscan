package main

import (
	"fmt"
	"net"
	"time"
	"os"
	"syscall"
	"flag"
	"strings"
	"errors"
	"bytes"
	"math"
	"encoding/binary"
	"runtime"
	"path/filepath"
	"encoding/csv"
)

// Exmaple data that is used during NB dialog:
//
// NBSTAT query message:
//  00 01  TRX ID
//  00 00  FLAGS
//  00 01 00 00 00 00 00 00  COUNTER (1Q only)
//  20 434b414141414141414141414141414141414141414141414141414141414141 00  QUERY '*'
//  00 21 00 01  NBSTAT (0x21) IN (0x01)
//
// NBSTAT positive response:
//  00 01  TRX ID
//  84 00  AA RESPONSE
//   00 00 00 01 00 00 00 00  COUNTER (1A only)
//  20 434b414141414141414141414141414141414141414141414141414141414141 00
//  00 21 00 01  NBSTAT (0x21) IN (0x01)
//  00 00 00 00
//  00 41  RDLEN
//    01   NUM_NAMES
//      4d4143424f4f4b50524f2d46364633 00 64 00
//  f0 18 98 45 f6 f3
//  00000000000000000000000000000000000000000000000000000000000000000000000000000000
//
// NBSTAT negative response:
//  00 01
//  84 03  Error 0x03 - invalid name
//  00 00 00 00 00 00 00 00
//  20 434b414141414141414141414141414141414141414141414141414141414141 00
//  00 0a 00 01
//  00 00 00 00
//  00


var QUERY_NBSTAT = hex2byte("0001 0000 0001 0000 0000 0000 20 434b414141414141414141414141414141414141414141414141414141414141 00 0021 0001")
var QUERY_NB     = hex2byte("0002 0100 0001 0000 0000 0000 20 434b414141414141414141414141414141414141414141414141414141414141 00 0020 0001")


const TypeNBSTAT    uint16 = 0x21
const TypeNB        uint16 = 0x20

const ClassIN       uint16 = 0x01

type NBHeader struct {
	TransactionID   uint16
	Flags           uint16
	QDCount         uint16
	ANCount         uint16
	NSCount         uint16
	ARCount         uint16
}

type NBAnswer struct {
	Header          NBHeader
	RecordName      [34]byte
	RecordType      uint16
	RecordClass     uint16
	RecordTTL       uint32
	RecordLength    uint16
}

type NBName struct {
	Name [15]byte
	Type uint8
	Flag uint16
}

type NBAddress struct {
	Flag    uint16 // 0x6000
	Address [4]uint8
}

type NBResult struct {
	UserName     string
	HostName     string
	Domain       string
	Addresses  []string
	MACAddr      string
	Names      []NBName
}

var results map[string]*NBResult = make(map[string]*NBResult)


func hex2byte(hex string) []byte {
	if strings.Contains(hex, " ") { hex = strings.ReplaceAll(hex, " ", "") }
	b := make([]byte, len(hex)/2)
	fmt.Sscanf(hex, "%x", &b)
	return b
}

func log(msg string, args ...any) {
	if !*quite {
		fmt.Fprintf(os.Stderr, "\r\x1b[31m[!] "+msg+"\x1b[0m\n", args...)
	}
}

var macDB map[string]string = make(map[string]string)

func readMacDB() {
	// MAC database is downloaded from here:
	//   https://maclookup.app/downloads/csv-database
	f, err := os.Open(strings.Replace(os.Args[0], ".exe", "", 1) + ".mac")
	if err != nil {
		if *verbose { log("Cannot open file: %s", err) }
		return
	}
	
	// remember to close the file at the end of the program
	defer f.Close()
	
	// read csv values using csv.Reader
	csvReader := csv.NewReader(f)
	data, err := csvReader.Read()
	for err == nil {
		macDB[strings.ToLower(data[0])] = data[1]
		data, err = csvReader.Read()
	}
}

func processCIDR(ip string, o chan<- []byte) {
	if len(ip) == 0 {
		return
	}
	
	// We may receive bare IP addresses, not CIDRs sometimes
	if !strings.Contains(ip, "/") {
		if strings.Contains(ip, ":") {
			ip = ip + "/128"
		} else {
			ip = ip + "/32"
		}
	}
	
	_, cidr, err := net.ParseCIDR(ip)
	if err != nil {
		log("Invalid CIDR %s: %s\n", cidr, err.Error())
		return
	}
	
	// Verify IPv4 for now
	ip4 := cidr.IP.To4()
	if ip4 == nil {
		log("Invalid IPv4 CIDR %s\n", ip)
		return
	}
	
	mask_base, mask_total := cidr.Mask.Size()
	rangeStart := binary.BigEndian.Uint32(cidr.IP)
	rangeEnd := rangeStart + uint32(math.Pow(2, float64(mask_total-mask_base))) // size of net
	ipb := make([]byte, 4)
	if !*quite && !*json { fmt.Printf("Processing %d IPs ...  ", rangeEnd-rangeStart) }
	for ipi := rangeStart; ipi < rangeEnd; ipi++ {
		binary.BigEndian.PutUint32(ipb, ipi)
		o <- ipb
	}
}

func parseReply(bbuff []byte, result *NBResult) uint16 {

	buff := bytes.NewBuffer(bbuff)
	resp := NBAnswer{}

	binary.Read(buff, binary.BigEndian, &resp)

	if resp.Header.QDCount != 0 || resp.Header.ANCount == 0 {
		return 0
	}

	// Names
	if resp.RecordType == TypeNBSTAT {
		var rcnt byte
		binary.Read(buff, binary.BigEndian, &rcnt)

		nbname := NBName{}
		for ; 0 < rcnt; rcnt-- {
			binary.Read(buff, binary.BigEndian, &nbname)
			name := strings.TrimSpace(strings.Replace(string(nbname.Name[:]), "\x00", "", -1))
			result.Names = append(result.Names, nbname)

			switch (nbname.Type) {
				case 0x00:
					if (nbname.Flag & 0x8000) == 0 {
						result.HostName = name
					} else {
						result.Domain = name
					}
				case 0x03:
					result.UserName = name
				case 0x1B:
					result.Domain = name
				case 0x1D, 0x1E:
					if len(result.Domain) == 0 {
						result.Domain = name
					}
				case 0x20:
					if len(result.HostName) == 0 {
						result.HostName = name
					}
			}
		}

		var macbytes [6]byte
		binary.Read(buff, binary.BigEndian, &macbytes)
		if macbytes[0]|macbytes[1]|macbytes[2]|macbytes[3]|macbytes[4]|macbytes[5] != 0 {
			result.MACAddr = fmt.Sprintf("%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", macbytes[0], macbytes[1], macbytes[2], macbytes[3], macbytes[4], macbytes[5])
		}
		return TypeNBSTAT
	}

	// Addresses
	if resp.RecordType == TypeNB {
		var ridx uint16
		for ridx = 0; ridx < (resp.RecordLength / 6); ridx++ {
			addr := NBAddress{}
			binary.Read(buff, binary.BigEndian, &addr)
			if addr.Flag != 0 {
				result.Addresses = append(result.Addresses, fmt.Sprintf("%d.%d.%d.%d", addr.Address[0], addr.Address[1], addr.Address[2], addr.Address[3]))
			}
		}
		return TypeNB
	}

	return 0
}


func initWindows() {
	stdout := syscall.Handle(os.Stdout.Fd())
	stderr := syscall.Handle(os.Stdout.Fd())
	
	var originalMode uint32

	syscall.GetConsoleMode(stdout, &originalMode)
	originalMode |= 0x0004
	
	syscall.MustLoadDLL("kernel32").MustFindProc("SetConsoleMode").Call(uintptr(stdout), uintptr(originalMode))

	syscall.GetConsoleMode(stderr, &originalMode)
	originalMode |= 0x0004
	
	syscall.MustLoadDLL("kernel32").MustFindProc("SetConsoleMode").Call(uintptr(stderr), uintptr(originalMode))
}

var verbose *bool
var quite   *bool
var json    *bool

func main() {
	initWindows()
	flag.Usage = func() {
		fmt.Println("NBScan v1.0. Scan a list of networks for NetBIOS information")
		fmt.Println("")
		fmt.Println("Usage: " + filepath.Base(os.Args[0]) + " [cidr] ... [cidr]")
		fmt.Println("")
		fmt.Println("Options:")
		flag.PrintDefaults()
	}

	json      = flag.Bool("json", false, "Output json format")
	verbose   = flag.Bool("v", false, "Log more info to stderr")
	quite     = flag.Bool("q", false, "Suppress error messages")
	printMAC := flag.Bool("m", false, "Print MAC address")
	ppsrate  := flag.Int("r", 250, "Set the maximum packets per second rate. 0 disables rate limiter")
	timeout  := flag.Int("t", 1, "Set the maximum timeout / wait time for response in seconds")
	
	flag.Parse()

	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(0)
	}

	runtime.GOMAXPROCS(runtime.NumCPU())

	cIP := make(chan []byte)

	go func() {
		// Parse CIDRs and feed IPs to the input channel
		for _, cidr := range flag.Args() {
			processCIDR(cidr, cIP)
		}
	}()

	lastComm  := time.Now()
	socket, _ := net.ListenPacket("udp", "")

	// listen for UDP replyes and parse response
	go func() {
		buff := make([]byte, 1500)
		
		for {
			rlen, raddr, err := socket.ReadFrom(buff)
			if err != nil {
				if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
					log("Receiver timed out: %s", err)
					continue
				}
				
				if errors.Is(err, net.ErrClosed) {
					return
				}
				// Complain about other error types
				log("Receiver returned error: %s", err)
				return
			}
			lastComm = time.Now()
			host := raddr.(*net.UDPAddr).IP
			ip := host.String()
			if buff[3] != 0 {
				if *verbose { log("Error 0x%x received from %s: %x", buff[3], ip, buff[0 : rlen-1]) }
				continue
			}
			
			_, found := results[ip]
			if !found {
				status := new(NBResult)
				results[ip] = status
			}
			
			if parseReply(buff[0 : rlen-1], results[ip]) == TypeNBSTAT && len(results[ip].HostName) > 0 {
				h := []byte(results[ip].HostName)
				cIP <- append(host.To4(), h...)
			}
		}
	}()

	// send UDP packets
	go func() {
		lastSent := time.Now()
		var msDelay int64 = 0; if 0 < *ppsrate && *ppsrate <= 1000 { msDelay = int64(1000 / *ppsrate) }

		for ipb := range cIP {
			ip := net.IP(ipb[0:4]).String()
			addr, err := net.ResolveUDPAddr("udp", ip+":137")
			if err != nil {
				log("Error resolving ip %s (%s)", ip, err)
				continue
			}

			cmd := QUERY_NBSTAT
			if len(ipb) > 4 {
				name := string(ipb[4:])
				for i := 0; i < 16; i++ {
					var c byte
					if len(name) > i { c = name[i] }
					if c == 0 {
						QUERY_NB[13+(i*2)] = 'C'
						QUERY_NB[14+(i*2)] = 'A'
					} else {
						QUERY_NB[13+(i*2)] = byte((c / 16) + 0x41)
						QUERY_NB[14+(i*2)] = byte((c % 16) + 0x41)
					}
				}
				cmd = QUERY_NB
			}

			if msDelay > 0 {
				var msPassed = time.Now().Sub(lastSent).Milliseconds()
				if msPassed < msDelay {
					// 10ms correction to compensate this if block
					time.Sleep(time.Duration(msDelay-msPassed-10) * time.Millisecond)
				}
			}

			_, err = socket.WriteTo(cmd, addr)
			if err != nil {
				log("Error sending packet to %s (%s)", ip, err)
				continue
			}
			lastSent = time.Now()
			lastComm = lastSent
		}
	}()

	for time.Now().Sub(lastComm).Milliseconds() < 1000 * int64(*timeout) {
		time.Sleep(time.Second)
	}
	socket.Close()

	if *json {
		output := "[";
		for ip, r := range results {
			output += "\n"
			output += fmt.Sprintf(` { "ip": "%s", "macaddr": "%s", "domain": "%s", "hostname": "%s"`, ip, r.MACAddr, r.Domain, r.HostName)
			if len(r.Addresses) > 0 {
				output += fmt.Sprintf(`, "addresses": ["%s"]`, strings.Join(r.Addresses, `", "`))
			}
			output += "},"
		}
		fmt.Println(output[0:len(output)-1], "\n]")
	} else {
		if *printMAC { readMacDB() }
		fmt.Println()
		for ip, r := range results {
			if *printMAC {
				vendor := ""
				if len(r.MACAddr) > 13 {
					if v, ok := macDB[r.MACAddr[0:8]];  ok { vendor = v }
					if v, ok := macDB[r.MACAddr[0:10]]; ok { vendor = v }
					if v, ok := macDB[r.MACAddr[0:13]]; ok { vendor = v }
				}
				if len(vendor) > 18 { vendor = vendor[0:18] }
				fmt.Printf("%-16s%-18s (%-18s) %s\\%s", ip, r.MACAddr, vendor, r.Domain, r.HostName)
			} else {
				fmt.Printf("%-16s %s\\%s", ip, r.Domain, r.HostName)
			}
			if len(r.Addresses) > 0 {
				fmt.Printf(" %s", r.Addresses)
			}
			if *verbose && (len(r.Domain) == 0 || len(r.HostName) == 0) {
				fmt.Printf(" //%x", r.Names)
			}
			fmt.Println()
		}
	}
}