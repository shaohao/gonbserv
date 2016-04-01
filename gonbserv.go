package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

type Server interface {
	startServer()
	shutdownServer()
}

var (
	conf       *Config
	allservers []Server
)

func main() {
	vdir := flag.String("vdir", "", "Map directories into virtual path tree")
	rw := flag.Bool("rw", false, "Allow read/write access")
	all := flag.Bool("all", false, "Show all(hidden) entries")

	dhcp := flag.Bool("dhcp", false, "Enable DHCP server")
	dhcpRange := flag.String("dhcprange", "", "IPv4 range for DHCP server")

	tftp := flag.Bool("tftp", false, "Enable TFTP server")
	tftpPort := flag.Int("tftpport", 69, "Port of TFTP server")

	ftp := flag.Bool("ftp", false, "Enable FTP server")
	ftpPort := flag.Int("ftpport", 21, "Port ot FTP server")

	ifn := flag.String("i", "", "Specify the interface/ip(net) to listen on.")

	flag.Parse()

	ifi, err := net.InterfaceByName(*ifn)
	if err != nil {
		log.Fatal(err)
	}
	ips, err := ifi.Addrs()
	if err != nil {
		log.Fatal(err)
	}
	if len(ips) <= 0 {
		errmsg := fmt.Sprintf("No IP is available on %s", ifn)
		log.Fatal(errmsg)
	}
	listenIP, listenIPNet, err := net.ParseCIDR(ips[0].String()) // fetch the first valid ip
	if err != nil {
		log.Fatal(err)
	}

	conf = &Config{}
	if err := conf.genVDMap(*vdir); err != nil {
		log.Fatal(err)
	}
	conf.writable = *rw
	conf.showHidden = *all

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	signal.Notify(c, syscall.SIGTERM)

	// Create DHCP Server
	if *dhcp {
		if *dhcpRange == "" {
			log.Fatal(errors.New("Missing dhcprange parameter when enable DHCP server"))
		}
		if b, e, err := parseDHCPRange(*dhcpRange); err != nil {
			log.Fatal(err)
		} else {
			if !listenIPNet.Contains(b) || !listenIPNet.Contains(e) {
				err = fmt.Errorf("The defined DHCP range is not within the network of listenning interface")
				log.Fatal(err)
			}
			dhcpServ := &DHCPServer{
				listenAddr:  fmt.Sprintf("%s:%d", net.IPv4bcast, 67),
				serverIP:    listenIP,
				serverIPNet: listenIPNet,
				ipPool:      map[ipbytes]bool{},
				ipBuffer:    map[macbytes]ipbytes{},
			}
			dhcpServ.initIPPool(b, e)
			allservers = append(allservers, dhcpServ)
		}
	}

	// Create TFTP Server
	if *tftp {
		tftpServ := &TFTPServer{
			listenAddr: fmt.Sprintf("%s:%d", listenIP, *tftpPort),
		}
		allservers = append(allservers, tftpServ)
	}

	// Create FTP Server
	if *ftp {
		ftpServ := &FTPServer{
			listenAddr: fmt.Sprintf("%s:%d", listenIP, *ftpPort),
			procPool:   map[*FTPPISession]bool{},
		}

		allservers = append(allservers, ftpServ)
	}

	if len(allservers) == 0 {
		log.Fatal("No server is set to run.")
	}
	for _, svr := range allservers {
		go svr.startServer()
	}

	<-c
	for _, svr := range allservers {
		svr.shutdownServer()
	}
	fmt.Println("Clean up")
	os.Exit(0)
}

func parseDHCPRange(dhcprange string) (begin, end net.IP, err error) {
	items := strings.SplitN(dhcprange, ",", 2)
	if len(items) <= 1 {
		err = fmt.Errorf("Invalid DHCP range expression")
		return
	}
	begin = net.ParseIP(items[0])
	if begin == nil {
		err = fmt.Errorf("%s is not a valid IP address", items[0])
		return
	}
	end = net.ParseIP(items[1])
	if end == nil {
		err = fmt.Errorf("%s is not a valid IP address", items[1])
		return
	}

	return
}
