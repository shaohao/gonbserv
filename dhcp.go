package main

import (
	"bytes"
	"encoding/binary"
	//	"fmt"
	"log"
	"net"
)

const (
	_ = iota
	DHCP_DISCOVER
	DHCP_OFFER
	DHCP_REQUEST
	DHCP_DECLINE
	DHCP_ACK
	DHCP_NAK
	DHCP_RELEASE
	DHCP_INFORM
)

type ipbytes [4]byte
type macbytes [6]byte

type DHCPServer struct {
	listenAddr  string
	serverIP    net.IP
	serverIPNet *net.IPNet
	ipPool      map[ipbytes]bool
	ipBuffer    map[macbytes]ipbytes
	replyIP     net.IP
}

func (svr *DHCPServer) initIPPool(b, e net.IP) {
	b4 := b.To4()
	bb := (uint32(b4[0]) << 24) | (uint32(b4[1]) << 16) | (uint32(b4[2]) << 8) | uint32(b4[3])
	e4 := e.To4()
	be := (uint32(e4[0]) << 24) | (uint32(e4[1]) << 16) | (uint32(e4[2]) << 8) | uint32(e4[3])
	for i := bb; i <= be; i++ {
		d := ipbytes{byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i & 0xFF)}
		svr.ipPool[d] = false
	}
	na := b.Mask(svr.serverIPNet.Mask).To4()
	ones, bits := svr.serverIPNet.Mask.Size()
	nb := (uint32(na[0]) << 24) | (uint32(na[1]) << 16) | (uint32(na[2]) << 8) | uint32(na[3])
	bs := nb | ((1 << uint32(bits-ones)) - 1)
	svr.replyIP = net.IPv4(byte(bs>>24), byte(bs>>16), byte(bs>>8), byte(bs&0xFF))
}

func (svr *DHCPServer) startServer() {
	saddr, err := net.ResolveUDPAddr("udp", svr.listenAddr)
	if err != nil {
		log.Fatal(err)
	}

	conn, err := net.ListenUDP("udp", saddr)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	for {
		buf := make([]byte, 1024)
		n, raddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Fatalln("read error")
		}
		s := &DHCPSession{
			server: svr,
			raddr:  raddr,
			conn:   conn,
		}
		s.processRequst(buf[:n], raddr)
	}
}

func (svr *DHCPServer) shutdownServer() {
}

type DHCPSession struct {
	server *DHCPServer
	raddr  *net.UDPAddr
	conn   *net.UDPConn
}

func (s *DHCPSession) processRequst(data []byte, addr *net.UDPAddr) {
	xid := data[4:8]
	cmac := net.HardwareAddr(data[28:34])

	options := s.parseOptionsData(data[240:])
	_ = options
	reqType := data[242]

	var msgData []byte
	switch reqType {
	case DHCP_DISCOVER:
		log.Printf("dhcp c: DHCPDISCOVER %s", cmac)
		clientIP := s.assignClientIP(cmac)
		if clientIP != nil {
			msgData = s.buildMessage(xid, clientIP, cmac, DHCP_OFFER)
			log.Printf("dhcp s: DHCPOFFER %s %s", clientIP, cmac)
		} else {
			msgData = s.buildMessage(xid, clientIP, cmac, DHCP_NAK)
			log.Printf("dhcp s: DHCPDISCOVER %s no address available", cmac)
		}
		s.reply(msgData)
	case DHCP_REQUEST:
		clientIP := s.assignClientIP(cmac)
		log.Printf("dhcp c: DHCPREQUEST %s %s", clientIP, cmac)
		msgData = s.buildMessage(xid, clientIP, cmac, DHCP_ACK)
		log.Printf("dhcp s: DHCPACK %s %s", clientIP, cmac)
		s.reply(msgData)
	}
}

func (s *DHCPSession) assignClientIP(cmac net.HardwareAddr) net.IP {
	var m macbytes
	copy(m[:], cmac[:6])
	ipb, okay := s.server.ipBuffer[m]
	if okay {
		return net.IPv4(ipb[0], ipb[1], ipb[2], ipb[3])
	}
	for ipb, hitted := range s.server.ipPool {
		if !hitted {
			ip := net.IPv4(ipb[0], ipb[1], ipb[2], ipb[3])
			s.server.ipPool[ipb] = true
			s.server.ipBuffer[m] = ipb
			return ip
		}
	}
	return nil
}

func (s *DHCPSession) reply(msgData []byte) error {
	raddr := &net.UDPAddr{IP: s.server.replyIP, Port: s.raddr.Port}
	_, err := s.conn.WriteToUDP(msgData, raddr)
	if err != nil {
		log.Printf("Error write to udp: %s", err)
	}
	return err
}

func (s *DHCPSession) buildMessage(xid []byte, clientIP net.IP, cmac net.HardwareAddr, msgType byte) []byte {
	offer := bytes.NewBuffer([]byte{})
	var bsu16 []byte = make([]byte, 2)
	var bsu32 []byte = make([]byte, 4)

	elapsed := 0
	if msgType != DHCP_NAK {
		elapsed = 4
	}

	leaseTime := 3600
	renewalTime := 1800
	rebindingTime := 3150

	serverIP4 := s.server.serverIP.To4()
	serverIPMask := s.server.serverIPNet.Mask

	brip := net.IPv4Mask(255, 255, 255, 0)

	offer.WriteByte(0x2) // Message type: reply
	offer.WriteByte(0x1) // Hardware type: ethernet
	offer.WriteByte(0x6) // Hardware address length
	offer.WriteByte(0x0) // hops
	offer.Write(xid)
	binary.BigEndian.PutUint16(bsu16, uint16(elapsed))
	offer.Write(bsu16)              // second elapsed
	offer.Write([]byte{0x80, 0x00}) // bootp flags
	offer.Write([]byte{0, 0, 0, 0}) // client ip
	if clientIP != nil {
		clientIP4 := clientIP.To4()
		offer.Write(clientIP4)
	} else {
		offer.Write(make([]byte, 0))
	}
	offer.Write(serverIP4)                          // next server ip
	offer.Write(make([]byte, 4))                    // relay agent ip
	offer.Write(cmac)                               // client mac address
	offer.Write(make([]byte, 10))                   // client hardware address padding
	offer.Write(make([]byte, 64))                   // server host name
	offer.Write(make([]byte, 128))                  // boot file name
	offer.Write([]byte{0x63, 0x82, 0x53, 0x63})     // Magic cookie
	offer.Write(s.buildOption(53, []byte{msgType})) // DHCP Message Type (Offer)
	offer.Write(s.buildOption(54, serverIP4))       // DHCP Server Identifier
	if msgType == DHCP_NAK {
		offer.Write(s.buildOption(56, []byte("address not available"))) // Message
	} else {
		binary.BigEndian.PutUint32(bsu32, uint32(leaseTime))
		offer.Write(s.buildOption(51, bsu32)) // IP address lease time
		binary.BigEndian.PutUint32(bsu32, uint32(renewalTime))
		offer.Write(s.buildOption(58, bsu32)) // Renewal Time value
		binary.BigEndian.PutUint32(bsu32, uint32(rebindingTime))
		offer.Write(s.buildOption(59, bsu32))                    // Rebinding time value
		offer.Write(s.buildOption(67, []byte("pxelinux.0\x00"))) // bootfile name
		offer.Write(s.buildOption(1, serverIPMask))              // Subnet mask
		offer.Write(s.buildOption(28, brip))                     // Broadcast Address
		offer.Write(s.buildOption(3, serverIP4))                 // Router
		offer.Write(s.buildOption(6, serverIP4))                 // Domain name server
	}
	offer.Write(s.buildOption(255, nil)) // End
	return offer.Bytes()
}

func (s *DHCPSession) buildOption(code int, data []byte) []byte {
	buff := bytes.NewBuffer([]byte{})
	buff.WriteByte(byte(code))
	if data != nil && len(data) > 0 {
		buff.WriteByte(byte(len(data)))
		buff.Write(data)
	}
	return buff.Bytes()
}

func (s *DHCPSession) parseOptionsData(data []byte) map[byte][]byte {
	buff := bytes.NewBuffer(data)
	var options map[byte][]byte = map[byte][]byte{}
	for {
		code, err0 := buff.ReadByte()
		if err0 != nil {
			log.Println("Error parse dhcp request opt code!")
			break
		}
		if code == 255 {
			break
		}
		dlen, err1 := buff.ReadByte()
		if err1 != nil {
			log.Println("Error parse dhcp request opt len!")
			break
		}
		value := make([]byte, dlen)
		n, err2 := buff.Read(value)
		if err2 != nil || n != int(dlen) {
			log.Println("Error parse dhcp request opt value!")
			break
		}
		options[code] = value
	}
	return options
}
