package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
)

const (
	_ = iota
	OPCODE_RRQ
	OPCODE_WRQ
	OPCODE_DATA
	OPCODE_ACK
	OPCODE_ERROR
	OPCODE_OACK
)

const (
	_ = iota
	ERRCODE_FILE_NOT_FOUND
	ERRCODE_ACCESS_VIOLATION
	ERRCODE_DISK_FULL
	ERROCDE_ILLEGAL_TFTP_OPERATION
	ERROCDE_UNKNOWN_TID
	ERRCODE_FILE_ALREADY_EXISTS
	ERRCODE_NO_SUCH_USER
)

type TFTPServer struct {
	listenAddr string
}

func (svr *TFTPServer) startServer() {
	saddr, err := net.ResolveUDPAddr("udp", svr.listenAddr)
	if err != nil {
		log.Fatal(err)
	}

	conn, err := net.ListenUDP("udp", saddr)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	fmt.Printf("[tftp] listen on %s\n", svr.listenAddr)

	for {
		buf := make([]byte, 1024)
		n, raddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Fatalln("read error")
		}
		s := &TFTPSession{
			vdt: &VDirTree{
				rpath: "",
				vpath: "/",
			},
			raddr: raddr,
		}
		go s.processTFTP(buf[:n], raddr)
	}
}

func (svr *TFTPServer) shutdownServer() {
}

type TFTPSession struct {
	vdt   *VDirTree
	raddr *net.UDPAddr
}

func (s *TFTPSession) replyError(errcode int, errmsg string) {
	e := s.pkgError(errcode, errmsg)

	con, err := net.DialUDP("udp", nil, s.raddr)
	if err != nil {
		log.Println("Failed to dial to remote host")
		return
	}
	defer con.Close()

	if _, err := con.Write(e); err != nil {
		log.Println("Failed to write data to remote host")
		return
	}
}

func (s *TFTPSession) pkgError(errcode int, errmsg string) []byte {
	buf := bytes.NewBuffer([]byte{})
	buf.WriteByte(byte((OPCODE_ERROR >> 8) & 0xFF))
	buf.WriteByte(byte(OPCODE_ERROR & 0xFF))
	buf.WriteByte(byte((errcode >> 8) & 0xFF))
	buf.WriteByte(byte(errcode & 0xFF))
	buf.WriteString(errmsg)
	buf.WriteByte(0)
	return buf.Bytes()
}

func (s *TFTPSession) pkgData(blkid int, data []byte) []byte {
	buf := bytes.NewBuffer([]byte{})
	buf.WriteByte(byte((OPCODE_DATA >> 8) & 0xFF))
	buf.WriteByte(byte(OPCODE_DATA & 0xFF))
	buf.WriteByte(byte((blkid >> 8) & 0xFF))
	buf.WriteByte(byte(blkid & 0xFF))
	buf.Write(data)
	return buf.Bytes()
}

func (s *TFTPSession) pkgOACK(opts map[string]int64) []byte {
	buf := bytes.NewBuffer([]byte{})
	buf.WriteByte(byte((OPCODE_OACK >> 8) & 0xFF))
	buf.WriteByte(byte(OPCODE_OACK & 0xFF))
	for k, v := range opts {
		buf.WriteString(k)
		buf.WriteByte(0)
		buf.WriteString(strconv.FormatInt(v, 10))
		buf.WriteByte(0)
	}
	return buf.Bytes()
}

func (s *TFTPSession) pkgACK(blkid int) []byte {
	buf := bytes.NewBuffer([]byte{})
	buf.WriteByte(byte((OPCODE_ACK >> 8) & 0xFF))
	buf.WriteByte(byte(OPCODE_ACK & 0xFF))
	return buf.Bytes()
}

func (s *TFTPSession) SendFile(opts map[string]int64, fh *os.File, send_oack bool) {
	var blkid uint16
	var blksize int64

	oack := s.pkgOACK(opts)

	con, err := net.DialUDP("udp", nil, s.raddr)
	if err != nil {
		log.Println("Failed to dial to remote host")
		return
	}
	defer con.Close()

	ackbuf := make([]byte, 1024)
	blkid = 0
	blksize = 512

	if send_oack {
		if _, err := con.Write(oack); err != nil {
			log.Println("Failed to write data to remote host")
			return
		}

		n, raddr, err := con.ReadFromUDP(ackbuf)
		_ = raddr
		if err != nil || n < 4 {
			return
		}

		opcode := binary.BigEndian.Uint16(ackbuf[:2])
		if opcode != OPCODE_ACK {
			return
		}
		blkid = binary.BigEndian.Uint16(ackbuf[2:4])
		blksize = opts["blksize"]
	}

	rbuf := make([]byte, blksize)

	for {
		rn, err := fh.Read(rbuf)
		if err == io.EOF {
			break
		}

		nblkid := int((blkid + 1) & 0xFFFF)

		data := s.pkgData(nblkid, rbuf[:rn])
		con.Write(data)

		n, raddr, err := con.ReadFromUDP(ackbuf)
		_ = raddr
		if err != nil || n < 4 {
			break
		}

		opcode := binary.BigEndian.Uint16(ackbuf[:2])
		if opcode != OPCODE_ACK {
			continue
		}

		blkid = binary.BigEndian.Uint16(ackbuf[2:4])
	}
}

func (s *TFTPSession) ProcessReadRequst(tid int, data []byte) {
	buf := bytes.NewBuffer(data)
	bb := bytes.SplitN(buf.Bytes(), []byte{0}, 3)
	fnb, modeb, optsb := bb[0], bb[1], bb[2]
	_ = modeb
	rp, vp, er := s.vdt.mapVPath(string(fnb))
	if er != nil {
		errmsg := fmt.Sprintf("file %s not allowed", vp)
		s.replyError(ERRCODE_ACCESS_VIOLATION, errmsg)
		return
	}
	fi, err := os.Stat(rp)
	log.Println(rp)
	if err != nil {
		errmsg := fmt.Sprintf("file %s not found", vp)
		s.replyError(ERRCODE_FILE_NOT_FOUND, errmsg)
		return
	}
	optsbs := bytes.Split(optsb, []byte{0})
	opts := map[string]int64{
		"tsize":   fi.Size(),
		"blksize": 512,
	}
	for i := 0; i < len(optsbs); i += 2 {
		if string(optsbs[i]) == "" {
			break
		}
		n, v := string(optsbs[i]), string(optsbs[i+1])
		if strings.ToLower(n) == "blksize" {
			blksize, _ := strconv.Atoi(v)
			opts["blksize"] = int64(blksize)
		}
	}
	has_oack := len(optsb) > 0

	fh, err := os.Open(rp)
	if err != nil {
		errmsg := "Failed to open file"
		s.replyError(ERRCODE_FILE_NOT_FOUND, errmsg)
		return
	}
	defer fh.Close()
	s.SendFile(opts, fh, has_oack)
}

func (s *TFTPSession) RecvFile(opts map[string]int64, fh *os.File) {
	ack := s.pkgACK(0)

	con, err := net.DialUDP("udp", nil, s.raddr)
	if err != nil {
		log.Println("Failed to dial to remote host")
		return
	}
	defer con.Close()

	if _, err := con.Write(ack); err != nil {
		log.Println("Failed to write data to remote host")
		return
	}

	blksize := opts["blksize"]
	b := make([]byte, blksize+10)
	for {
		n, raddr, err := con.ReadFromUDP(b)
		_ = raddr
		if err != nil {
			break
		}

		opcode := binary.BigEndian.Uint16(b[:2])
		if opcode != OPCODE_DATA {
			continue
		}
		blkid := binary.BigEndian.Uint16(b[2:4])
		wbuf := b[4:n]
		wlen := len(wbuf)
		if wlen > 0 {
			fh.Write(wbuf)
			ack := s.pkgACK(int(blkid))
			if _, err := con.Write(ack); err != nil {
				log.Println("Failed to write data to remote host")
				break
			}
		}
		if wlen >= 0 && int64(wlen) < blksize {
			break
		}
	}
}

func (s *TFTPSession) ProcessWriteRequst(tid int, data []byte) {
	buf := bytes.NewBuffer(data)
	bb := bytes.SplitN(buf.Bytes(), []byte{0}, 3)
	fnb, modeb, optsb := bb[0], bb[1], bb[2]
	_ = modeb
	rp, vp, er := s.vdt.mapVPath(string(fnb))
	if er != nil {
		errmsg := fmt.Sprintf("file %s not allowed", vp)
		s.replyError(ERRCODE_ACCESS_VIOLATION, errmsg)
		return
	}
	optsbs := bytes.Split(optsb, []byte{0})
	opts := map[string]int64{
		"tsize":   0,
		"blksize": 512,
	}
	for i := 0; i < len(optsbs); i += 2 {
		n, v := string(optsbs[i]), string(optsbs[i+1])
		switch strings.ToLower(n) {
		case "blksize":
			blksize, _ := strconv.Atoi(v)
			opts["blksize"] = int64(blksize)
		case "tsize":
			tsize, _ := strconv.ParseUint(v, 10, 64)
			opts["tsize"] = int64(tsize)
		}
	}

	fh, err := os.Create(rp)
	if err != nil {
		errmsg := "Failed to open file"
		s.replyError(ERRCODE_FILE_NOT_FOUND, errmsg)
		return
	}
	defer fh.Close()
	s.RecvFile(opts, fh)
}

func (s *TFTPSession) processTFTP(buf []byte, addr *net.UDPAddr) {
	opcode := binary.BigEndian.Uint16(buf[:2])
	_, tid := addr.IP, addr.Port
	data := buf[2:]
	switch opcode {
	case OPCODE_RRQ:
		s.ProcessReadRequst(tid, data)
	case OPCODE_WRQ:
		if conf.writable {
			s.ProcessWriteRequst(tid, data)
		} else {
			s.replyError(ERRCODE_ACCESS_VIOLATION, "Write not allowed")
		}
	case OPCODE_ERROR:
	}
}
