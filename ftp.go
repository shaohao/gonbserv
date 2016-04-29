package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type FTPServer struct {
	listenAddr string
	procPool   map[*FTPPISession]bool
}

func (svr *FTPServer) startServer() {
	saddr, err := net.ResolveTCPAddr("tcp", svr.listenAddr)
	if err != nil {
		log.Fatal(err)
	}
	ln, err := net.ListenTCP("tcp", saddr)
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		pi := &FTPPISession{
			vdt: &VDirTree{
				rpath: "",
				vpath: "/",
			},
			conn:    conn,
			sigExit: make(chan bool),
		}
		go pi.Create()
		svr.procPool[pi] = true
	}
}

func (svr *FTPServer) shutdownServer() {
}

type FTPPISession struct {
	vdt  *VDirTree
	conn net.Conn

	renameFrom  string
	skipBytes   uint64
	receiveSize uint64

	killed  bool
	sigExit chan bool

	dtp       *FTPDTPProc
	isEPSVAll bool
}

func (pi *FTPPISession) Create() {
	const CMDSIZE = 1024 // enough for protocol command
	buf := make([]byte, CMDSIZE)

	pi.reply("220 Service ready")

	defer pi.conn.Close()

	for !pi.killed {
		n, err := pi.conn.Read(buf)
		if err != nil {
			log.Println(err)
			break
		}

		if quit := pi.processCmd(buf[:n]); quit {
			break
		}
	}

	pi.sigExit <- true
}

func (pi *FTPPISession) Delete() {
	pi.terminateDTP()

	if !pi.killed {
		pi.killed = true
	}
	<-pi.sigExit
}

func (pi *FTPPISession) startDTP(connaddr string) (err error) {
	pi.dtp = &FTPDTPProc{}
	var laddr, raddr *net.TCPAddr
	var pasv bool
	if connaddr == "" {
		pasv = true
		addr := pi.conn.LocalAddr().String()
		saddr, err := net.ResolveTCPAddr("tcp", addr)
		if err != nil {
			return err
		}
		laddr, raddr = &net.TCPAddr{IP: saddr.IP, Port: 0}, nil
	} else {
		pasv = false
		laddr = nil
		raddr, err = net.ResolveTCPAddr("tcp", connaddr)
		if err != nil {
			return err
		}
	}
	return pi.dtp.Open(pasv, laddr, raddr)
}

func (pi *FTPPISession) terminateDTP() {
	if pi.dtp != nil {
		pi.dtp.Close()
	}
	pi.dtp = nil
}

func (pi *FTPPISession) isWriteProtect(cmd string) bool {
	var wpCmds = [...]string{
		"APPE", "STOR", "ALLO", "RNFR", "RNTO", "DELE", "RMD", "MKD",
	}
	for _, c := range wpCmds {
		if c == cmd {
			return !conf.writable
		}
	}
	return false
}

func (pi *FTPPISession) reply(format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	pi.conn.Write([]byte(msg + "\r\n"))
	log.Println(msg)
}

func (pi *FTPPISession) processCmd(buf []byte) (quit bool) {
	instr := strings.TrimRight(string(buf), "\r\n")
	sl := strings.SplitN(instr, " ", 2)
	cmd, args := strings.ToUpper(sl[0]), ""
	if len(sl) > 1 {
		args = sl[1]
	}
	log.Println("Client: ", instr)

	quit = false
	isEPRT := false
	isEPSV := false
	isAppend := false
	isNameList := false

	if pi.isWriteProtect(cmd) {
		pi.reply("532 Write not allowed")
		return
	}
	switch cmd {
	// access control commands
	case "USER":
		if len(args) > 0 {
			pi.reply("331 User name okay, need password.")
		} else {
			pi.reply("530 missing user name")
		}
	case "PASS":
		pi.reply("230 User logged in, proceed.")
	case "CWD":
		if err := pi.vdt.doCWD(args); err != nil {
			pi.reply("550 Failed to change directory.")
		} else {
			pi.reply("250 Directory successfully changed.")
			if pi.vdt.IsVRoot() {
				log.Println("ftp: cd `ROOT'")
			} else {
				log.Println("ftp: cd ", pi.vdt.rpath)
			}
		}
	case "CDUP":
		pi.vdt.doUP()
		pi.reply("250 Directory successfully changed.")
		log.Println("ftp: cd ", pi.vdt.rpath)
	case "QUIT":
		pi.reply("221 Goodbye.")
		quit = true
	// transfer parameter commands
	case "EPRT":
		isEPRT = true
		fallthrough
	case "PORT":
		if pi.isEPSVAll {
			pi.reply("501 %s not allowed after EPSV ALL", cmd)
			return
		}
		var ip string
		var port int
		if isEPRT {
			ipport := strings.Split(args, "|")
			ip = ipport[2]
			port, _ = strconv.Atoi(ipport[3])
		} else {
			ipport := strings.Split(args, ",")
			pH, _ := strconv.Atoi(ipport[4])
			pL, _ := strconv.Atoi(ipport[5])
			ip = fmt.Sprintf("%s.%s.%s.%s", ipport[0], ipport[1], ipport[2], ipport[3])
			port = ((pH << 8) | pL)
		}
		ipAddr := fmt.Sprintf("%s:%d", ip, port)
		err := pi.startDTP(ipAddr)
		if err != nil {
			pi.reply("520 cannot start data channel")
		}
		pi.reply("200 Okay")
	case "EPSV":
		if strings.ToUpper(args) == "ALL" {
			pi.reply("200 EPSV ALL accepted")
			pi.isEPSVAll = true
			return
		}
		isEPSV = true
		fallthrough
	case "PASV":
		err := pi.startDTP("")
		if err != nil {
			pi.reply("520 cannot start data channel")
			return
		}
		ip := pi.dtp.IP().String()
		port := pi.dtp.Port()
		if isEPSV {
			pi.reply("229 Entering Extended Passive Mode (|||%d|).", port)
		} else {
			ipStr := strings.Replace(ip, ".", ",", -1)
			pH, pL := (port >> 8), (port & 0xFF)
			pi.reply("227 Entering Passive Mode (%s,%d,%d).", ipStr, pH, pL)
		}
	case "TYPE":
		pi.reply("200 Switching to Binary mode (always).")
	// service commands
	case "RETR":
		if pi.dtp == nil {
			pi.reply("550 NO data connection available.")
			return
		}
		rp, _, er := pi.vdt.mapVPath(args)
		if er != nil {
			pi.reply("550 %s", er)
			pi.terminateDTP()
			return
		}
		fi, err0 := os.Stat(rp)
		// Only for files
		if err0 != nil || fi.IsDir() {
			pi.reply("550 Failed to open file.")
			pi.terminateDTP()
			return
		}
		fh, err := os.Open(rp)
		if err != nil {
			pi.reply("550 Failed to open file.")
			pi.terminateDTP()
			return
		}
		defer fh.Close()

		pi.reply("150 Sending File.")
		pi.dtp.Send(fh, pi.skipBytes)
		pi.dtp.Close()
		pi.reply("226 Transfer complete.")
	case "APPE":
		isAppend = true
		fallthrough
	case "STOR":
		if pi.dtp == nil {
			pi.reply("550 Data transfer channel closed.")
			return
		}
		rp, _, er := pi.vdt.mapVPath(args)
		if er != nil {
			pi.reply("532 Write path not allowed")
			pi.terminateDTP()
			return
		}
		var fh *os.File
		if isAppend {
			fh, _ = os.OpenFile(rp, os.O_APPEND|os.O_WRONLY, 0644)
		} else {
			fh, _ = os.Create(rp)
		}
		defer fh.Close()

		pi.reply("150 Receiving File.")
		pi.dtp.Recv(fh, pi.receiveSize)
		pi.dtp.Close()
		pi.reply("226 Closing data connection")
	case "ALLO":
		pi.receiveSize, _ = strconv.ParseUint(args, 10, 64)
		pi.reply("200 OK.")
	case "REST":
		skip, _ := strconv.ParseUint(args, 10, 64)
		pi.skipBytes = skip
		pi.reply("350 Restart position accepted %d.", skip)
	case "RNFR":
		rp, vp, er := pi.vdt.mapVPath(args)
		if er != nil {
			pi.reply("550 %s", er)
			return
		}
		_, err := os.Stat(rp)
		if err != nil {
			pi.reply("550 file not found: %s", vp)
			return
		}
		pi.renameFrom = rp
		pi.reply("350 File exists, please send target name.")
	case "RNTO":
		if pi.renameFrom == "" {
			pi.reply("503 Bad command sequence")
			return
		}
		rp, vp, er := pi.vdt.mapVPath(args)
		if er != nil {
			pi.reply("532 Rename path not allowed")
			return
		}
		renameTo := rp
		if _, err := os.Stat(renameTo); err == nil {
			pi.reply("550 file exists: %s", vp)
			return
		}
		if err := os.Rename(pi.renameFrom, renameTo); err != nil {
			pi.reply("550 rename failed (%s)", err)
			return
		}
		pi.reply("250 rename successful")
		pi.renameFrom = ""
	case "DELE":
		rp, _, er := pi.vdt.mapVPath(args)
		if er != nil {
			pi.reply("532 Delete path not allowed")
			return
		}
		if _, err := os.Stat(rp); err != nil {
			pi.reply("550 no such file.")
			return
		}
		if err := os.Remove(rp); err != nil {
			pi.reply("550 delete failed (%s)", err)
			return
		}
		pi.reply("250 OK DELETED")
	case "RMD":
		rp, _, er := pi.vdt.mapVPath(args)
		if er != nil {
			pi.reply("532 Delete path not allowed")
			return
		}
		if _, err := os.Stat(rp); err != nil {
			pi.reply("550 no such directory.")
			return
		}
		if err := os.RemoveAll(rp); err != nil {
			pi.reply("300 DELETE FAILED. (%s)", err)
			return
		}
		pi.reply("250 OK DELETED")
	case "MKD":
		rp, vp, er := pi.vdt.mapVPath(args)
		if er != nil {
			pi.reply("532 Mkdir path not allowed")
			return
		}
		if err := os.Mkdir(rp, 0755); err != nil {
			pi.reply("550 Cannot create. (%s)", err)
			return
		}
		pi.reply("257 \"%s\" created.", vp)
	case "PWD":
		pi.reply("257 \"%s\" is current directory.", pi.vdt.vpath)
	case "NLST":
		isNameList = true
		fallthrough
	case "LIST":
		if pi.dtp == nil {
			pi.reply("550 NO data connection available.")
			return
		}
		obj := pi.vdt.vpath
		parseListArgs := func(args string) (list, all bool, obj string) {
			all = conf.showHidden
		PARSE:
			for {
				switch {
				case strings.Contains(args, "-l"):
					list = true
					args = strings.Replace(args, "-l", "", -1)
				case strings.Contains(args, "-a"):
					all = true
					args = strings.Replace(args, "-a", "", -1)
				default:
					obj = strings.Trim(args, " ")
					break PARSE
				}
			}
			return
		}
		_, all, o := parseListArgs(args)
		conf.showHidden = all
		if o != "" {
			obj = o
		}
		lst, er := pi.vdt.doLIST(obj)
		if er != nil {
			pi.reply("550 %s", er)
			return
		}
		var lststr string
		if isNameList {
			lststr = pi.loadDirNameList(o, lst)
		} else {
			lststr = pi.loadDirContent(lst)
		}
		r := bytes.NewReader([]byte(lststr))
		pi.reply("150 Here comes the listing.")
		pi.dtp.Send(r, 0)
		pi.dtp.Close()
		pi.reply("226 Directory/File send OK.")
	case "SYST":
		appName := path.Base(filepath.ToSlash(os.Args[0]))
		pi.reply("215 UNIX emulated by %s", appName)
	case "NOOP":
		pi.reply("200 Okay")
	// RFC2389
	case "FEAT":
		pi.reply("211-Features:")
		pi.reply(" EPSV")
		pi.reply(" MDTM")
		pi.reply(" PASV")
		pi.reply(" REST STREAM")
		pi.reply(" SIZE")
		pi.reply(" TVFS")
		pi.reply(" UTF8")
		pi.reply("211 End")
	// RFC3659
	case "OPTS":
		opts := strings.SplitN(args, " ", 2)
		name, value := opts[0], opts[1]
		switch strings.ToUpper(name) {
		case "UTF8":
			utf8 := (strings.ToUpper(value) == "ON")
			_ = utf8
			pi.reply("200 Always in UTF-8 mode.")
		default:
			pi.reply("502 Unknown command %s", name)
		}
	case "MDTM":
		rp, _, er := pi.vdt.mapVPath(args)
		if er != nil {
			pi.reply("532 %s", er)
			return
		}
		fi, err := os.Stat(rp)
		// Only for files
		if err != nil || fi.IsDir() {
			pi.reply("550 Could not get file modification time.")
			return
		}
		mtime := fi.ModTime()
		pi.reply("213 %4d%02d%02d%02d%02d%02d",
			mtime.Year(), mtime.Month(), mtime.Day(),
			mtime.Hour(), mtime.Minute(), mtime.Second(),
		)
	case "SIZE":
		size, err := pi.vdt.doSIZE(args)
		if err != nil {
			pi.reply("550 Could not get file size.")
			return
		}
		pi.reply("213 %d", size)
	case "AUTH":
		pi.reply("530 Please login with USER and PASS.")
	default:
		pi.reply("550 not support.")
	}
	return false
}

func (s *FTPPISession) loadDirNameList(vp string, vlist []*VEntry) string {
	var lines []string

	for _, ve := range vlist {
		vpath := path.Join(vp, path.Base(ve.VPath))
		lines = append(lines, vpath)
	}

	if len(lines) <= 0 {
		return ""
	}
	return strings.Join(lines, "\r\n") + "\r\n"
}

func (pi *FTPPISession) loadDirContent(vlist []*VEntry) string {
	getEntryInfo := func(ve *VEntry) string {
		getEntryType := func(ve *VEntry) string {
			fmode := ve.Mode()
			switch {
			case fmode.IsDir():
				return "d"
			case fmode.IsRegular():
				return "-"
			case (fmode & os.ModeCharDevice) != 0:
				return "c"
			case (fmode & os.ModeSymlink) != 0:
				return "l"
			}
			return "-"
		}
		getEntryMode := func(ve *VEntry) string {
			modes := map[int]string{4: "r", 2: "w", 1: "x", 0: "-"}
			mcal := func(d int) string {
				return modes[d&4] + modes[d&2] + modes[d&1]
			}
			perm := int(ve.Mode().Perm())
			u := mcal((perm >> 6) & 7)
			g := mcal((perm >> 3) & 7)
			o := mcal((perm >> 0) & 7)
			return u + g + o
		}
		getEntrySize := func(ve *VEntry) string {
			return strconv.FormatInt(ve.Size(), 10)
		}
		getEntryTime := func(ve *VEntry) string {
			now := time.Now()
			etime := ve.ModTime()
			if now.Year() == etime.Year() {
				return fmt.Sprintf("%s %02d %02d:%02d",
					etime.Month().String()[:3],
					etime.Day(), etime.Hour(), etime.Minute(),
				)
			}
			return fmt.Sprintf("%s %02d %04d",
				etime.Month().String()[:3],
				etime.Day(), etime.Year(),
			)
		}
		getEntryName := func(ve *VEntry) string {
			return path.Base(ve.VPath)
		}

		line := []string{}
		line = append(line, getEntryType(ve)+getEntryMode(ve))
		line = append(line, "1")
		line = append(line, "ftp")
		line = append(line, "ftp")
		line = append(line, getEntrySize(ve))
		line = append(line, getEntryTime(ve))
		line = append(line, getEntryName(ve))

		return strings.Join(line, " ")
	}

	var lines []string
	for _, entry := range vlist {
		line := getEntryInfo(entry)
		lines = append(lines, line)
	}

	if len(lines) <= 0 {
		return ""
	}
	return strings.Join(lines, "\r\n") + "\r\n"
}

type FTPDTPProc struct {
	laddr *net.TCPAddr

	listener net.Listener
	conn     net.Conn

	killed bool

	receiveSize uint64
	skipBytes   uint64
}

func (x *FTPDTPProc) IP() net.IP {
	return x.laddr.IP
}

func (x *FTPDTPProc) Port() int {
	return x.laddr.Port
}

func (x *FTPDTPProc) Open(pasv bool, laddr, raddr *net.TCPAddr) error {
	var err error
	if !pasv {
		x.conn, err = net.DialTCP("tcp", laddr, raddr)
		return err
	}
	x.listener, err = net.ListenTCP("tcp", laddr)
	if err != nil {
		return err
	}
	// update local listen address
	x.laddr, err = net.ResolveTCPAddr("tcp", x.listener.Addr().String())
	if err != nil {
		return err
	}

	// Make accept in another process
	go func() {
		x.conn, err = x.listener.Accept()
		if err != nil {
			log.Println(err)
		}
	}()

	return nil
}

const CHUNK_SIZE = 8 * 1024

func (x *FTPDTPProc) Recv(w io.Writer, recvSize uint64) error {
	buf := make([]byte, CHUNK_SIZE)

	var err error = nil
	for cnt := uint64(0); cnt <= recvSize || recvSize == 0; {
		if x.killed {
			break
		}
		var n int
		n, err = x.conn.Read(buf)
		if err != nil { // err == io.EOF
			break
		}
		w.Write(buf[:n])
		cnt += uint64(n)
	}

	return err
}

func (x *FTPDTPProc) Send(r io.ReadSeeker, skipBytes uint64) error {
	if skipBytes > 0 {
		r.Seek(int64(skipBytes), 0)
	}
	buf := make([]byte, CHUNK_SIZE)

	var err error = nil
	for {
		if x.killed {
			break
		}
		var n int
		n, err = r.Read(buf)
		if err != nil {
			break
		}
		x.conn.Write(buf[:n])
	}

	return err
}

func (x *FTPDTPProc) Close() {
	if !x.killed {
		x.killed = true
	}

	if x.conn != nil {
		x.conn.Close()
	}
	if x.listener != nil {
		x.listener.Close()
	}
}
