package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func main() {
	rw := flag.Bool("rw", false, "Allow read/write access")
	all := flag.Bool("all", false, "Show all(hidden) entries")
	dhcp := flag.Bool("dhcp", false, "Enable DHCP server")
	dhcpRange := flag.String("dhcprange", "", "IPv4 range for DHCP server")
	tftp := flag.Bool("tftp", false, "Enable TFTP server")
	tftpPort := flag.Int("tftpport", 69, "Port of TFTP server")
	ftp := flag.Bool("ftp", false, "Enable FTP server")
	ftpPort := flag.Int("ftpport", 21, "Port ot FTP server")
	flag.Parse()

	_, _, _, _ = dhcp, dhcpRange, tftp, tftpPort

	cwd, err := os.Getwd()
	if err != nil {
		log.Println(err)
		return
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	signal.Notify(c, syscall.SIGTERM)

	if *ftp {
		ftpServ := &FTPServer{
			rootPath:   cwd,
			listenAddr: fmt.Sprintf("127.0.0.1:%d", *ftpPort),
			writable:   *rw,
			showHidden: *all,
		}
		go ftpServ.startServer()
	}

	for {
		<-c
		fmt.Println("Clean up")
		os.Exit(0)
	}
}

type VDirTree struct {
	root  string
	rpath string
	vpath string
}

func (vdt *VDirTree) reset() {
	vdt.rpath, vdt.vpath = vdt.root, "/"
}

func (vdt *VDirTree) mapVPath(vp string) (rabs string, vabs string) {
	if vp[:1] == "/" {
		rabs = filepath.Join(vdt.root, vp[1:])
		vabs = vp
	} else {
		rabs = filepath.Join(vdt.rpath, vp)
		vabs = filepath.Join(vdt.vpath, vp)
	}
	return
}

func (vdt *VDirTree) doCWD(dir string) error {
	rp, vp := vdt.mapVPath(dir)
	fi, err := os.Stat(rp)
	if err != nil {
		return errors.New("Failed to change new directory!")
	}
	if !fi.IsDir() {
		return errors.New("Cannot change to a file!")
	}
	vdt.rpath, vdt.vpath = rp, vp
	log.Printf("Current path: %s, %s", vdt.rpath, vdt.vpath)
	return nil
}

func (vdt *VDirTree) doUP() {
	if vdt.vpath == "/" {
		return
	}
	vdt.rpath = filepath.Dir(vdt.rpath)
	vp := filepath.Dir(vdt.vpath)
	if vp == "/" {
		vdt.rpath = vdt.root
	}
	vdt.vpath = vp
}

type FTPServer struct {
	listenAddr string
	rootPath   string
	showHidden bool
	writable   bool
}

func (serv *FTPServer) startServer() {
	ln, err := net.Listen("tcp", serv.listenAddr)
	if err != nil {
		log.Println(err)
		return
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		s := newSession(serv, conn)
		go s.startPI()
	}
}

type session struct {
	vdt *VDirTree

	server *FTPServer
	conn   net.Conn

	dataStart chan bool
	dataEnd   chan bool

	dataReader  io.ReadSeeker
	dataWriter  io.Writer
	renameFrom  string
	receiveSize uint64
	skipBytes   uint64
}

func newSession(serv *FTPServer, conn net.Conn) *session {
	return &session{
		vdt: &VDirTree{
			root:  serv.rootPath,
			rpath: serv.rootPath,
			vpath: "/",
		},
		server:      serv,
		conn:        conn,
		dataStart:   make(chan bool),
		dataEnd:     make(chan bool),
		dataReader:  nil,
		dataWriter:  nil,
		renameFrom:  "",
		receiveSize: 0,
		skipBytes:   0,
	}
}

func (s *session) startPI() {
	buf := make([]byte, 1024)

	s.conn.Write([]byte("220 Service ready\r\n"))

	for {
		n, err := s.conn.Read(buf)
		if err != nil {
			log.Println(err)
			return
		}

		if quit := s.processPI(buf[:n]); quit {
			defer s.conn.Close()
			break
		}
	}
}

func (s *session) reply(format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	s.conn.Write([]byte(msg + "\r\n"))
	log.Println(msg)
}

func (s *session) processPI(buf []byte) (quit bool) {
	instr := strings.TrimRight(string(buf), "\r\n")
	sl := strings.SplitN(instr, " ", 2)
	cmd, args := sl[0], ""
	if len(sl) > 1 {
		args = sl[1]
	}
	log.Println("Client: ", instr)
	quit = false
	isAppend := false
	switch strings.ToUpper(cmd) {
	// access control commands
	case "USER":
		if len(args) > 0 {
			s.reply("331 User name okay, need password.")
		} else {
			s.reply("530 missing user name")
		}
	case "PASS":
		s.reply("230 User logged in, proceed.")
	case "CWD":
		if err := s.vdt.doCWD(args); err != nil {
			s.reply("550 Failed to change directory.")
		} else {
			s.reply("250 Directory successfully changed.")
			log.Println("ftp: cd ", s.vdt.rpath)
		}
	case "CDUP":
		s.vdt.doUP()
		s.reply("250 Directory successfully changed.")
		log.Println("ftp: cd ", s.vdt.rpath)
		//s.reply("550 Failed to change directory.")
	case "QUIT":
		s.reply("221 Goodbye.")
		quit = true
	// transfer parameter commands
	case "PASV":
		lip := strings.Split(s.conn.LocalAddr().String(), ":")[0]
		daddr, err := s.startDTP(lip)
		if err != nil {
			s.reply("520 cannog start data channel")
			return
		}
		da := strings.Split(daddr, ":")
		ip := strings.Replace(da[0], ".", ",", -1)
		port, _ := strconv.Atoi(da[1])
		m := "227 Entering Passive Mode (%s,%d,%d)."
		s.reply(m, ip, (port >> 8), (port & 0xFF))
	case "EPSV":
		lip := strings.Split(s.conn.LocalAddr().String(), ":")[0]
		daddr, err := s.startDTP(lip)
		if err != nil {
			s.reply("520 cannog start data channel")
			return
		}
		da := strings.Split(daddr, ":")
		port, _ := strconv.Atoi(da[1])
		m := "229 Entering Extended Passive Mode (|||%d|)."
		s.reply(m, port)
	case "TYPE":
		s.reply("200 Switching to Binary mode (always).")
	// service commands
	case "RETR":
		rp, _ := s.vdt.mapVPath(args)
		if rp == "" {
			s.reply("550 Failed to open file.")
			return
		}
		s.reply("150 Sending File.")
		fh, err := os.Open(rp)
		if err != nil {
			s.reply("550 Failed to open file.")
			return
		}
		defer fh.Close()

		s.dataReader = fh
		s.dataStart <- true
		<-s.dataEnd
		s.reply("226 Transfer complete.")
		s.skipBytes = 0
		s.dataReader = nil
	case "APPE":
		isAppend = true
		fallthrough
	case "STOR":
		if !s.server.writable {
			s.reply("532 Write not allowed")
			return
		}
		s.reply("150 Receiving File.")
		rp, _ := s.vdt.mapVPath(args)
		var fh *os.File
		if isAppend {
			fh, _ = os.OpenFile(rp, os.O_APPEND|os.O_WRONLY, 0644)
		} else {
			fh, _ = os.Create(rp)
		}
		defer fh.Close()

		s.dataWriter = fh
		s.dataStart <- true
		<-s.dataEnd
		s.reply("226 Closing data connection")
		s.receiveSize = 0
		s.dataWriter = nil
	case "ALLO":
		if !s.server.writable {
			s.reply("532 Write not allowed")
			return
		}
		s.receiveSize, _ = strconv.ParseUint(args, 10, 64)
		s.reply("200 OK.")
	case "REST":
		skip, _ := strconv.ParseUint(args, 10, 64)
		s.skipBytes = skip
		s.reply("350 Restart position accepted %d.", skip)
	case "RNFR":
		if !s.server.writable {
			s.reply("532 Write not allowed")
			return
		}
		rp, vp := s.vdt.mapVPath(args)
		if _, err := os.Stat(rp); err != nil {
			s.reply("550 file not found: %s", vp)
			return
		}
		s.renameFrom = rp
		s.reply("350 File exists, please send target name.")
	case "RNTO":
		if !s.server.writable {
			s.reply("532 Write not allowed")
			return
		}
		if s.renameFrom == "" {
			s.reply("503 Bad command sequence")
			return
		}
		rp, vp := s.vdt.mapVPath(args)
		renameTo := rp
		if _, err := os.Stat(renameTo); err == nil {
			s.reply("550 file exists: %s", vp)
			return
		}
		if err := os.Rename(s.renameFrom, renameTo); err != nil {
			s.reply("550 rename failed (%s)", err)
			return
		}
		s.reply("250 rename successful")
		s.renameFrom = ""
	case "DELE":
		if !s.server.writable {
			s.reply("532 Write not allowed")
			return
		}
		rp, _ := s.vdt.mapVPath(args)
		if _, err := os.Stat(rp); err != nil {
			s.reply("550 no such file.")
			return
		}
		if err := os.Remove(rp); err != nil {
			s.reply("550 delete failed (%s)", err)
			return
		}
		s.reply("250 OK DELETED")
	case "RMD":
		if !s.server.writable {
			s.reply("532 Write not allowed")
			return
		}
		rp, _ := s.vdt.mapVPath(args)
		if _, err := os.Stat(rp); err != nil {
			s.reply("550 no such directory.")
			return
		}
		if err := os.RemoveAll(rp); err != nil {
			s.reply("300 DELETE FAILED. (%s)", err)
			return
		}
		s.reply("250 OK DELETED")
	case "MKD":
		if !s.server.writable {
			s.reply("532 Write not allowed")
			return
		}
		rp, vp := s.vdt.mapVPath(args)
		if err := os.Mkdir(rp, 0755); err != nil {
			s.reply("550 Cannot create. (%s)", err)
			return
		}
		s.reply("257 \"%s\" created.", vp)
	case "PWD":
		s.reply("257 \"%s\" is current directory.", s.vdt.vpath)
	case "LIST":
		obj := s.vdt.rpath
		parseListArgs := func(args string) (list bool, all bool, obj string) {
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
		s.server.showHidden = all
		if o != "" {
			obj = o
		}
		fi, err := os.Stat(obj)
		if err != nil {
			s.reply("550 no such directory/file.")
			break
		}
		if fi.Mode().IsDir() {
			s.reply("150 Here comes the directory listing.")
		} else {
			s.reply("150 Here comes the file %s", obj)
		}
		s.dataReader = bytes.NewReader([]byte(s.loadDirList(obj)))
		s.dataStart <- true
		<-s.dataEnd
		s.reply("226 Directory/File send OK.")
		s.dataReader = nil
	case "SYST":
		appName := path.Base(filepath.ToSlash(os.Args[0]))
		s.reply("215 UNIX emulated by %s", appName)
	case "NOOP":
		s.reply("200 Okay")
	// RFC2389
	case "FEAT":
		s.reply("211-Features:")
		s.reply(" MDTM")
		s.reply(" SIZE")
		s.reply(" REST STREAM")
		s.reply(" TVirtualDirectoryTree")
		s.reply(" UTF8")
		s.reply("211 End")
	// RFC3659
	case "OPTS":
		opts := strings.SplitN(args, " ", 2)
		name, value := opts[0], opts[1]
		switch strings.ToUpper(name) {
		case "UTF8":
			utf8 := (strings.ToUpper(value) == "ON")
			_ = utf8
			s.reply("200 Always in UTF-8 mode.")
		default:
			s.reply("502 Unknown command %s", name)
		}
	case "MDTM":
		s.reply("550 no such file")
	case "SIZE":
		rp, _ := s.vdt.mapVPath(args)
		fi, err := os.Stat(rp)
		if err != nil {
			s.reply("550 Could not get file size.")
			return
		}
		size := fi.Size()
		s.reply("213 %d", size)
	default:
		s.reply("550 not support.")
	}
	return false
}

func (s *session) startDTP(ip string) (string, error) {
	ln, err := net.Listen("tcp", ip+":0")
	if err != nil {
		return "", err
	}
	go s.processFTPData(ln)
	return ln.Addr().String(), nil
}

func (s *session) processFTPData(ln net.Listener) {
	conn, err := ln.Accept()
	if err != nil {
		log.Println(err)
		return
	}
	defer conn.Close()

	const CHUNK_SIZE = 8 * 1024
	buf := make([]byte, CHUNK_SIZE)

	<-s.dataStart
	if s.dataWriter != nil {
		for cnt := uint64(0); cnt <= s.receiveSize || s.receiveSize == 0; {
			n, err := conn.Read(buf)
			if err != nil { // err == io.EOF
				break
			}
			s.dataWriter.Write(buf[:n])
			cnt += uint64(n)
		}
	} else if s.dataReader != nil {
		if s.skipBytes > 0 {
			s.dataReader.Seek(int64(s.skipBytes), 0)
		}
		for {
			n, err := s.dataReader.Read(buf)
			if err != nil {
				break
			}
			conn.Write(buf[:n])
		}
	}
	s.dataEnd <- true
}

func (s *session) loadDirList(dir string) string {
	getEntryInfo := func(fi os.FileInfo) string {
		getEntryType := func(fi os.FileInfo) string {
			if fi.IsDir() {
				return "d"
			}
			return "-"
		}
		getEntryMode := func(fi os.FileInfo) string {
			modes := map[int]string{4: "r", 2: "w", 1: "x", 0: "-"}
			mcal := func(d int) string {
				return modes[d&4] + modes[d&2] + modes[d&1]
			}
			perm := int(fi.Mode().Perm())
			u := mcal((perm >> 6) & 7)
			g := mcal((perm >> 3) & 7)
			o := mcal((perm >> 0) & 7)
			return u + g + o
		}
		getEntrySize := func(fi os.FileInfo) string {
			return strconv.FormatInt(fi.Size(), 10)
		}
		getEntryTime := func(fi os.FileInfo) string {
			now := time.Now()
			etime := fi.ModTime()
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
		getEntryName := func(fi os.FileInfo) string {
			return fi.Name()
		}

		line := []string{}
		line = append(line, getEntryType(fi)+getEntryMode(fi))
		line = append(line, "1")
		line = append(line, "ftp")
		line = append(line, "ftp")
		line = append(line, getEntrySize(fi))
		line = append(line, getEntryTime(fi))
		line = append(line, getEntryName(fi))

		return strings.Join(line, " ")
	}

	entries, _ := ioutil.ReadDir(dir)

	// sort by directory first
	dirs := []os.FileInfo{}
	files := []os.FileInfo{}
	for _, entry := range entries {
		if entry.IsDir() {
			if s.server.showHidden || entry.Name()[:1] != "." {
				dirs = append(dirs, entry)
			}
		} else {
			files = append(files, entry)
		}
	}

	lines := []string{}
	for _, entry := range append(dirs, files...) {
		line := getEntryInfo(entry)
		lines = append(lines, line)
	}

	if len(lines) <= 0 {
		return ""
	}
	return strings.Join(lines, "\r\n") + "\r\n"
}
