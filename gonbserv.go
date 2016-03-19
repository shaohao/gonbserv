package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func main() {
	ln, err := net.Listen("tcp", "127.0.0.1:2121")
	if err != nil {
		log.Println(err)
		return
	}

	cwd, err := os.Getwd()
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
		s := newSession(conn, cwd)
		go startPI(s)
	}
}

type VDirTree struct {
	root       string
	rpath      string
	vpath      string
	showHidden bool
}

func (vdt *VDirTree) reset() {
	vdt.rpath, vdt.vpath = vdt.root, "/"
}

func (vdt *VDirTree) mapVPath(vp string) (rabs string, vabs string) {
	if filepath.IsAbs(vp) {
		rpath := filepath.Join(vdt.root, vp[1:])
		if _, err := os.Stat(rpath); err != nil {
			rpath = ""
		}
		rabs, vabs = rpath, vp
	} else {
		rabs = filepath.Join(vdt.rpath, vp)
		vabs = filepath.Join(vdt.vpath, vp)
	}
	return
}

func (vdt *VDirTree) doCWD(dir string) error {
	rp, vp := vdt.mapVPath(dir)
	if rp == "" {
		return errors.New("Failed to change new directory!")
	}
	fi, err := os.Stat(rp)
	if err != nil {
		return errors.New("Failed to change new directory!")
	}
	if !fi.IsDir() {
		return errors.New("Cannot change to a file!")
	}
	vdt.rpath, vdt.vpath = rp, vp
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

func (vdt *VDirTree) doList(args string) {
}

type readerwriter interface {
	Read([]byte) (int, error)
}

type session struct {
	vdt  *VDirTree
	conn net.Conn

	dataStart chan bool
	dataEnd   chan bool

	dataIo    io.ReadWriteSeeker
	skipBytes uint64
}

func newSession(conn net.Conn, rootDir string) *session {
	return &session{
		dataStart: make(chan bool),
		dataEnd:   make(chan bool),
		dataIo:    nil,
		conn:      conn,
		skipBytes: 0,
		vdt: &VDirTree{
			root:       rootDir,
			rpath:      rootDir,
			vpath:      "/",
			showHidden: false,
		},
	}
}

func startPI(s *session) {
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

func (s *session) reply(msg string) {
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
		if s.vdt.doCWD(args) != nil {
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
		s.reply(fmt.Sprintf(m, ip, (port >> 8), (port & 0xFF)))
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
		s.reply(fmt.Sprintf(m, port))
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

		s.dataIo = fh
		s.dataStart <- true
		<-s.dataEnd
		s.reply("226 Transfer complete.")
		s.skipBytes = 0
	case "STOR":
		s.reply("532 Write not allowed")
	case "APPE":
		s.reply("532 Write not allowed")
	case "ALLO":
		s.reply("200 OK.")
	case "REST":
		skip, _ := strconv.ParseUint(args, 10, 64)
		s.skipBytes = skip
		s.reply(fmt.Sprintf("350 Restart position accepted %d.", skip))
	case "RNFR":
		s.reply("550 file not found: ")
	case "RNTO":
		s.reply("550 rename failed")
	case "DELE":
		s.reply("550 delete failed")
	case "RMD":
		s.reply("550 no such directory")
	case "MKD":
		s.reply("550 Cannot create.")
	case "PWD":
		s.reply(fmt.Sprintf("257 \"%s\" is current directory.", s.vdt.vpath))
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
		log.Println(all)
		s.vdt.showHidden = all
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
			s.reply("150 Here comes the file " + obj)
		}
		s.dataIo = bytes.NewReader([]byte{s.loadDirList(obj)})
		s.dataStart <- true
		<-s.dataEnd
		s.reply("226 Directory/File send OK.")
	case "SYST":
		s.reply("215 UNIX emulated by " + path.Base(filepath.ToSlash(os.Args[0])))
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
		name := args
		//name, opts := args[0], args[1]
		switch strings.ToUpper(name) {
		case "UTF8":
			//utf8 := (strings.ToUpper(opts) == "ON")
			//utf8 = true
			s.reply("200 Always in UTF-8 mode.")
		default:
			s.reply("502 Unknown command " + name)
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
		s.reply(fmt.Sprintf("213 %d", size))
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

	<-s.dataStart
	buf := make([]byte, 256)
	for {
		n, err := s.dataIo.Read(buf)
		if err != nil {
			break
		}
		conn.Write(buf[:n])
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
			if s.vdt.showHidden || entry.Name()[:1] != "." {
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
