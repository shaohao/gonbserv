package main

import (
	"errors"
	"io/ioutil"
	"log"
	"os"
	"path"
	"path/filepath"
)

type VEntry struct {
	vname     string
	rfileinfo os.FileInfo
}

type VDirTree struct {
	rpath string
	vpath string
}

func (vdt *VDirTree) reset() {
	vdt.rpath, vdt.vpath = "", "/"
}

func (vdt *VDirTree) mapVPath(vp string) (vabs, rabs string, err error) {
	vp = path.Clean(vp)
	if path.Base(vp)[:1] == "." && !conf.showHidden {
		err = errors.New("Restrict path access")
		return
	}
	if vp[:1] == "/" {
		vabs = vp
	} else {
		vabs = path.Join(vdt.vpath, vp)
	}
	rabs, err = conf.findRPath(vabs)
	return
}

func (vdt *VDirTree) doCWD(vdir string) error {
	vp, rp, err := vdt.mapVPath(vdir)
	// it is okay to change to virtual root
	if err != nil && vp == "/" {
		vdt.rpath, vdt.vpath = "", vp
		return nil
	}
	if err != nil {
		return err
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
	vp := path.Dir(vdt.vpath)
	if vp == "/" {
		vdt.rpath = ""
	} else {
		vdt.rpath = filepath.Dir(vdt.rpath)
	}
	vdt.vpath = vp
}

func (vdt *VDirTree) doLIST(vpath string) (vlist []VEntry, err error) {
	vp, rp, er := vdt.mapVPath(vpath)
	log.Printf("vp: %s, rp: %s, er: %s\n", vp, rp, er)
	var vdirs, vfiles []VEntry
	appendVEntry := func(ve VEntry) {
		if !conf.showHidden && ve.vname[:1] == "." {
			return
		}
		if ve.rfileinfo.IsDir() {
			vdirs = append(vdirs, ve)
		} else {
			vfiles = append(vfiles, ve)
		}
	}
	// Okay to list virtual root
	if er != nil && vp == "/" {
		for v, r := range conf.vmap {
			fi, er := os.Stat(r)
			if er != nil {
				continue
			}
			entry := VEntry{
				vname:     path.Base(v),
				rfileinfo: fi,
			}
			appendVEntry(entry)
		}
		vlist = append(vdirs, vfiles...)
		return
	}
	if er != nil {
		err = er
		return
	}
	var fis []os.FileInfo
	fis, err = ioutil.ReadDir(rp)
	if err != nil {
		return
	}
	for _, fi := range fis {
		entry := VEntry{
			vname:     fi.Name(),
			rfileinfo: fi,
		}
		appendVEntry(entry)
	}
	vlist = append(vdirs, vfiles...)
	return
}

func (vdt *VDirTree) doSIZE(vpath string) (size int64, err error) {
	vp, rp, er := vdt.mapVPath(vpath)
	// Okay to size virtual root
	if er != nil && vp == "/" {
		return
	}
	if er != nil {
		err = er
		return
	}
	fi, er := os.Stat(rp)
	// Only for files
	if er != nil || fi.IsDir() {
		err = er
	}
	size = fi.Size()
	return
}
