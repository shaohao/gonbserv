package main

import (
	"errors"
	"io/ioutil"
	"log"
	"os"
	"path"
	"path/filepath"
	"time"
)

type VEntry struct {
	VPath string
	RPath string
	rfi   os.FileInfo
}

type VList struct {
	vdirs, vfiles []*VEntry
}

type VDirTree struct {
	rpath string
	vpath string
}

func (vdt *VDirTree) reset() {
	vdt.rpath, vdt.vpath = "", "/"
}

func (vdt *VDirTree) IsVRoot() bool {
	return vdt.rpath == "" && vdt.vpath == "/"
}

func (vdt *VDirTree) mapVPath(vp string) (rabs, vabs string, err error) {
	vp = path.Clean(vp)
	if !isVisible(vp) {
		err = errors.New("Restrict path access")
		return
	}
	if vp[0] == '/' {
		vabs = vp
	} else {
		vabs = path.Join(vdt.vpath, vp)
	}
	rabs, err = conf.findRPath(vabs)
	// It's okay to map virtual root
	if vabs == "/" {
		rabs, err = "", nil
	}
	return
}

func (vdt *VDirTree) doCWD(vdir string) error {
	rp, vp, err := vdt.mapVPath(vdir)
	if err != nil {
		return err
	}
	// it is okay to change to virtual root
	if rp != "" {
		fi, err := os.Stat(rp)
		if err != nil {
			return errors.New("Failed to change new directory!")
		}
		if !fi.IsDir() {
			return errors.New("Cannot change to a file!")
		}
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

func (vdt *VDirTree) doLIST(vpath string) ([]*VEntry, error) {
	rp, vp, err := vdt.mapVPath(vpath)
	log.Printf("vp: %s, rp: %s, er: %s\n", vp, rp, err)
	if err != nil {
		return nil, err
	}
	// Okay to list virtual root
	if rp == "" {
		list, err := listVRoot()
		return list, err
	}
	fi, err := os.Stat(rp)
	if err != nil {
		return nil, err
	}
	if fi.IsDir() {
		list, err := listDir(rp, vp)
		return list, err
	}
	list, err := listSingleItem(rp, vp)
	return list, err
}

func (vdt *VDirTree) doSIZE(vpath string) (size int64, err error) {
	size = 0
	rp, vp, err := vdt.mapVPath(vpath)
	if err != nil {
		return
	}
	// Okay to size virtual root
	if vp != "/" {
		var fi os.FileInfo
		fi, err = os.Stat(rp)
		// Only for files
		if err != nil || fi.IsDir() {
			return
		}
		size = fi.Size()
	}
	return size, err
}

func listVRoot() ([]*VEntry, error) {
	vl := &VList{}
	// list root dir when mount to root
	rp, okay := conf.vmap["/"]
	if okay {
		return listDir(rp, "/")
	}
	for v, r := range conf.vmap {
		fi, err := os.Stat(r)
		if err != nil {
			continue
		}
		vl.appendVEntry(&VEntry{
			VPath: v,
			RPath: r,
			rfi:   fi,
		})
	}
	return vl.getList(), nil
}

func listDir(rp, vp string) ([]*VEntry, error) {
	fis, err := ioutil.ReadDir(rp)
	if err != nil {
		return nil, err
	}
	vl := &VList{}
	for _, fi := range fis {
		vl.appendVEntry(&VEntry{
			VPath: path.Join(vp, fi.Name()),
			RPath: rp,
			rfi:   fi,
		})
	}
	return vl.getList(), nil
}

func listSingleItem(rp, vp string) ([]*VEntry, error) {
	fi, err := os.Stat(rp)
	if err != nil {
		return nil, err
	}
	vl := &VList{}
	vl.appendVEntry(&VEntry{
		VPath: path.Join(vp, fi.Name()),
		RPath: rp,
		rfi:   fi,
	})
	return vl.getList(), nil
}

func (vlst *VList) appendVEntry(ve *VEntry) {
	if !ve.IsVisible() {
		return
	}
	if ve.IsDir() {
		vlst.vdirs = append(vlst.vdirs, ve)
	} else {
		vlst.vfiles = append(vlst.vfiles, ve)
	}
}

func (vlst *VList) getList() []*VEntry {
	return append(vlst.vdirs, vlst.vfiles...)
}

func isVisible(vpath string) bool {
	vname := path.Base(vpath)
	return vname[0] != '.' || conf.showHidden
}

func (ve *VEntry) IsVisible() bool {
	return isVisible(ve.VPath)
}

func (ve *VEntry) IsDir() bool {
	return ve.rfi.IsDir()
}

func (ve *VEntry) VName() string {
	return path.Base(ve.VPath)
}

func (ve *VEntry) Size() int64 {
	return ve.rfi.Size()
}

func (ve *VEntry) Mode() os.FileMode {
	return ve.rfi.Mode()
}

func (ve *VEntry) ModTime() time.Time {
	return ve.rfi.ModTime()
}
