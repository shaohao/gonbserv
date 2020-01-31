package main

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
)

type Config struct {
	vmap       map[string]string
	showHidden bool
	writable   bool
}

func (c *Config) findRPath(vp string) (rp string, err error) {
	r, okay := c.vmap[vp]
	if !okay {
		dir := path.Dir(vp)
		base := path.Base(vp)
		if dir == vp && vp == "/" {
			r0, okay0 := c.vmap[dir]
			if okay0 {
				rp = r0
			} else {
				rp = ""
				err = errors.New("Restrict path access")
			}
			return
		}
		r, err = c.findRPath(dir)
		if err != nil {
			return
		}
		rp = path.Join(r, base)
		return
	}
	rp = r
	return
}

func (c *Config) genVDMap(vdirs string) (err error) {
	c.vmap = map[string]string{}

	items := strings.Split(vdirs, ",")
	for _, item := range items {
		if len(item) == 0 {
			continue
		}
		rv := strings.SplitN(item, ":", 2)
		var r, v string
		switch {
		case len(rv) == 1:
			r = filepath.Clean(rv[0])
			v = path.Join("/", filepath.Base(r))
		case len(rv) > 1:
			r = filepath.Clean(rv[0])
			v = path.Clean(path.Join("/", rv[1]))
		default:
			err = fmt.Errorf("Invalid vdir parameter %s\n", vdirs)
			return
		}
		if _, e := os.Stat(r); e != nil {
			err = e
			return
		}
		c.vmap[v] = r
	}
	return
}
