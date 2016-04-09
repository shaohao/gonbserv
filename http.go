package main

import (
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"time"
)

type HTTPServer struct {
	listenAddr string
	vdt        *VDirTree
}

func (svr *HTTPServer) startServer() {
	svr.vdt = &VDirTree{
		rpath: "",
		vpath: "/",
	}
	http.HandleFunc("/", svr.rootHandle)
	http.HandleFunc("/static/", svr.staticHandle)
	http.HandleFunc("/fs/", svr.fsHandle)
	http.ListenAndServe(svr.listenAddr, nil)
}

func (svr *HTTPServer) shutdownServer() {
}

func (svr *HTTPServer) rootHandle(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/fs/", 308)
}

func (svr *HTTPServer) staticHandle(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, r.URL.Path[1:])
}

func humanizeSize(s int64) string {
	size := float64(s)
	units := []string{"B", "KB", "MB", "GB", "TB"}
	for i, u := range units {
		if size < 9*1000.0 {
			if i == 0 {
				break
			}
			return fmt.Sprintf("%.02f %s", size, u)
		}
		size /= 1024.0
	}
	return fmt.Sprintf("%d B", int64(s))
}

func humanizeTime(t time.Time) string {
	return fmt.Sprintf("%02d-%s-%04d %02d:%02d",
		t.Day(), t.Month().String()[:3], t.Year(),
		t.Hour(), t.Minute(),
	)
}

func pathHiSplit(p string) []string {
	dir := path.Dir(p)
	base := path.Base(p)
	if dir == base {
		return []string{"/"}
	}
	return append(pathHiSplit(dir), p)
}

var funcMap = template.FuncMap{
	"humanize_size": humanizeSize,
	"humanize_time": humanizeTime,
	"path_base":     func(p string) string { return path.Base(p) },
	"path_dir":      func(p string) string { return path.Dir(p) },
	"path_hisplit":  pathHiSplit,
	"plus1":         func(x int) int { return x + 1 },
}

func (svr *HTTPServer) fsHandle(w http.ResponseWriter, r *http.Request) {
	vpath := path.Join("/", r.URL.Path[len("/fs/"):])
	rp, vp, err := svr.vdt.mapVPath(vpath)
	if err != nil {
		http.Error(w, http.StatusText(404), 404)
		return
	}
	switch r.Method {
	case "GET":
		svr.getHandle(rp, vp, w, r)
	case "POST":
		if !conf.writable {
			http.Error(w, http.StatusText(403), 403)
			return
		}
		svr.putHandle(rp, vp, w, r)
	}
}

func (svr *HTTPServer) putHandle(rp, vp string, w http.ResponseWriter, r *http.Request) {
	err := r.ParseMultipartForm(200000)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	formdata := r.MultipartForm
	for _, fhead := range formdata.File {
		fh, fn := fhead[0], fhead[0].Filename
		file, err := fh.Open()
		defer file.Close()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}

		out, err := os.Create(filepath.Join(rp, fn))
		defer out.Close()
		if err != nil {
			http.Error(w, "Unable to create the file for writing.", 500)
			return
		}

		log.Printf("Receiving file: %s", fn)
		_, err = io.Copy(out, file)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
	}
}

func (svr *HTTPServer) getHandle(rp, vp string, w http.ResponseWriter, r *http.Request) {
	if vp != "/" {
		fi, err := os.Stat(rp)
		if err != nil {
			http.Error(w, http.StatusText(500), 500)
			return
		}
		if fi.Mode().IsRegular() {
			http.ServeFile(w, r, rp)
			return
		}
	}
	lst, err := svr.vdt.doLIST(vp)
	if err != nil {
		http.Error(w, http.StatusText(500), 500)
		return
	}
	tpl := template.Must(template.New("main").Funcs(funcMap).ParseGlob("*.html"))
	content := map[string]interface{}{
		"CWD":        path.Clean(vp),
		"IsVRoot":    vp == "/",
		"Items":      lst,
		"IsWritable": conf.writable && vp != "/",
	}
	tpl.ExecuteTemplate(w, "index.html", content)
}
