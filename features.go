package main

// features.go: fail2ban, logs, HTTP/3, auto reload, .htpasswd.
// Same package as main.go; registers its own tabs and routes in init().

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var featureTabs = [][2]string{{"f2b", "fail2ban"}, {"logs", "logs"}, {"h3", "http/3"}, {"htpasswd", ".htpasswd"}, {"autoreload", "auto reload"}}

var featureRoutes = map[string]http.HandlerFunc{
	"/f2b": f2bTab, "/f2b/do": f2bDo, "/logs": logsTab, "/h3": h3Tab, "/h3/do": h3Do,
	"/htpasswd": htTab, "/htpasswd/do": htDo, "/autoreload": arTab, "/autoreload/do": arDo,
}

var (
	logRoot = env("LOG_DIR", root+"/log")
	htPath  = env("HTPASSWD", base+"/.htpasswd")
	setPath = filepath.Join(root, ".swagui", "settings.json")
	setMu   sync.Mutex
	autoOn  = true
	snapMu  sync.Mutex
	applyMu sync.Mutex
	snap    string
	badSnap string
)

func init() {
	tabs = append(tabs, featureTabs...)
	for p, h := range featureRoutes {
		http.HandleFunc(p, guard(h))
	}
	if len(os.Args) > 1 && os.Args[1] == "guard" {
		return
	}
	if b, err := os.ReadFile(setPath); err == nil {
		var s struct{ Auto *bool }
		if json.Unmarshal(b, &s) == nil && s.Auto != nil {
			autoOn = *s.Auto
		}
	}
	snap = snapshot()
	go autoWatcher()
}

// ---------------- guard whitelist (argv only, no shell) ----------------

var okCmd = []*regexp.Regexp{
	regexp.MustCompile(`^nginx (-t|-V|-s reload)$`),
	regexp.MustCompile(`^fail2ban-client status( [A-Za-z0-9_][A-Za-z0-9_-]{0,39})?$`),
	regexp.MustCompile(`^fail2ban-client set [A-Za-z0-9_][A-Za-z0-9_-]{0,39} (banip|unbanip) [0-9A-Fa-f:.]{2,45}$`),
}

func cmdAllowed(c []string) bool {
	for _, a := range c {
		if a == "" || strings.ContainsAny(a, " \t\r\n") {
			return false
		}
	}
	s := strings.Join(c, " ")
	for _, re := range okCmd {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

// ---------------- auto reload ----------------

func isAuto() bool { setMu.Lock(); defer setMu.Unlock(); return autoOn }

func snapshot() string {
	h := fnv.New64a()
	for _, d := range []string{base, filepath.Join(base, "proxy-confs"), filepath.Join(base, "site-confs")} {
		fs, _ := os.ReadDir(d)
		for _, f := range fs {
			if i, err := f.Info(); err == nil && !f.IsDir() && strings.HasSuffix(f.Name(), ".conf") {
				fmt.Fprintf(h, "%s/%s:%d:%d;", d, f.Name(), i.ModTime().UnixNano(), i.Size())
			}
		}
	}
	return fmt.Sprint(h.Sum64())
}

func pending() bool { snapMu.Lock(); defer snapMu.Unlock(); return snapshot() != snap }

// nginx -t; reload if force or automatic mode
func applyCfg(force bool) (string, bool) {
	applyMu.Lock()
	defer applyMu.Unlock()
	s := snapshot()
	o, c := run("nginx", "-t")
	ok := c == 0
	switch {
	case !ok:
		log.Println("[RELOAD] nginx -t failed, reload skipped")
		snapMu.Lock()
		badSnap = s
		snapMu.Unlock()
	case force || isAuto():
		o2, c2 := run("nginx", "-s", "reload")
		o, ok = o+o2, c2 == 0
		if ok {
			snapMu.Lock()
			snap = s
			snapMu.Unlock()
		}
	default:
		o += "\nmanual mode: config is valid, reload pending (use the reload button)"
	}
	lastAt, lastOK = time.Now(), ok
	return o, ok
}

func okMsg() string {
	if isAuto() {
		return "OK, nginx reloaded"
	}
	return "OK, saved and tested (manual mode: reload pending)"
}

func pendingBanner() string {
	if !pending() {
		return ""
	}
	return "<b>config changed, reload pending</b><form method=post action=/reload><input type=submit value='reload now'></form><hr>"
}

func autoWatcher() {
	for range time.Tick(5 * time.Second) {
		if !isAuto() || dkURL == "" {
			continue
		}
		s := snapshot()
		snapMu.Lock()
		skip := s == snap || s == badSnap
		snapMu.Unlock()
		if !skip {
			log.Println("[AUTO-RELOAD] external config change detected")
			applyCfg(true)
		}
	}
}

func arTab(w http.ResponseWriter, r *http.Request) {
	ck := func(b bool) string { return map[bool]string{true: " checked", false: ""}[b] }
	a := isAuto()
	page(w, "autoreload", fmt.Sprintf("<form method=post action=/autoreload/do>mode:<br><input type=radio name=mode value=manual%s> Manual: save + nginx -t, reload only by button<br><input type=radio name=mode value=auto%s> Automatic: reload after save and when config files change on disk (checked every 5s)<br><input type=submit value=apply></form><p>"+tbl+"<tr><td>reload pending<td>%v</tr><tr><td>last apply<td>%s</tr></table><form method=post action=/reload><input type=submit value='nginx -t + reload now'></form>", ck(!a), ck(a), pending(), e(lastApply())))
}

func arDo(w http.ResponseWriter, r *http.Request) {
	setMu.Lock()
	autoOn = r.FormValue("mode") == "auto"
	b, _ := json.Marshal(map[string]bool{"Auto": autoOn})
	setMu.Unlock()
	os.MkdirAll(filepath.Dir(setPath), 0755)
	os.WriteFile(setPath, b, 0644)
	http.Redirect(w, r, "/autoreload", 303)
}

// ---------------- fail2ban ----------------

var jailRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_-]{0,39}$`)

func f2bField(s, label string) string {
	m := regexp.MustCompile(label + `:[ \t]*(.*)`).FindStringSubmatch(s)
	if m == nil {
		return "-"
	}
	return strings.TrimSpace(m[1])
}

func f2bTab(w http.ResponseWriter, r *http.Request) {
	out, code := run("fail2ban-client", "status")
	if code != 0 {
		page(w, "f2b", "<b>fail2ban-client failed</b><pre>"+e(out)+"</pre>")
		return
	}
	var jails []string
	for _, j := range strings.Split(f2bField(out, "Jail list"), ",") {
		if j = strings.TrimSpace(j); j != "" && j != "-" {
			jails = append(jails, j)
		}
	}
	var s, opt strings.Builder
	s.WriteString(tbl + "<tr><th>jail<th>failed<th>banned<th>total<th>banned IPs</tr>")
	for _, j := range jails {
		o, _ := run("fail2ban-client", "status", j)
		var ips strings.Builder
		for _, ip := range strings.Fields(f2bField(o, "Banned IP list")) {
			fmt.Fprintf(&ips, "<form method=post action=/f2b/do>%s <input type=hidden name=jail value='%s'><input type=hidden name=ip value='%s'><input type=hidden name=op value=unbanip><input type=submit value=unban></form>", e(ip), e(j), e(ip))
		}
		fmt.Fprintf(&s, "<tr><td>%s<td>%s<td>%s<td>%s<td>%s</tr>", e(j), e(f2bField(o, "Currently failed")), e(f2bField(o, "Currently banned")), e(f2bField(o, "Total banned")), ips.String())
		fmt.Fprintf(&opt, "<option>%s</option>", e(j))
	}
	s.WriteString("</table><h3>ban manually</h3><form method=post action=/f2b/do><input type=hidden name=op value=banip><select name=jail>" + opt.String() + "</select> IP: <input name=ip size=40> <input type=submit value=ban></form>")
	page(w, "f2b", s.String())
}

func f2bDo(w http.ResponseWriter, r *http.Request) {
	jail, ip, op := r.FormValue("jail"), strings.TrimSpace(r.FormValue("ip")), r.FormValue("op")
	if !jailRe.MatchString(jail) || net.ParseIP(ip) == nil || (op != "banip" && op != "unbanip") {
		http.Error(w, "bad input", 400)
		return
	}
	out, code := run("fail2ban-client", "set", jail, op, ip)
	result(w, fmt.Sprintf("%s %s in %s: exit %d", op, ip, jail, code), out, "/f2b")
}

// ---------------- logs: product / type / lines ----------------

func listNames(dir string, dirs bool) (r []string) {
	fs, _ := os.ReadDir(dir)
	for _, f := range fs {
		if dirs && f.IsDir() || !dirs && !f.IsDir() && regexp.MustCompile(`\.log(\.\d+)?$`).MatchString(f.Name()) {
			r = append(r, f.Name())
		}
	}
	return
}

func has(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func tailLines(path string, n int, f string) ([]string, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	st, _ := fh.Stat()
	off := int64(0)
	if st.Size() > 8<<20 {
		off = st.Size() - 8<<20
	}
	fh.Seek(off, io.SeekStart)
	b, _ := io.ReadAll(fh)
	ls := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if off > 0 {
		ls = ls[1:]
	}
	if f != "" {
		k := ls[:0]
		for _, l := range ls {
			if strings.Contains(l, f) {
				k = append(k, l)
			}
		}
		ls = k
	}
	if len(ls) > n {
		ls = ls[len(ls)-n:]
	}
	return ls, nil
}

func logsTab(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	prods := listNames(logRoot, true)
	p := q.Get("p")
	if !has(prods, p) {
		p = ""
		if has(prods, "nginx") {
			p = "nginx"
		} else if len(prods) > 0 {
			p = prods[0]
		}
	}
	types := listNames(filepath.Join(logRoot, p), false)
	t := q.Get("t")
	if !has(types, t) {
		t = ""
		if len(types) > 0 {
			t = types[0]
		}
	}
	n, _ := strconv.Atoi(q.Get("n"))
	if n < 1 || n > 5000 {
		n = 100
	}
	var s strings.Builder
	s.WriteString("product: ")
	for _, x := range prods {
		if x == p {
			s.WriteString("<b>[ " + e(x) + " ]</b> ")
		} else {
			s.WriteString("<a href='/logs?p=" + url.QueryEscape(x) + "'>[ " + e(x) + " ]</a> ")
		}
	}
	s.WriteString("<br>type: ")
	for _, x := range types {
		if x == t {
			s.WriteString("<b>[ " + e(x) + " ]</b> ")
		} else {
			s.WriteString("<a href='/logs?p=" + url.QueryEscape(p) + "&t=" + url.QueryEscape(x) + "'>[ " + e(x) + " ]</a> ")
		}
	}
	s.WriteString("<form method=get action=/logs><input type=hidden name=p value='" + e(p) + "'><input type=hidden name=t value='" + e(t) + "'>lines: <select name=n>")
	for _, v := range []int{50, 100, 200, 500, 1000, 2000} {
		sel := ""
		if v == n {
			sel = " selected"
		}
		fmt.Fprintf(&s, "<option%s>%d</option>", sel, v)
	}
	rev := q.Get("rev") == "1"
	fmt.Fprintf(&s, "</select> filter: <input name=q value='%s'> <input type=checkbox name=rev value=1%s> newest first <input type=submit value=show></form><hr>", e(q.Get("q")), map[bool]string{true: " checked", false: ""}[rev])
	if t != "" {
		ls, err := tailLines(filepath.Join(logRoot, p, t), n, q.Get("q"))
		if err != nil {
			s.WriteString("<b>" + e(err.Error()) + "</b>")
		} else {
			if rev {
				for i, j := 0, len(ls)-1; i < j; i, j = i+1, j-1 {
					ls[i], ls[j] = ls[j], ls[i]
				}
			}
			s.WriteString("<pre>" + e(strings.Join(ls, "\n")) + "</pre>")
		}
	} else {
		s.WriteString("no log files in " + e(logRoot))
	}
	page(w, "logs", s.String())
}

// ---------------- HTTP/3 (marker-based, reversible) ----------------

const h3Tag = " # swag-ui:h3"

var (
	sslListen = regexp.MustCompile(`(?m)^([ \t]*)listen\s+(\[::\]:)?443\s+ssl([^;\n]*);[^\n]*$`)
	quicRe    = regexp.MustCompile(`(?m)^\s*listen\s+(\[::\]:)?443\s+quic`)
)

func h3On(s string) string {
	if strings.Contains(s, h3Tag) {
		return s
	}
	return sslListen.ReplaceAllStringFunc(s, func(l string) string {
		m := sslListen.FindStringSubmatch(l)
		ind, v6, q := m[1], m[2], "443 quic"
		if strings.Contains(m[3], "default_server") {
			q += " reuseport default_server"
		}
		o := l + "\n" + ind + "listen " + v6 + q + ";" + h3Tag
		if v6 == "" {
			o += "\n" + ind + "http3 on;" + h3Tag + "\n" + ind + `add_header Alt-Svc 'h3=":443"; ma=86400' always;` + h3Tag
		}
		return o
	})
}

func h3Off(s string) string {
	var k []string
	for _, l := range strings.Split(s, "\n") {
		if !strings.Contains(l, h3Tag) {
			k = append(k, l)
		}
	}
	return strings.Join(k, "\n")
}

func h3Files() []string {
	r := []string{"site-confs/default.conf"}
	ns, _ := list("proxy-confs")
	for _, n := range ns {
		if strings.HasSuffix(n, ".conf") {
			r = append(r, "proxy-confs/"+n)
		}
	}
	return r
}

func h3Tab(w http.ResponseWriter, r *http.Request) {
	v, _ := run("nginx", "-V")
	udp := "unknown (docker api off)"
	if cts, derr := loadCts(); derr == "" {
		udp = "NO: publish 443:443/udp on the swag container"
		for _, c := range cts {
			if c.name() == swag {
				for _, p := range c.Ports {
					if p.Type == "udp" && p.PrivatePort == 443 {
						udp = "yes"
					}
				}
			}
		}
	}
	var s strings.Builder
	fmt.Fprintf(&s, tbl+"<tr><td>nginx http_v3_module<td>%v</tr><tr><td>UDP 443 published<td>%s</tr></table><p>"+tbl+"<tr><th>file<th>http/3<th>action</tr>", strings.Contains(v, "http_v3_module"), e(udp))
	for _, n := range h3Files() {
		st := "missing"
		if b, err := os.ReadFile(filepath.Join(base, n)); err == nil {
			switch c := string(b); {
			case strings.Contains(c, h3Tag):
				st = "ON (swag-ui)"
			case quicRe.MatchString(c):
				st = "ON (manual)"
			case sslListen.MatchString(c):
				st = "off"
			default:
				st = "n/a (no 443 ssl listen)"
			}
		}
		btn := ""
		if st == "off" || st == "ON (swag-ui)" {
			op := map[bool]string{true: "off", false: "on"}[st != "off"]
			btn = fmt.Sprintf("<form method=post action=/h3/do><input type=hidden name=f value='%s'><input type=hidden name=op value=%s><input type=submit value=%s></form>", e(n), op, op)
		}
		fmt.Fprintf(&s, "<tr><td>%s<td>%s<td>%s</tr>", e(n), st, btn)
	}
	s.WriteString("</table><form method=post action=/h3/do><input type=hidden name=f value='*'><input type=submit name=op value=on> <input type=submit name=op value=off> all files</form>")
	page(w, "h3", s.String())
}

func h3Do(w http.ResponseWriter, r *http.Request) {
	op, f := r.FormValue("op"), r.FormValue("f")
	files := h3Files()
	if f != "*" {
		if !has(files, f) {
			http.Error(w, "bad file", 400)
			return
		}
		files = []string{f}
	}
	old := map[string][]byte{}
	for _, n := range files {
		p := filepath.Join(base, n)
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		ns := h3Off(string(b))
		if op == "on" {
			ns = h3On(string(b))
		}
		if ns != string(b) {
			old[n] = b
			os.WriteFile(p, []byte(ns), 0644)
		}
	}
	if len(old) == 0 {
		result(w, "nothing to change", "", "/h3")
		return
	}
	out, ok := apply()
	if !ok {
		for n, b := range old {
			os.WriteFile(filepath.Join(base, n), b, 0644)
		}
		result(w, "FAILED, rolled back", out, "/h3")
		return
	}
	result(w, fmt.Sprintf("OK: %d file(s) changed", len(old)), out, "/h3")
}

// ---------------- .htpasswd (apr1-md5, no dependencies) ----------------

const a64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

var userRe = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,64}$`)

func apr1(pw, salt string) string {
	p, s := []byte(pw), []byte(salt)
	alt := md5.Sum(append(append(append([]byte{}, p...), s...), p...))
	c := md5.New()
	c.Write(p)
	c.Write([]byte("$apr1$"))
	c.Write(s)
	for l := len(p); l > 0; l -= 16 {
		if l > 16 {
			c.Write(alt[:])
		} else {
			c.Write(alt[:l])
		}
	}
	for i := len(p); i > 0; i >>= 1 {
		if i&1 == 1 {
			c.Write([]byte{0})
		} else {
			c.Write(p[:1])
		}
	}
	f := c.Sum(nil)
	for i := 0; i < 1000; i++ {
		c = md5.New()
		if i&1 == 1 {
			c.Write(p)
		} else {
			c.Write(f)
		}
		if i%3 != 0 {
			c.Write(s)
		}
		if i%7 != 0 {
			c.Write(p)
		}
		if i&1 == 1 {
			c.Write(f)
		} else {
			c.Write(p)
		}
		f = c.Sum(nil)
	}
	var o strings.Builder
	for _, g := range [][3]int{{0, 6, 12}, {1, 7, 13}, {2, 8, 14}, {3, 9, 15}, {4, 10, 5}} {
		v := int(f[g[0]])<<16 | int(f[g[1]])<<8 | int(f[g[2]])
		for i := 0; i < 4; i++ {
			o.WriteByte(a64[v&63])
			v >>= 6
		}
	}
	v := int(f[11])
	for i := 0; i < 2; i++ {
		o.WriteByte(a64[v&63])
		v >>= 6
	}
	return "$apr1$" + salt + "$" + o.String()
}

func htLines() (r []string) {
	b, _ := os.ReadFile(htPath)
	for _, l := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(l) != "" {
			r = append(r, l)
		}
	}
	return
}

func htTab(w http.ResponseWriter, r *http.Request) {
	var s strings.Builder
	fmt.Fprintf(&s, "file: %s<p>"+tbl+"<tr><th>user<th>action</tr>", e(htPath))
	for _, l := range htLines() {
		u, _, _ := strings.Cut(l, ":")
		fmt.Fprintf(&s, "<tr><td>%s<td><form method=post action=/htpasswd/do><input type=hidden name=op value=del><input type=hidden name=user value='%s'><input type=submit value=delete></form></tr>", e(u), e(u))
	}
	s.WriteString("</table><h3>add / change password</h3><form method=post action=/htpasswd/do><input type=hidden name=op value=add>user: <input name=user> password: <input type=password name=password> <input type=submit value=save></form><h3>use in a proxy-conf (server or location)</h3><pre>auth_basic \"Restricted\";\nauth_basic_user_file /config/nginx/.htpasswd;</pre>nginx re-reads the file per request, no reload needed.")
	page(w, "htpasswd", s.String())
}

func htDo(w http.ResponseWriter, r *http.Request) {
	op, u, pw := r.FormValue("op"), r.FormValue("user"), r.FormValue("password")
	if !userRe.MatchString(u) || (op != "add" && op != "del") || (op == "add" && (pw == "" || len(pw) > 128)) {
		http.Error(w, "bad input", 400)
		return
	}
	var out []string
	for _, l := range htLines() {
		if !strings.HasPrefix(l, u+":") {
			out = append(out, l)
		}
	}
	if op == "add" {
		b := make([]byte, 8)
		rand.Read(b)
		for i := range b {
			b[i] = a64[int(b[i])&63]
		}
		out = append(out, u+":"+apr1(pw, string(b)))
	}
	tmp := htPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(strings.Join(out, "\n")+"\n"), 0644); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	os.Rename(tmp, htPath)
	http.Redirect(w, r, "/htpasswd", 303)
}
