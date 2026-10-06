package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html"
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

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

var (
	root   = env("CONFIG_DIR", "/config")
	base   = env("NGINX_DIR", root+"/nginx")
	le     = env("LE_DIR", root+"/etc/letsencrypt/live")
	swag   = env("SWAG_CONTAINER", "swag")
	user   = env("UI_USER", "admin")
	pass   = os.Getenv("UI_PASS")
	e      = html.EscapeString
	nameRe = regexp.MustCompile(`^((proxy-confs|site-confs)/)?[A-Za-z0-9._-]+\.conf(\.sample)?$`)
	srvRe  = regexp.MustCompile(`(?m)^\s*server_name\s+([^;]+);`)
	appRe  = regexp.MustCompile(`(?m)^\s*set\s+\$upstream_app\s+"?([^";\s]+)"?\s*;`)
	portRe = regexp.MustCompile(`(?m)^\s*set\s+\$upstream_port\s+"?([^";\s]+)"?\s*;`)
	hc     = &http.Client{Timeout: 4 * time.Second}
	dkURL  string
)

// ---- docker (optional, read-only: DOCKER_HOST=tcp://proxy:2375 or DOCKER_SOCK) ----

func initDocker() {
	if h := os.Getenv("DOCKER_HOST"); strings.HasPrefix(h, "tcp://") {
		dkURL = "http://" + strings.TrimPrefix(h, "tcp://")
	} else if s := env("DOCKER_SOCK", "/var/run/docker.sock"); fileExists(s) {
		dkURL = "http://d"
		hc.Transport = &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", s)
		}}
	}
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

type ct struct {
	Names         []string
	Image, Status string
	Labels        map[string]string
	Ports         []struct {
		PrivatePort, PublicPort int
		Type                    string
	}
	NetworkSettings struct {
		Networks map[string]struct {
			Aliases   []string
			IPAddress string
		}
	}
}

func (c ct) name() string {
	if len(c.Names) == 0 {
		return "?"
	}
	return strings.TrimPrefix(c.Names[0], "/")
}

func (c ct) ids() (r []string) {
	for _, n := range c.Names {
		r = append(r, strings.TrimPrefix(n, "/"))
	}
	if s := c.Labels["com.docker.compose.service"]; s != "" {
		r = append(r, s)
	}
	for _, n := range c.NetworkSettings.Networks {
		r = append(r, n.Aliases...)
		if n.IPAddress != "" {
			r = append(r, n.IPAddress)
		}
	}
	return
}

func loadCts() ([]ct, string) {
	if dkURL == "" {
		return nil, "docker api off (set DOCKER_HOST=tcp://docker-proxy:2375)"
	}
	resp, err := hc.Get(dkURL + "/containers/json")
	if err != nil {
		return nil, err.Error()
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var cs []ct
	if err := json.Unmarshal(b, &cs); err != nil {
		return nil, string(b)
	}
	return cs, ""
}

// ---- upstreams <-> containers ----

type up struct{ Conf, Host, App, Port string }

func upstreams() (r []up) {
	ns, _ := list("proxy-confs")
	for _, n := range ns {
		if !strings.HasSuffix(n, ".conf") {
			continue
		}
		b, _ := os.ReadFile(filepath.Join(base, "proxy-confs", n))
		s, host := string(b), ""
		if m := srvRe.FindStringSubmatch(s); m != nil {
			host = strings.Join(strings.Fields(m[1]), " ")
		}
		as, ps, seen := appRe.FindAllStringSubmatch(s, -1), portRe.FindAllStringSubmatch(s, -1), map[string]bool{}
		for i, a := range as {
			p := ""
			if i < len(ps) {
				p = ps[i][1]
			}
			if k := a[1] + ":" + p; !seen[k] {
				seen[k] = true
				r = append(r, up{n, host, a[1], p})
			}
		}
	}
	return
}

// by name/alias/compose service/container IP; or, if app is an IP / host.docker.internal, by published host port
func match(u up, cts []ct) *ct {
	for i := range cts {
		for _, id := range cts[i].ids() {
			if id == u.App {
				return &cts[i]
			}
		}
	}
	if p, _ := strconv.Atoi(u.Port); p > 0 && (net.ParseIP(u.App) != nil || u.App == "host.docker.internal") {
		for i := range cts {
			for _, cp := range cts[i].Ports {
				if cp.PublicPort == p {
					return &cts[i]
				}
			}
		}
	}
	return nil
}

func swagNets(cts []ct) map[string]bool {
	m := map[string]bool{}
	for _, c := range cts {
		if c.name() == swag {
			for k := range c.NetworkSettings.Networks {
				m[k] = true
			}
		}
	}
	return m
}

func shared(c ct, sn map[string]bool) bool {
	for k := range c.NetworkSettings.Networks {
		if sn[k] {
			return true
		}
	}
	return false
}

// ---- reload via docker exec (through swag-guard, or socket directly) ----

var (
	lastAt time.Time
	lastOK bool
)

func dkPost(path string, body any) []byte {
	bs, _ := json.Marshal(body)
	resp, err := hc.Post(dkURL+path, "application/json", bytes.NewReader(bs))
	if err != nil {
		return []byte(err.Error())
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return b
}

func run(cmd ...string) (string, int) {
  log.Printf("[UI-DOCKER] Initiating 'exec' command inside swag container: %v", cmd)
	if dkURL == "" {
		return "docker api off", 1
	}
	b := dkPost("/containers/"+swag+"/exec", map[string]any{"AttachStdout": true, "AttachStderr": true, "Cmd": cmd})
	var x struct{ Id string }
	json.Unmarshal(b, &x)
	if x.Id == "" {
		return "exec create failed: " + string(b), 1
	}
	raw := dkPost("/exec/"+x.Id+"/start", map[string]any{})
	var out bytes.Buffer
	for len(raw) >= 8 {
		n := int(binary.BigEndian.Uint32(raw[4:8]))
		raw = raw[8:]
		if n > len(raw) {
			n = len(raw)
		}
		out.Write(raw[:n])
		raw = raw[n:]
	}
	var st struct{ ExitCode int }
	if resp, err := hc.Get(dkURL + "/exec/" + x.Id + "/json"); err == nil {
		json.NewDecoder(resp.Body).Decode(&st)
		resp.Body.Close()
	}
	log.Printf("[UI-DOCKER] Exec process finished. Command: %v. ExitCode: %d", cmd, st.ExitCode)
	return out.String(), st.ExitCode
}

func apply() (string, bool) {
	log.Println("[UI-RELOAD] Configuration change triggered. Running 'nginx -t' validation...")
	o, c := run("nginx", "-t")
	ok := c == 0
	if ok {
		log.Println("[UI-RELOAD] 'nginx -t' passed successfully. Executing 'nginx -s reload'...")
		o2, c2 := run("nginx", "-s", "reload")
		o, ok = o+o2, c2 == 0
	} else {
		log.Println("[UI-RELOAD] CRITICAL: 'nginx -t' validation failed. Reload aborted to prevent downtime.")
	}
	
	lastAt, lastOK = time.Now(), ok
	log.Printf("[UI-RELOAD] Finished configuration application cycle. Success status: %v", ok)
	return o, ok
}

func lastApply() string {
	if lastAt.IsZero() {
		return "never (since swag-ui start)"
	}
	st := "OK"
	if !lastOK {
		st = "FAILED"
	}
	return lastAt.Format("2006-01-02 15:04:05") + " " + st
}

// ---- guard mode: minimal filtering proxy in front of docker.sock ----

func guardMode() {
	if dkURL == "" {
		log.Fatal("[GUARD] Critical error: no docker socket or DOCKER_HOST found")
	}
	log.Printf("[GUARD] Successfully connected to backend Docker API at: %s", dkURL)
	
	var mu sync.Mutex
	known := map[string]bool{}
	cmds := map[string]bool{"nginx -t": true, "nginx -s reload": true}
	
	do := func(method, path string, body []byte) (int, []byte) {
		log.Printf("[GUARD-PROXY] Forwarding request to Docker: %s %s", method, path)
		req, _ := http.NewRequest(method, dkURL+path, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := hc.Do(req)
		if err != nil {
			log.Printf("[GUARD-ERROR] Failed to contact Docker daemon: %v", err)
			return 502, []byte(err.Error())
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		log.Printf("[GUARD-PROXY] Docker backend responded with status: %d (bytes received: %d)", resp.StatusCode, len(b))
		return resp.StatusCode, b
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		p, code, out := r.URL.Path, 403, []byte("forbidden by swag-guard")
		log.Printf("[GUARD-REQUEST] Incoming intercept: %s %s from %s", r.Method, p, r.RemoteAddr)

		isID := func(suffix string) (string, bool) {
			id := strings.TrimSuffix(strings.TrimPrefix(p, "/exec/"), suffix)
			mu.Lock()
			defer mu.Unlock()
			hasPrefix := strings.HasPrefix(p, "/exec/")
			hasSuffix := strings.HasSuffix(p, suffix)
			isKnown := known[id]
			return id, hasPrefix && hasSuffix && isKnown
		}

		switch {
		case r.Method == "GET" && p == "/containers/json":
			log.Println("[GUARD-ACCESS] Route allowed: listing containers")
			code, out = do("GET", p, nil)

		case r.Method == "POST" && p == "/containers/"+swag+"/exec":
			var q struct{ Cmd []string }
			// Читаем тело запроса аккуратно, логируя попытки
			bodyBytes, _ := io.ReadAll(io.LimitReader(r.Body, 1024))
			r.Body.Close()
			
			if json.Unmarshal(bodyBytes, &q) == nil {
				fullCmd := strings.Join(q.Cmd, " ")
				log.Printf("[GUARD-EXEC] Intercepted exec request for container '%s'. Command: '%s'", swag, fullCmd)
				
				if cmds[fullCmd] {
					log.Printf("[GUARD-ACCESS] Command '%s' is VALID. Proxying exec creation...", fullCmd)
					bs, _ := json.Marshal(map[string]any{"AttachStdout": true, "AttachStderr": true, "Cmd": q.Cmd})
					code, out = do("POST", p, bs)
					
					var x struct{ Id string }
					if json.Unmarshal(out, &x) == nil && x.Id != "" {
						mu.Lock()
						known[x.Id] = true
						mu.Unlock()
						log.Printf("[GUARD-TRACK] Registered approved Exec ID: %s", x.Id)
					}
				} else {
					log.Printf("[GUARD-DENIED] Security alert: Command '%s' is NOT ALLOWED inside container '%s'", fullCmd, swag)
					code = 403
					out = []byte("forbidden command by swag-guard")
				}
			} else {
				log.Println("[GUARD-ERROR] Failed to parse JSON body for container exec request")
				code = 400
				out = []byte("bad request")
			}

		case r.Method == "POST":
			if id, ok := isID("/start"); ok {
				log.Printf("[GUARD-ACCESS] Route allowed: Starting previously approved Exec session ID: %s", id)
				code, out = do("POST", p, []byte("{}"))
			} else {
				log.Printf("[GUARD-DENIED] Blocked unauthorized POST request or unverified Exec ID on path: %s", p)
			}

		case r.Method == "GET":
			if id, ok := isID("/json"); ok {
				log.Printf("[GUARD-ACCESS] Route allowed: Inspecting approved Exec session results for ID: %s", id)
				code, out = do("GET", p, nil)
			} else {
				log.Printf("[GUARD-DENIED] Blocked unauthorized GET request or unverified Exec ID on path: %s", p)
			}
			
		default:
			log.Printf("[GUARD-DENIED] Request method/path combination is completely unhandled: %s %s", r.Method, p)
		}

		w.WriteHeader(code)
		w.Write(out)
	})

	log.Printf("[GUARD] Server is up and listening on port %s", env("LISTEN", ":2375"))
	log.Fatal(http.ListenAndServe(env("LISTEN", ":2375"), mux))
}

// ---- html ----

var tabs = [][2]string{{"", "dashboard"}, {"containers", "docker ps"}, {"confs", "proxy-confs"}, {"files", "nginx files"}, {"certs", "certs/domains"}}

func page(w http.ResponseWriter, cur, body string) {
	nav := ""
	for _, t := range tabs {
		if t[0] == cur {
			nav += "<b>[ " + t[1] + " ]</b> "
		} else {
			nav += "<a href=/" + t[0] + ">[ " + t[1] + " ]</a> "
		}
	}
	fmt.Fprintf(w, "<!doctype html><meta charset=utf-8><title>swag-ui</title><tt>SWAG-UI swag=%s nginx=%s<br>%s<hr>%s</tt>", e(swag), e(base), nav, body)
}

func list(sub string) ([]string, error) {
	fs, err := os.ReadDir(filepath.Join(base, sub))
	var r []string
	for _, f := range fs {
		if !f.IsDir() && nameRe.MatchString(f.Name()) {
			r = append(r, f.Name())
		}
	}
	return r, err
}

const tbl = "<table border=1 cellpadding=3>"

func dash(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	ups := upstreams()
	cts, derr := loadCts()
	cs, _ := loadCerts()
	hrs := hostRows(cs)
	ns, _ := list("proxy-confs")
	on, off := 0, 0
	for _, n := range ns {
		if strings.HasSuffix(n, ".conf") {
			on++
		} else {
			off++
		}
	}
	sn := swagNets(cts)
	var prob []string
	for _, c := range cs {
		if c.status() != "OK" {
			prob = append(prob, fmt.Sprintf("cert %s: %s (%d days)", c.Name, c.status(), c.days()))
		}
	}
	certOf := map[string]string{}
	for _, h := range hrs {
		if _, ok := certOf[h.Conf]; !ok {
			certOf[h.Conf] = h.Status
		}
		if h.Status == "NO CERT" {
			prob = append(prob, "no cert for "+h.Host+" ("+h.Conf+")")
		}
	}
	var s strings.Builder
	s.WriteString("<h3>services (active proxy-confs &rarr; upstream &rarr; container)</h3>" + tbl + "<tr><th>conf<th>server_name<th>upstream<th>container<th>container status<th>swag net<th>cert</tr>")
	
	for _, u := range ups {
		cn, st, nt := "-", "-", "-"
		if derr == "" {
			if c := match(u, cts); c != nil {
				cn, st, nt = c.name(), c.Status, "yes"
				if !shared(*c, sn) {
					nt = "NO"
					prob = append(prob, c.name()+" is not in swag network ("+u.Conf+")")
				}
			} else {
				cn = "NOT FOUND"
				prob = append(prob, "upstream "+u.App+":"+u.Port+" not matched to a container ("+u.Conf+")")
			}
		}

		// ---- МОДЕРНИЗАЦИЯ: Разбираем хосты и делаем их кликабельными ссылками ----
		var links []string
		// server_name может содержать несколько доменов через пробел
		for _, rawHost := range strings.Fields(u.Host) {
			if rawHost == "_" {
				links = append(links, "_")
				continue
			}

			displayHost := rawHost
			// Если домен заканчивается на .*, ищем реальный домен в сертификатах
			if pre, ok := strings.CutSuffix(rawHost, ".*"); ok && len(cs) > 0 {
				for _, c := range cs {
					fullMatch := pre + "." + c.Name
					if c.covers(fullMatch) {
						displayHost = fullMatch
						break
					}
				}
			}

			// Оборачиваем готовый домен в красивую HTML-ссылку
			links = append(links, fmt.Sprintf("<a href='https://%s' target='_blank' style='text-decoration:underline; color:#0066cc;'>%s</a>", displayHost, e(displayHost)))
		}
		// Склеиваем ссылки обратно через пробел
		formattedHosts := strings.Join(links, " ")
		// -----------------------------------------------------------------------

		// Выводим строку таблицы (вместо e(u.Host) теперь подставляем нашу строку formattedHosts)
		fmt.Fprintf(&s, "<tr><td>%s<td>%s<td>%s:%s<td>%s<td>%s<td>%s<td>%s</tr>", e(u.Conf), formattedHosts, e(u.App), e(u.Port), e(cn), e(st), nt, certOf[u.Conf])
	}
	s.WriteString("</table>")
	pr := "none"
	if len(prob) > 0 {
		pr = "<b>" + e(strings.Join(prob, "\n")) + "</b>"
		pr = strings.ReplaceAll(pr, "\n", "<br>")
	}
	run := "n/a"
	if derr == "" {
		run = fmt.Sprint(len(cts))
	}
	head := fmt.Sprintf("<h3>status</h3>"+tbl+"<tr><td>last nginx apply<td>%s</tr><tr><td>proxy-confs active / samples<td>%d / %d</tr><tr><td>certificates<td>%d</tr><tr><td>running containers<td>%s</tr><tr><td>problems<td>%s</tr></table>", e(lastApply()), on, off, len(cs), run, pr)
	page(w, "", head+s.String())
}


func containers(w http.ResponseWriter, r *http.Request) {
	cts, derr := loadCts()
	if derr != "" {
		page(w, "containers", "<b>"+e(derr)+"</b>")
		return
	}
	sn, by := swagNets(cts), map[string][]string{}
	for _, u := range upstreams() {
		if c := match(u, cts); c != nil {
			by[c.name()] = append(by[c.name()], fmt.Sprintf("%s (%s:%s)", u.Conf, u.App, u.Port))
		}
	}
	var s strings.Builder
	s.WriteString(tbl + "<tr><th>name<th>image<th>status<th>ports (in&rarr;host)<th>in swag net<th>proxied by<th>action</tr>")
	for _, c := range cts {
		n := c.name()
		if n == swag {
			continue
		}
		seen, ports, act := map[int]bool{}, []string{}, []string{}
		for _, p := range c.Ports {
			if p.Type != "tcp" || (seen[p.PrivatePort] && p.PublicPort == 0) {
				continue
			}
			t := fmt.Sprint(p.PrivatePort)
			if p.PublicPort > 0 {
				t += fmt.Sprintf("&rarr;%d", p.PublicPort)
			}
			ports = append(ports, t)
			if !seen[p.PrivatePort] {
				act = append(act, fmt.Sprintf("<a href='/new?name=%s&port=%d'>proxy :%d</a>", url.QueryEscape(n), p.PrivatePort, p.PrivatePort))
			}
			seen[p.PrivatePort] = true
		}
		sh := "yes"
		if !shared(c, sn) {
			sh = "no"
			for k := range c.NetworkSettings.Networks {
				sh = "no: docker network connect " + e(k) + " " + e(swag)
				break
			}
		}
		px := "-"
		if v := by[n]; len(v) > 0 {
			px = "<b>YES</b> " + e(strings.Join(v, ", "))
		}
		if len(act) == 0 {
			act = []string{"<a href='/new?name=" + url.QueryEscape(n) + "&port=80'>proxy (set port)</a>"}
		}
		fmt.Fprintf(&s, "<tr><td>%s<td>%s<td>%s<td>%s<td>%s<td>%s<td>%s</tr>", e(n), e(c.Image), e(c.Status), strings.Join(ports, "<br>"), sh, px, strings.Join(act, "<br>"))
	}
	s.WriteString("</table>")
	page(w, "containers", s.String())
}

func rows(sub string, toggle bool, filter func(string) bool) string {
	ns, _ := list(sub)
	var s strings.Builder
	for _, n := range ns {
		if !filter(n) {
			continue
		}
		f := n
		if sub != "" {
			f = sub + "/" + n
		}
		fmt.Fprintf(&s, "<tr><td><a href='/edit?f=%s'>%s</a>", url.QueryEscape(f), e(n))
		if toggle {
			lbl := "enable"
			if strings.HasSuffix(n, ".conf") {
				lbl = "disable"
			}
			fmt.Fprintf(&s, "<td><form method=post action=/toggle><input type=hidden name=f value='%s'><input type=submit value=%s></form>", e(f), lbl)
		}
		s.WriteString("</tr>")
	}
	return s.String()
}

func confs(w http.ResponseWriter, r *http.Request) {
	ns, err := list("proxy-confs")
	diag := fmt.Sprintf("dir: %s/proxy-confs, files: %d", e(base), len(ns))
	if err != nil {
		diag += " <b>ERROR: " + e(err.Error()) + "</b>"
	}
	isOn := func(n string) bool { return strings.HasSuffix(n, ".conf") }
	isOff := func(n string) bool { return !isOn(n) }
	page(w, "confs", fmt.Sprintf("<a href=/new>[ new file ]</a> %s<h3>active</h3>"+tbl+"%s</table><h3>samples / disabled</h3>"+tbl+"%s</table>", diag, rows("proxy-confs", true, isOn), rows("proxy-confs", true, isOff)))
}

func files(w http.ResponseWriter, r *http.Request) {
	isOn := func(n string) bool { return strings.HasSuffix(n, ".conf") }
	page(w, "files", fmt.Sprintf("<h3>%s</h3>"+tbl+"%s</table><h3>site-confs</h3>"+tbl+"%s</table><p><form method=post action=/reload><input type=submit value='nginx -t + reload'></form>", e(base), rows("", false, isOn), rows("site-confs", false, isOn)))
}

// ---- certs ----

type cert struct {
	Name, Issuer string
	SANs         []string
	NotAfter     time.Time
}

func (c cert) days() int { return int(time.Until(c.NotAfter).Hours() / 24) }
func (c cert) status() string {
	switch d := c.days(); {
	case d < 0:
		return "EXPIRED"
	case d <= 14:
		return "CRITICAL"
	case d <= 30:
		return "RENEW DUE"
	}
	return "OK"
}
func (c cert) covers(h string) bool {
	for _, s := range c.SANs {
		if s == h || (strings.HasPrefix(s, "*.") && strings.Count(h, ".") == strings.Count(s, ".") && strings.HasSuffix(h, s[1:])) {
			return true
		}
	}
	return false
}

func loadCerts() (cs []cert, err error) {
	ds, err := os.ReadDir(le)
	for _, d := range ds {
		b, e1 := os.ReadFile(filepath.Join(le, d.Name(), "fullchain.pem"))
		if e1 != nil {
			continue
		}
		blk, _ := pem.Decode(b)
		if blk == nil {
			continue
		}
		if x, e2 := x509.ParseCertificate(blk.Bytes); e2 == nil {
			cs = append(cs, cert{d.Name(), x.Issuer.CommonName, x.DNSNames, x.NotAfter})
		}
	}
	return
}

type hostRow struct{ Conf, Host, Cert, Days, Status string }

func hostRows(cs []cert) (r []hostRow) {
	ns, _ := list("proxy-confs")
	for _, n := range ns {
		if !strings.HasSuffix(n, ".conf") {
			continue
		}
		b, _ := os.ReadFile(filepath.Join(base, "proxy-confs", n))
		for _, m := range srvRe.FindAllStringSubmatch(string(b), -1) {
			for _, tok := range strings.Fields(m[1]) {
				if tok == "_" {
					continue
				}
				hosts := []string{tok}
				if pre, ok := strings.CutSuffix(tok, ".*"); ok && len(cs) > 0 {
					hosts = nil
					for _, c := range cs {
						hosts = append(hosts, pre+"."+c.Name)
					}
				}
				for _, h := range hosts {
					row := hostRow{n, h, "-", "-", "NO CERT"}
					for _, c := range cs {
						if c.covers(h) {
							row.Cert, row.Days, row.Status = c.Name, fmt.Sprint(c.days()), c.status()
							break
						}
					}
					r = append(r, row)
				}
			}
		}
	}
	return
}

func certsTab(w http.ResponseWriter, r *http.Request) {
	cs, err := loadCerts()
	var s strings.Builder
	if err != nil {
		s.WriteString("<b>ERROR " + e(le) + ": " + e(err.Error()) + "</b>")
	}
	s.WriteString("<h3>certificates</h3>" + tbl + "<tr><th>name<th>SAN<th>issuer<th>expires<th>days<th>status</tr>")
	for _, c := range cs {
		fmt.Fprintf(&s, "<tr><td>%s<td>%s<td>%s<td>%s<td>%d<td>%s</tr>", e(c.Name), e(strings.Join(c.SANs, " ")), e(c.Issuer), c.NotAfter.Format("2006-01-02"), c.days(), c.status())
	}
	s.WriteString("</table><h3>hosts from active proxy-confs</h3>" + tbl + "<tr><th>conf<th>host<th>cert<th>days<th>status</tr>")
	for _, h := range hostRows(cs) {
		fmt.Fprintf(&s, "<tr><td>%s<td>%s<td>%s<td>%s<td>%s</tr>", e(h.Conf), e(h.Host), e(h.Cert), h.Days, h.Status)
	}
	s.WriteString("</table>")
	page(w, "certs", s.String())
}

// ---- edit ----

const tpl = `server {
    listen 443 ssl;
    listen [::]:443 ssl;

    server_name %[1]s.*;

    include /config/nginx/ssl.conf;
    client_max_body_size 0;

    location / {
        include /config/nginx/proxy.conf;
        include /config/nginx/resolver.conf;
        set $upstream_app %[1]s;
        set $upstream_port %[2]s;
        set $upstream_proto http;
        proxy_pass $upstream_proto://$upstream_app:$upstream_port;
    }
}
`

func backTo(f string) string {
	if strings.HasPrefix(f, "proxy-confs/") {
		return "/confs"
	}
	return "/files"
}

func form(w http.ResponseWriter, f, content string, isNew bool) {
	ro := " readonly"
	if isNew {
		ro = ""
	}
	page(w, "", fmt.Sprintf("<form method=post action=/save>file: <input name=f size=60 value='%s'%s><br><textarea name=c rows=32 cols=110 spellcheck=false>%s</textarea><br><input type=submit value='save + nginx -t + reload'> <a href='%s'>[ close without saving ]</a></form>", e(f), ro, e(content), backTo(f)))
}

func newf(w http.ResponseWriter, r *http.Request) {
	n, p := r.URL.Query().Get("name"), r.URL.Query().Get("port")
	if n == "" {
		form(w, "proxy-confs/name.subdomain.conf", "", true)
		return
	}
	form(w, "proxy-confs/"+n+".subdomain.conf", fmt.Sprintf(tpl, n, p), true)
}

func edit(w http.ResponseWriter, r *http.Request) {
	f := r.URL.Query().Get("f")
	if !nameRe.MatchString(f) {
		http.Error(w, "bad name", 400)
		return
	}
	b, err := os.ReadFile(filepath.Join(base, f))
	if err != nil {
		http.Error(w, err.Error(), 404)
		return
	}
	form(w, f, string(b), false)
}

func result(w http.ResponseWriter, msg, out, back string) {
	page(w, "", fmt.Sprintf("<b>%s</b><pre>%s</pre><a href='%s'>[ back ]</a>", e(msg), e(out), back))
}

func save(w http.ResponseWriter, r *http.Request) {
	f, c := r.FormValue("f"), strings.ReplaceAll(r.FormValue("c"), "\r\n", "\n")
	if !nameRe.MatchString(f) {
		http.Error(w, "bad name", 400)
		return
	}
	p, bk := filepath.Join(base, f), backTo(f)
	old, rerr := os.ReadFile(p)
	if rerr == nil {
		os.WriteFile(p+".bak", old, 0644)
	}
	if err := os.WriteFile(p, []byte(c), 0644); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if strings.HasSuffix(f, ".sample") {
		result(w, "saved (sample, not active)", "", bk)
		return
	}
	out, ok := apply()
	if !ok {
		if rerr == nil {
			os.WriteFile(p, old, 0644)
		} else {
			os.Remove(p)
		}
		result(w, "FAILED, rolled back", out, bk)
		return
	}
	result(w, "OK, nginx reloaded", out, bk)
}

func toggle(w http.ResponseWriter, r *http.Request) {
	f := r.FormValue("f")
	if !nameRe.MatchString(f) || !strings.HasPrefix(f, "proxy-confs/") {
		http.Error(w, "bad name", 400)
		return
	}
	to := f + ".sample"
	if strings.HasSuffix(f, ".sample") {
		to = strings.TrimSuffix(f, ".sample")
	}
	if err := os.Rename(filepath.Join(base, f), filepath.Join(base, to)); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	out, ok := apply()
	if !ok {
		os.Rename(filepath.Join(base, to), filepath.Join(base, f))
		result(w, "FAILED, rolled back", out, "/confs")
		return
	}
	result(w, "OK: "+f+" -> "+to, out, "/confs")
}

func reload(w http.ResponseWriter, r *http.Request) {
	out, ok := apply()
	result(w, map[bool]string{true: "OK", false: "FAILED"}[ok], out, "/files")
}

func guard(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || subtle.ConstantTimeCompare([]byte(u), []byte(user)) != 1 || subtle.ConstantTimeCompare([]byte(p), []byte(pass)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="swag-ui"`)
			http.Error(w, "auth2", 401)
			return
		}
		if r.Method == "POST" {
			if o := r.Header.Get("Origin"); o != "" {
				if ou, _ := url.Parse(o); ou == nil || ou.Host != r.Host {
					http.Error(w, "origin", 403)
					return
				}
			}
		}
		h(w, r)
	}
}

func main() {
	// 1. РЕЖИМ ПРОКСИ (swag-guard)
	if len(os.Args) > 1 && os.Args[1] == "guard" {
		log.Printf("[GUARD] Инициализация Docker подключения для прокси-сервера...")
		initDocker()
		log.Printf("[GUARD] Путь к Docker API настроен как: %s", dkURL)
		log.Printf("[GUARD] Запуск защитного прокси swag-guard на порту %s...", env("LISTEN", ":2375"))
		guardMode()
		return
	}

	// 2. РЕЖИМ ВЕБ-ИНТЕРФЕЙСА (swag-ui)
	log.Printf("[UI] Запуск веб-интерфейса swag-ui на порту %s...", env("LISTEN", ":8080"))
	if pass == "" {
		log.Fatal("[UI] Критическая ошибка: Переменная окружения UI_PASS обязательна, но не задана")
	}

	log.Println("[UI] Инициализация Docker подключения для интерфейса...")
	initDocker()
	log.Printf("[UI] Путь к Docker API настроен как: %s", dkURL)

	log.Println("[UI] Регистрация маршрутов веб-интерфейса...")
	for p, h := range map[string]http.HandlerFunc{
		"/":            dash,
		"/containers":  containers,
		"/confs":       confs,
		"/files":       files,
		"/certs":       certsTab,
		"/new":         newf,
		"/edit":        edit,
		"/save":        save,
		"/toggle":      toggle,
		"/reload":      reload,
	} {
		// Используем стандартный http.HandleFunc, так как в режиме UI 
		// нам не нужно изолировать роутер от самого себя
		http.HandleFunc(p, guard(h))
	}

	log.Println("[UI] Веб-интерфейс успешно запущен и готов к приему соединений.")
	log.Fatal(http.ListenAndServe(env("LISTEN", ":8080"), nil))
}
