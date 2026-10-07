package main

// auth.go: authentication management on top of SWAG's own mechanisms.
// No database: state is derived from nginx files. Managed lines carry "# swag-ui:auth".

import (
	"fmt"
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

const (
	authTag = " # swag-ui:auth"
	wasTag  = "#swag-ui:was "
)

var (
	locIncRe  = regexp.MustCompile(`^\s*include\s+/config/nginx/(authelia|authentik|ldap|tinyauth)-location\.conf\s*;`)
	srvIncRe  = regexp.MustCompile(`^\s*include\s+/config/nginx/(authelia|authentik|ldap|tinyauth)-server\.conf\s*;`)
	basicRe   = regexp.MustCompile(`^\s*auth_basic\s+("[^"]*"|[^;\s]+)\s*;`)
	ufRe      = regexp.MustCompile(`^\s*auth_basic_user_file\s+([^;\s]+)\s*;`)
	reqRe     = regexp.MustCompile(`^\s*auth_request\s+([^;\s]+)\s*;`)
	sslIncRe  = regexp.MustCompile(`^\s*include\s+/config/nginx/ssl\.conf\s*;`)
	proxyRe   = regexp.MustCompile(`^\s*proxy_pass\s`)
	listenRe  = regexp.MustCompile(`(?m)^\s*listen\s+[^;]*443`)
	locPathRe = regexp.MustCompile(`^(\^~ |= |~\*? )?[/^][A-Za-z0-9/._()?|^$*+\[\]-]{0,98}$`)
	hostRe    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$`)
	slugRe    = regexp.MustCompile(`[^A-Za-z0-9]+`)
	curlOK    = regexp.MustCompile(`^curl -sS -m 5 -o /dev/null -w %\{http_code\} http://[A-Za-z0-9][A-Za-z0-9.-]{0,62}:[0-9]{1,5}/[A-Za-z0-9/._-]{0,80}$`)

	testMu sync.Mutex
	tests  = map[string]testRes{}
)

func init() {
	okCmd = append(okCmd, curlOK)
	tabs = append(tabs, [2]string{"auth", "authentication"})
	for p, h := range map[string]http.HandlerFunc{"/auth": authTab, "/auth/p": provPage, "/auth/svc": svcPage, "/auth/do": authDo} {
		http.HandleFunc(p, guard(h))
	}
	if !(len(os.Args) > 1 && os.Args[1] == "guard") {
		go testLoop()
	}
}

// ---------------- providers ----------------

type prov struct {
	Key, Label, Var, Host string
	Port                  int
	Health, Codes         string
}

var provs = []prov{
	{"authelia", "Authelia", "$upstream_authelia", "authelia", 9091, "/api/health", "200"},
	{"authentik", "Authentik", "$upstream_authentik", "authentik-server", 9000, "/outpost.goauthentik.io/ping", "204 200"},
	{"tinyauth", "Tinyauth", "$upstream_tinyauth", "tinyauth", 3000, "/api/healthcheck", "200"},
	{"ldap", "LDAP", "$upstream_auth_app", "ldap-auth", 9000, "/ldaplogin", "200"},
}

func provBy(k string) *prov {
	for i := range provs {
		if provs[i].Key == k {
			return &provs[i]
		}
	}
	return nil
}
func (p prov) srv() string { return p.Key + "-server.conf" }
func (p prov) loc() string { return p.Key + "-location.conf" }
func (p prov) enabled() bool {
	return fileExists(filepath.Join(base, p.srv())) && fileExists(filepath.Join(base, p.loc()))
}
func (p prov) label() string { return p.Label }
func label(k string) string {
	switch k {
	case "basic":
		return "Basic Auth"
	case "custom":
		return "auth_request (custom)"
	case "", "none":
		return "none"
	}
	if p := provBy(k); p != nil {
		return p.Label
	}
	return k
}

func readBase(rel string) string { b, _ := os.ReadFile(filepath.Join(base, rel)); return string(b) }

// upstream host/port of the auth service, parsed from <provider>-server.conf
func (p prov) endpoint() (string, int) {
	s, v := readBase(p.srv()), regexp.QuoteMeta(p.Var)
	host, port := p.Host, p.Port
	if m := regexp.MustCompile(`set\s+` + v + `\s+([^;\s]+)\s*;`).FindStringSubmatch(s); m != nil {
		host = m[1]
	}
	re := `proxy_pass\s+http://` + v + `:(\d+)`
	if p.Key == "ldap" {
		re = `set\s+\$upstream_auth_port\s+(\d+)\s*;`
	}
	if m := regexp.MustCompile(re).FindStringSubmatch(s); m != nil {
		port, _ = strconv.Atoi(m[1])
	}
	return host, port
}

func ldapGet(s, key string) string {
	m := regexp.MustCompile(`(?m)^[ \t]*proxy_set_header[ \t]+X-Ldap-` + key + `[ \t]+"([^"]*)"[ \t]*;`).FindStringSubmatch(s)
	if m == nil {
		return ""
	}
	return m[1]
}

func ldapSet(s, key, val string, optional bool) string {
	re := regexp.MustCompile(`(?m)^([ \t]*)#?[ \t]*proxy_set_header[ \t]+X-Ldap-` + key + `[ \t]+"[^"]*"[ \t]*;`)
	return re.ReplaceAllStringFunc(s, func(l string) string {
		ind := l[:len(l)-len(strings.TrimLeft(l, " \t"))]
		if val == "" && optional {
			return ind + `#proxy_set_header X-Ldap-` + key + ` "";`
		}
		return ind + `proxy_set_header X-Ldap-` + key + ` "` + val + `";`
	})
}

func ldapServer(s string) (host string, port int, ok bool) {
	u, err := url.Parse(ldapGet(s, "URL"))
	if err != nil || u.Hostname() == "" || u.Hostname() == "example.com" {
		return "", 0, false
	}
	port = 389
	if u.Scheme == "ldaps" {
		port = 636
	}
	if u.Port() != "" {
		port, _ = strconv.Atoi(u.Port())
	}
	return u.Hostname(), port, true
}

// ---------------- connection tests (run inside swag, same network as nginx) ----------------

type testRes struct {
	At  time.Time
	OK  bool
	Msg string
}

func curl(host string, port int, path string) (string, int, string) {
	out, code := run("curl", "-sS", "-m", "5", "-o", "/dev/null", "-w", "%{http_code}", "http://"+host+":"+strconv.Itoa(port)+path)
	hc := "000"
	if len(out) >= 3 {
		hc = out[:3]
	}
	return hc, code, strings.TrimSpace(out)
}

func curlErr(host string, code int, out string) string {
	switch code {
	case 6:
		return "cannot resolve '" + host + "': is the container on swag's docker network and named like this?"
	case 7:
		return "connection refused by " + host
	case 28:
		return "timeout connecting to " + host
	}
	return fmt.Sprintf("curl exit %d: %s", code, out)
}

func testProv(p prov) testRes {
	r := testRes{At: time.Now()}
	switch {
	case dkURL == "":
		r.Msg = "docker api off: cannot run the test inside swag"
	case !p.enabled():
		r.Msg = "not enabled"
	default:
		host, port := p.endpoint()
		hc, code, out := curl(host, port, p.Health)
		switch {
		case code != 0:
			r.Msg = curlErr(host, code, out)
		case !strings.Contains(p.Codes, hc):
			r.Msg = fmt.Sprintf("%s:%d%s answered HTTP %s (expected %s); not counted as connected", host, port, p.Health, hc, p.Codes)
		default:
			r.OK, r.Msg = true, fmt.Sprintf("%s:%d%s answered HTTP %s", host, port, p.Health, hc)
		}
		if p.Key == "ldap" && r.OK {
			lh, lp, ok := ldapServer(readBase(p.srv()))
			if !ok {
				r.OK, r.Msg = false, r.Msg+"; LDAP server URL is not configured (template default)"
			} else if _, c2, o2 := curl(lh, lp, "/"); c2 == 6 || c2 == 7 || c2 == 28 {
				r.OK, r.Msg = false, "ldap-auth is up, but LDAP server: "+curlErr(lh, c2, o2)
			} else {
				r.Msg += fmt.Sprintf("; LDAP server %s:%d accepts TCP (bind credentials are not validated)", lh, lp)
			}
		}
	}
	testMu.Lock()
	tests[p.Key] = r
	testMu.Unlock()
	return r
}

func testLoop() {
	time.Sleep(20 * time.Second)
	for {
		for _, p := range provs {
			if p.enabled() {
				testProv(p)
			}
		}
		time.Sleep(2 * time.Minute)
	}
}

func provStatus(k string) string {
	testMu.Lock()
	r, ok := tests[k]
	testMu.Unlock()
	switch {
	case !ok:
		return "⚪ not tested yet"
	case r.OK:
		return "🟢 connected (" + r.At.Format("15:04:05") + ")"
	}
	return "🔴 " + e(r.Msg)
}

// ---------------- nginx block parser ----------------

type blk struct {
	Head               string
	Open, Close, Depth int
}

func parseBlocks(s string) (out []blk) {
	var stack []int
	var h strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '#':
			for i < len(s) && s[i] != '\n' {
				i++
			}
			h.WriteByte('\n')
		case c == '"' || c == '\'':
			h.WriteByte(c)
			for i++; i < len(s) && s[i] != c; i++ {
				if s[i] == '\\' && i+1 < len(s) {
					h.WriteByte(s[i])
					i++
				}
				h.WriteByte(s[i])
			}
			h.WriteByte(c)
		case c == '{' && i > 0 && s[i-1] == '$':
			for i < len(s) && s[i] != '}' {
				h.WriteByte(s[i])
				i++
			}
		case c == '{':
			out = append(out, blk{Head: strings.Join(strings.Fields(h.String()), " "), Open: i, Depth: len(stack)})
			stack = append(stack, len(out)-1)
			h.Reset()
		case c == '}':
			if n := len(stack); n > 0 {
				out[stack[n-1]].Close = i
				stack = stack[:n-1]
			}
			h.Reset()
		case c == ';':
			h.Reset()
		default:
			h.WriteByte(c)
		}
	}
	return
}

type locInfo struct {
	Path, Prov, Custom, UserFile string
	Open, Close                  int
	Auth                         []int
	Managed, Clone, Proxy        bool
}

type srvInfo struct {
	Open, Close, SSL int
	Locs             []locInfo
	Inc              map[string][]int
	Basic, Req       bool
}

func (sv *srvInfo) find(path string) *locInfo {
	n := strings.Join(strings.Fields(path), " ")
	for i := range sv.Locs {
		if sv.Locs[i].Path == n {
			return &sv.Locs[i]
		}
	}
	return nil
}

func lineOf(s string, off int) int { return strings.Count(s[:off], "\n") }
func indentOf(l string) string     { return l[:len(l)-len(strings.TrimLeft(l, " \t"))] }

func analyze(src string) ([]string, *srvInfo, error) {
	lines, bs := strings.Split(src, "\n"), parseBlocks(src)
	si := -1
	for i, b := range bs {
		if b.Depth == 0 && b.Head == "server" && b.Close > b.Open && listenRe.MatchString(src[b.Open:b.Close]) {
			si = i
			break
		}
	}
	if si < 0 {
		return lines, nil, fmt.Errorf("no server block with 'listen 443' found")
	}
	S := bs[si]
	sv := &srvInfo{Open: lineOf(src, S.Open), Close: lineOf(src, S.Close), SSL: -1, Inc: map[string][]int{}}
	inKid := map[int]bool{}
	for _, b := range bs[si+1:] {
		if b.Open > S.Close {
			break
		}
		o, c := lineOf(src, b.Open), lineOf(src, b.Close)
		for i := o; i <= c; i++ {
			inKid[i] = true
		}
		if b.Depth == S.Depth+1 && strings.HasPrefix(b.Head, "location") {
			if o == c {
				return lines, nil, fmt.Errorf("one-line location block is not supported: %q", b.Head)
			}
			li := locInfo{Path: strings.TrimSpace(strings.TrimPrefix(b.Head, "location")), Open: o, Close: c}
			li.Clone = o > 0 && strings.Contains(lines[o-1], "swag-ui:auth begin")
			sv.Locs = append(sv.Locs, li)
		}
	}
	for k := range sv.Locs {
		l := &sv.Locs[k]
		deep := map[int]bool{}
		for _, b := range bs {
			if b.Depth > S.Depth+1 && lineOf(src, b.Open) > l.Open && lineOf(src, b.Open) < l.Close {
				for i := lineOf(src, b.Open); i <= lineOf(src, b.Close); i++ {
					deep[i] = true
				}
			}
		}
		for i := l.Open + 1; i < l.Close; i++ {
			ln := lines[i]
			if deep[i] {
				continue
			}
			tagged := strings.Contains(ln, "swag-ui:auth")
			if proxyRe.MatchString(ln) {
				l.Proxy = true
			}
			if m := locIncRe.FindStringSubmatch(ln); m != nil {
				l.Auth, l.Managed = append(l.Auth, i), l.Managed || tagged
				if l.Prov == "" {
					l.Prov = m[1]
				}
			} else if m := basicRe.FindStringSubmatch(ln); m != nil {
				l.Auth, l.Managed = append(l.Auth, i), l.Managed || tagged
				if strings.Trim(m[1], `"`) != "off" && l.Prov == "" {
					l.Prov = "basic"
				}
			} else if m := ufRe.FindStringSubmatch(ln); m != nil {
				l.Auth, l.Managed, l.UserFile = append(l.Auth, i), l.Managed || tagged, m[1]
			} else if m := reqRe.FindStringSubmatch(ln); m != nil {
				l.Auth, l.Managed = append(l.Auth, i), l.Managed || tagged
				if m[1] != "off" {
					l.Custom = m[1]
				}
			}
		}
		if l.Prov == "" && l.Custom != "" {
			l.Prov = "custom"
		}
	}
	for i := sv.Open + 1; i < sv.Close; i++ {
		if inKid[i] {
			continue
		}
		ln := lines[i]
		if m := srvIncRe.FindStringSubmatch(ln); m != nil {
			sv.Inc[m[1]] = append(sv.Inc[m[1]], i)
		} else if sslIncRe.MatchString(ln) && sv.SSL < 0 {
			sv.SSL = i
		} else if m := basicRe.FindStringSubmatch(ln); m != nil && strings.Trim(m[1], `"`) != "off" {
			sv.Basic = true
		} else if m := reqRe.FindStringSubmatch(ln); m != nil && m[1] != "off" {
			sv.Req = true
		}
	}
	return lines, sv, nil
}

func del(lines []string, i int) []string { return append(lines[:i], lines[i+1:]...) }
func ins(lines []string, at int, add ...string) []string {
	return append(lines[:at+1], append(append([]string{}, add...), lines[at+1:]...)...)
}

// comment out manual auth lines, drop managed ones
func neutralize(src, path string) (string, error) {
	lines, sv, err := analyze(src)
	if err != nil {
		return "", err
	}
	if l := sv.find(path); l != nil {
		for k := len(l.Auth) - 1; k >= 0; k-- {
			i := l.Auth[k]
			if strings.Contains(lines[i], authTag) {
				lines = del(lines, i)
			} else {
				lines[i] = indentOf(lines[i]) + wasTag + strings.TrimLeft(lines[i], " \t")
			}
		}
	}
	return strings.Join(lines, "\n"), nil
}

func insertProv(src, path, pv, bfile string) (string, error) {
	lines, sv, err := analyze(src)
	if err != nil {
		return "", err
	}
	l := sv.find(path)
	if l == nil {
		return "", fmt.Errorf("location %q not found", path)
	}
	ind, add := indentOf(lines[l.Open])+"    ", []string(nil)
	switch pv {
	case "basic":
		add = []string{ind + `auth_basic "Restricted";` + authTag, ind + "auth_basic_user_file " + bfile + ";" + authTag}
	case "none":
		if sv.Basic {
			add = append(add, ind+"auth_basic off;"+authTag)
		}
		if sv.Req {
			add = append(add, ind+"auth_request off;"+authTag)
		}
	default:
		add = []string{ind + "include /config/nginx/" + pv + "-location.conf;" + authTag}
	}
	if len(add) == 0 {
		return src, nil
	}
	return strings.Join(ins(lines, l.Open, add...), "\n"), nil
}

func createClone(src, path string) (string, error) {
	lines, sv, err := analyze(src)
	if err != nil {
		return "", err
	}
	var t *locInfo
	for i := range sv.Locs {
		if sv.Locs[i].Proxy && (t == nil || sv.Locs[i].Path == "/") {
			t = &sv.Locs[i]
		}
	}
	if t == nil {
		return "", fmt.Errorf("no proxied location to copy the proxy settings from")
	}
	skip := map[int]bool{}
	for _, i := range t.Auth {
		skip[i] = true
	}
	ind := indentOf(lines[t.Open])
	b := []string{ind + "# swag-ui:auth begin " + path, ind + "location " + path + " {"}
	for i := t.Open + 1; i < t.Close; i++ {
		if !skip[i] && !strings.Contains(lines[i], "swag-ui:") {
			b = append(b, lines[i])
		}
	}
	b = append(b, ind+"}", ind+"# swag-ui:auth end "+path)
	return strings.Join(ins(lines, sv.Close-1, b...), "\n"), nil
}

// remove the rule: delete a managed clone, or managed lines (restoring commented originals)
func removeRule(src, path string) (string, error) {
	lines, sv, err := analyze(src)
	if err != nil {
		return "", err
	}
	l := sv.find(path)
	if l == nil {
		return src, nil
	}
	if l.Clone {
		end := l.Close
		for end < len(lines) && !strings.Contains(lines[end], "swag-ui:auth end") {
			end++
		}
		lines = append(lines[:l.Open-1], lines[end+1:]...)
		return strings.Join(lines, "\n"), nil
	}
	for k := len(l.Auth) - 1; k >= 0; k-- {
		if strings.Contains(lines[l.Auth[k]], authTag) {
			lines = del(lines, l.Auth[k])
		}
	}
	src = strings.Join(lines, "\n")
	lines, sv, _ = analyze(src)
	l = sv.find(path)
	for i := l.Open + 1; i < l.Close; i++ {
		if t := strings.TrimLeft(lines[i], " \t"); strings.HasPrefix(t, wasTag) {
			lines[i] = indentOf(lines[i]) + strings.TrimPrefix(t, wasTag)
		}
	}
	return strings.Join(lines, "\n"), nil
}

// server-level include of <provider>-server.conf for every provider in use
func fixServerIncludes(src string) (string, error) {
	for n := 0; n < 12; n++ {
		lines, sv, err := analyze(src)
		if err != nil {
			return "", err
		}
		used := map[string]bool{}
		for _, l := range sv.Locs {
			if provBy(l.Prov) != nil {
				used[l.Prov] = true
			}
		}
		changed := false
		for _, p := range provs {
			inc := sv.Inc[p.Key]
			if used[p.Key] && len(inc) == 0 {
				at, ind := sv.Open, indentOf(lines[sv.Open])+"    "
				if sv.SSL >= 0 {
					at, ind = sv.SSL, indentOf(lines[sv.SSL])
				}
				lines, changed = ins(lines, at, ind+"include /config/nginx/"+p.srv()+";"+authTag), true
			} else if !used[p.Key] {
				for k := len(inc) - 1; k >= 0; k-- {
					if strings.Contains(lines[inc[k]], authTag) {
						lines, changed = del(lines, inc[k]), true
					}
				}
			}
			if changed {
				break
			}
		}
		if !changed {
			return src, nil
		}
		src = strings.Join(lines, "\n")
	}
	return src, nil
}

func setRule(src, path, pv, bfile string) (string, error) {
	_, sv, err := analyze(src)
	if err != nil {
		return "", err
	}
	if sv.find(path) == nil {
		if src, err = createClone(src, path); err != nil {
			return "", err
		}
	}
	for _, f := range []func(string) (string, error){
		func(s string) (string, error) { return neutralize(s, path) },
		func(s string) (string, error) { return insertProv(s, path, pv, bfile) },
		fixServerIncludes,
	} {
		if src, err = f(src); err != nil {
			return "", err
		}
	}
	return src, nil
}

// ---------------- .htpasswd users per rule ----------------

func poolUsers() (r []string) {
	for _, l := range htLines() {
		u, _, _ := strings.Cut(l, ":")
		r = append(r, u)
	}
	return
}

func basicRel(conf, path string) string {
	n := strings.TrimSuffix(conf, ".conf")
	if path != "/" {
		n += "." + strings.Trim(slugRe.ReplaceAllString(path, "_"), "_")
	}
	return "htpasswd.d/" + n + ".htpasswd"
}

func fileUsers(np string) (us []string, shared bool) {
	if np == "/config/nginx/.htpasswd" || filepath.Clean(np) == filepath.Clean(htPath) {
		return poolUsers(), true
	}
	if !strings.HasPrefix(np, "/config/nginx/") {
		return nil, false
	}
	b, _ := os.ReadFile(filepath.Join(base, strings.TrimPrefix(np, "/config/nginx/")))
	for _, l := range strings.Split(string(b), "\n") {
		if u, _, ok := strings.Cut(l, ":"); ok {
			us = append(us, u)
		}
	}
	return
}

// copy selected users' hashes from the pool into a per-rule file (never shown in the UI)
func writeBasic(rel string, users []string) (func(), error) {
	pool := map[string]string{}
	for _, l := range htLines() {
		u, _, _ := strings.Cut(l, ":")
		pool[u] = l
	}
	var out []string
	for _, u := range users {
		if pool[u] == "" {
			return nil, fmt.Errorf("unknown user %q", u)
		}
		out = append(out, pool[u])
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("select at least one user for Basic Auth")
	}
	p := filepath.Join(base, rel)
	old, oerr := os.ReadFile(p)
	os.MkdirAll(filepath.Dir(p), 0755)
	if err := os.WriteFile(p, []byte(strings.Join(out, "\n")+"\n"), 0644); err != nil {
		return nil, err
	}
	return func() {
		if oerr != nil {
			os.Remove(p)
		} else {
			os.WriteFile(p, old, 0644)
		}
	}, nil
}

func htPropagate(user, hash string) {
	fs, _ := filepath.Glob(filepath.Join(base, "htpasswd.d", "*.htpasswd"))
	for _, f := range fs {
		b, _ := os.ReadFile(f)
		var out []string
		ch := false
		for _, l := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
			if strings.HasPrefix(l, user+":") {
				ch = true
				if hash != "" {
					out = append(out, user+":"+hash)
				}
			} else if l != "" {
				out = append(out, l)
			}
		}
		if ch {
			os.WriteFile(f, []byte(strings.Join(out, "\n")+"\n"), 0644)
		}
	}
}

func activeConfs() (r []string) {
	ns, _ := list("proxy-confs")
	for _, n := range ns {
		if strings.HasSuffix(n, ".conf") {
			r = append(r, n)
		}
	}
	return
}

func confInfo(conf string) (*srvInfo, error) {
	_, sv, err := analyze(readBase("proxy-confs/" + conf))
	return sv, err
}

func htUsage() map[string][]string {
	m := map[string][]string{}
	for _, n := range activeConfs() {
		sv, err := confInfo(n)
		if err != nil {
			continue
		}
		for _, l := range sv.Locs {
			if l.Prov == "basic" {
				us, sh := fileUsers(l.UserFile)
				for _, u := range us {
					t := n + " " + l.Path
					if sh {
						t += " (shared .htpasswd)"
					}
					m[u] = append(m[u], t)
				}
			}
		}
	}
	return m
}

func usedIn(l []string) string {
	if len(l) == 0 {
		return "-"
	}
	for i := range l {
		l[i] = e(l[i])
	}
	return strings.Join(l, "<br>")
}

// ---------------- safe change workflow: write, nginx -t, reload, rollback ----------------

func changeFile(rel string, mutate func(string) (string, func(), error)) (string, bool) {
	p := filepath.Join(base, rel)
	old, err := os.ReadFile(p)
	if err != nil {
		return err.Error(), false
	}
	ns, undo, err := mutate(string(old))
	if err != nil {
		return err.Error(), false
	}
	if ns == string(old) {
		return "no change", true
	}
	mode := os.FileMode(0644)
	if fi, err := os.Stat(p); err == nil {
		mode = fi.Mode().Perm()
	}
	os.WriteFile(p+".bak", old, mode)
	if err := os.WriteFile(p, []byte(ns), mode); err != nil {
		return err.Error(), false
	}
	out, ok := apply()
	if !ok {
		os.WriteFile(p, old, mode)
		if undo != nil {
			undo()
		}
		return "FAILED, rolled back\n" + out, false
	}
	return out, true
}

// ---------------- views ----------------

func confOK(c string) bool {
	return strings.HasSuffix(c, ".conf") && nameRe.MatchString("proxy-confs/"+c)
}

func provUse() map[string]map[string]bool {
	m := map[string]map[string]bool{}
	for _, n := range activeConfs() {
		if sv, err := confInfo(n); err == nil {
			for _, l := range sv.Locs {
				if l.Prov != "" {
					if m[l.Prov] == nil {
						m[l.Prov] = map[string]bool{}
					}
					m[l.Prov][n] = true
				}
			}
		}
	}
	return m
}

func authCell(conf string) string {
	sv, err := confInfo(conf)
	if err != nil {
		return "?"
	}
	var items []string
	same, first := true, ""
	for i, l := range sv.Locs {
		if !l.Proxy && l.Prov == "" {
			continue
		}
		k := l.Prov
		if k == "" && sv.Basic {
			k = "basic"
		}
		if i == 0 || first == "" {
			first = k
		} else if k != first {
			same = false
		}
		items = append(items, e(l.Path)+" &rarr; "+authIcon(k)+label(k))
	}
	switch {
	case len(items) == 0:
		return "-"
	case same:
		return authIcon(first) + label(first)
	}
	return strings.Join(items, "<br>")
}

func authIcon(k string) string {
	switch k {
	case "", "none":
		return ""
	case "basic":
		return "🔑 "
	}
	return "🔐 "
}

func authDash() string {
	use := provUse()
	var s strings.Builder
	s.WriteString("<h3>authentication providers</h3>" + tbl + "<tr><th>provider<th>type<th>status<th>services</tr>")
	for _, p := range provs {
		if p.enabled() {
			fmt.Fprintf(&s, "<tr><td><a href='/auth/p?n=%s'>%s</a><td>%s<td>%s<td>%d</tr>", p.Key, p.Label, map[bool]string{true: "ldap-auth", false: "auth_request"}[p.Key == "ldap"], provStatus(p.Key), len(use[p.Key]))
		}
	}
	if n := len(htLines()); n > 0 || len(use["basic"]) > 0 {
		fmt.Fprintf(&s, "<tr><td><a href=/htpasswd>Basic Auth</a><td>auth_basic<td>🟢 %d users<td>%d</tr>", n, len(use["basic"]))
	}
	return s.String() + "</table>"
}

func authTab(w http.ResponseWriter, r *http.Request) {
	use := provUse()
	var s strings.Builder
	s.WriteString("<h3>authentication providers</h3>" + tbl + "<tr><th>provider<th>server<th>status<th>services<th>action</tr>")
	for _, p := range provs {
		if !p.enabled() {
			fmt.Fprintf(&s, "<tr><td>%s<td>-<td>not enabled<td>-<td><form method=post action=/auth/do><input type=hidden name=op value=penable><input type=hidden name=p value=%s><input type=submit value=enable></form></tr>", p.Label, p.Key)
			continue
		}
		h, po := p.endpoint()
		srv := fmt.Sprintf("http://%s:%d", h, po)
		if p.Key == "ldap" {
			srv = ldapGet(readBase(p.srv()), "URL")
		}
		fmt.Fprintf(&s, "<tr><td>%s<td>%s<td>%s<td>%d<td><a href='/auth/p?n=%s'>[ details / edit ]</a></tr>", p.Label, e(srv), provStatus(p.Key), len(use[p.Key]), p.Key)
	}
	fmt.Fprintf(&s, "<tr><td>Basic Auth<td>%s<td>%d users<td>%d<td><a href=/htpasswd>[ users ]</a></tr></table>", e(htPath), len(htLines()), len(use["basic"]))
	s.WriteString("<h3>services</h3>" + tbl + "<tr><th>conf<th>server_name<th>authentication<th></tr>")
	for _, n := range activeConfs() {
		host := ""
		if m := srvRe.FindStringSubmatch(readBase("proxy-confs/" + n)); m != nil {
			host = strings.Join(strings.Fields(m[1]), " ")
		}
		fmt.Fprintf(&s, "<tr><td>%s<td>%s<td>%s<td><a href='/auth/svc?c=%s'>[ configure ]</a></tr>", e(n), e(host), authCell(n), url.QueryEscape(n))
	}
	page(w, "auth", s.String()+"</table>")
}

func provPage(w http.ResponseWriter, r *http.Request) {
	p := provBy(r.URL.Query().Get("n"))
	if p == nil || !p.enabled() {
		http.Redirect(w, r, "/auth", 303)
		return
	}
	src, use := readBase(p.srv()), provUse()[p.Key]
	var s strings.Builder
	fmt.Fprintf(&s, "<h3>%s</h3>status: %s<p><form method=post action=/auth/do><input type=hidden name=p value=%s><input type=hidden name=op value=ptest><input type=submit value='test connection'></form>", p.Label, provStatus(p.Key), p.Key)
	h, po := p.endpoint()
	fmt.Fprintf(&s, "<h4>configuration (%s)</h4><form method=post action=/auth/do><input type=hidden name=p value=%s><input type=hidden name=op value=psave>container name: <input name=host value='%s'>", e(p.srv()), p.Key, e(h))
	if p.Key == "ldap" {
		secret := "set"
		if ldapGet(src, "BindPass") == "secret" {
			secret = "template default"
		}
		fmt.Fprintf(&s, " (the ldap-auth container)<br>LDAP URL: <input name=url size=40 value='%s'><br>Base DN: <input name=basedn size=50 value='%s'><br>Bind DN: <input name=binddn size=50 value='%s'><br>Bind password (%s, write-only): <input type=password name=bindpass><br>Filter template (optional, e.g. (cn=%%(username)s)): <input name=tmpl size=40 value='%s'>", e(ldapGet(src, "URL")), e(ldapGet(src, "BaseDN")), e(ldapGet(src, "BindDN")), secret, e(ldapGet(src, "Template")))
	} else {
		fmt.Fprintf(&s, " port: <input name=port size=5 value='%d'>", po)
	}
	s.WriteString("<br><input type=submit value='save + nginx -t + reload'></form><p>The container must be on the same docker network as swag.<h4>used by</h4>")
	if len(use) == 0 {
		s.WriteString("no services<br><form method=post action=/auth/do><input type=hidden name=op value=pdisable><input type=hidden name=p value=" + p.Key + "><input type=submit value='disable provider'></form>")
	}
	for c := range use {
		s.WriteString("<a href='/auth/svc?c=" + url.QueryEscape(c) + "'>" + e(c) + "</a><br>")
	}
	page(w, "auth", s.String()+"<p><a href=/auth>[ back ]</a>")
}

func userBoxes(sel map[string]bool) string {
	var s strings.Builder
	for _, u := range poolUsers() {
		fmt.Fprintf(&s, "<input type=checkbox name=user value='%s'%s>%s ", e(u), map[bool]string{true: " checked", false: ""}[sel[u]], e(u))
	}
	if s.Len() == 0 {
		return "(no users in .htpasswd yet)"
	}
	return "Basic Auth users: " + s.String()
}

func provOptions(cur string) string {
	opt := func(v, t string) string {
		return "<option value=" + v + map[bool]string{true: " selected", false: ""}[v == cur] + ">" + t + "</option>"
	}
	s := opt("none", "none") + opt("basic", "Basic Auth")
	if cur == "custom" {
		s += opt("custom", "auth_request (custom, keep)")
	}
	for _, p := range provs {
		if p.enabled() {
			s += opt(p.Key, p.Label)
		}
	}
	return s
}

func svcPage(w http.ResponseWriter, r *http.Request) {
	c := r.URL.Query().Get("c")
	if !confOK(c) {
		http.Error(w, "bad conf", 400)
		return
	}
	sv, err := confInfo(c)
	if err != nil {
		page(w, "auth", "<b>"+e(err.Error())+"</b><p>This file has to be edited by hand.<br><a href='/edit?f=proxy-confs/"+url.QueryEscape(c)+"'>[ edit ]</a>")
		return
	}
	var s strings.Builder
	fmt.Fprintf(&s, "<h3>%s</h3>", e(c))
	if sv.Basic || sv.Req {
		s.WriteString("<b>server-level auth_basic / auth_request found: it applies to locations without their own rule.</b><p>")
	}
	for _, l := range sv.Locs {
		if !l.Proxy && l.Prov == "" {
			continue
		}
		cur := l.Prov
		if cur == "" {
			cur = "none"
		}
		src := "manual"
		if l.Clone {
			src = "managed path"
		} else if l.Managed {
			src = "managed"
		}
		sel := map[string]bool{}
		if cur == "basic" {
			us, sh := fileUsers(l.UserFile)
			for _, u := range us {
				sel[u] = true
			}
			if sh {
				src += ", shared .htpasswd: all users"
			}
		}
		fmt.Fprintf(&s, "<form method=post action=/auth/do><input type=hidden name=op value=setrule><input type=hidden name=c value='%s'><input type=hidden name=path value='%s'><b>%s</b> (%s) <select name=prov>%s</select> %s <input type=submit value=apply></form>", e(c), e(l.Path), e(l.Path), src, provOptions(cur), userBoxes(sel))
		if l.Clone || l.Managed {
			fmt.Fprintf(&s, "<form method=post action=/auth/do><input type=hidden name=op value=delrule><input type=hidden name=c value='%s'><input type=hidden name=path value='%s'><input type=submit value='remove rule'></form>", e(c), e(l.Path))
		}
		s.WriteString("<br>")
	}
	fmt.Fprintf(&s, "<h4>add a path rule</h4>Creates a separate location copied from the proxy settings. Use <tt>None</tt> to leave a path public while another is protected.<form method=post action=/auth/do><input type=hidden name=op value=setrule><input type=hidden name=c value='%s'>path: <input name=path value=/ size=30> <select name=prov>%s</select> %s <input type=submit value=add></form><p><a href=/auth>[ back ]</a> <a href='/edit?f=proxy-confs/%s'>[ edit file ]</a>", e(c), provOptions("none"), userBoxes(nil), url.QueryEscape(c))
	page(w, "auth", s.String())
}

func authDo(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	back, op := "/auth", r.FormValue("op")
	fin := func(msg, out string, ok bool) {
		if !ok {
			msg = "FAILED"
		}
		result(w, msg, out, back)
	}
	switch op {
	case "ptest":
		p := provBy(r.FormValue("p"))
		if p == nil {
			http.Error(w, "bad provider", 400)
			return
		}
		res := testProv(*p)
		back = "/auth/p?n=" + p.Key
		fin(map[bool]string{true: "connected", false: "NOT connected"}[res.OK], res.Msg, true)
	case "penable", "pdisable":
		p := provBy(r.FormValue("p"))
		if p == nil {
			http.Error(w, "bad provider", 400)
			return
		}
		if op == "pdisable" {
			if len(provUse()[p.Key]) > 0 {
				fin("", "provider is used by services", false)
				return
			}
			for _, f := range []string{p.srv(), p.loc()} {
				os.Rename(filepath.Join(base, f), filepath.Join(base, f+".disabled"))
			}
			out, ok := apply()
			if !ok {
				for _, f := range []string{p.srv(), p.loc()} {
					os.Rename(filepath.Join(base, f+".disabled"), filepath.Join(base, f))
				}
			}
			fin("provider disabled (files kept as *.disabled)", out, ok)
			return
		}
		for _, f := range []string{p.srv(), p.loc()} {
			dst := filepath.Join(base, f)
			if fileExists(dst) {
				continue
			}
			if fileExists(dst + ".disabled") {
				os.Rename(dst+".disabled", dst)
				continue
			}
			b, err := os.ReadFile(dst + ".sample")
			if err != nil {
				fin("", f+".sample not found in "+base, false)
				return
			}
			os.WriteFile(dst, b, 0600)
			if p.Key != "ldap" {
				os.Chmod(dst, 0644)
			}
		}
		back = "/auth/p?n=" + p.Key
		fin("provider enabled (copied from the SWAG sample)", "Now set the container name and test the connection.", true)
	case "psave":
		p := provBy(r.FormValue("p"))
		host, port := strings.TrimSpace(r.FormValue("host")), r.FormValue("port")
		pn, _ := strconv.Atoi(port)
		if p == nil || !hostRe.MatchString(host) || (p.Key != "ldap" && (pn < 1 || pn > 65535)) {
			http.Error(w, "bad input", 400)
			return
		}
		back = "/auth/p?n=" + p.Key
		out, ok := changeFile(p.srv(), func(s string) (string, func(), error) {
			v := regexp.QuoteMeta(p.Var)
			s = regexp.MustCompile(`(set\s+`+v+`\s+)[^;\s]+(\s*;)`).ReplaceAllString(s, "${1}"+host+"${2}")
			if p.Key != "ldap" {
				return regexp.MustCompile(`(proxy_pass\s+http://`+v+`:)\d+`).ReplaceAllString(s, "${1}"+port), nil, nil
			}
			for _, f := range []struct {
				k, f string
				opt  bool
			}{{"URL", "url", false}, {"BaseDN", "basedn", false}, {"BindDN", "binddn", false}, {"BindPass", "bindpass", false}, {"Template", "tmpl", true}} {
				v := strings.TrimSpace(r.FormValue(f.f))
				if strings.ContainsAny(v, "\"\\$\r\n") {
					return "", nil, fmt.Errorf("%s contains a forbidden character (\" \\ $ or newline)", f.k)
				}
				if v != "" || f.opt {
					s = ldapSet(s, f.k, v, f.opt)
				}
			}
			return s, nil, nil
		})
		fin("saved", out, ok)
	case "setrule", "delrule":
		c, path := r.FormValue("c"), strings.Join(strings.Fields(r.FormValue("path")), " ")
		pv := r.FormValue("prov")
		if !confOK(c) || !locPathRe.MatchString(path) {
			http.Error(w, "bad conf or path", 400)
			return
		}
		back = "/auth/svc?c=" + url.QueryEscape(c)
		if op == "setrule" && pv != "none" && pv != "basic" && pv != "custom" && (provBy(pv) == nil || !provBy(pv).enabled()) {
			fin("", "provider is not enabled", false)
			return
		}
		rel := basicRel(c, path)
		out, ok := changeFile("proxy-confs/"+c, func(s string) (string, func(), error) {
			if op == "delrule" {
				ns, err := removeRule(s, path)
				return ns, nil, err
			}
			if pv == "custom" {
				return s, nil, nil
			}
			var undo func()
			if pv == "basic" {
				var err error
				if undo, err = writeBasic(rel, r.Form["user"]); err != nil {
					return "", nil, err
				}
			}
			ns, err := setRule(s, path, pv, "/config/nginx/"+rel)
			if err != nil && undo != nil {
				undo()
			}
			return ns, undo, err
		})
		if ok && (op == "delrule" || pv != "basic") {
			os.Remove(filepath.Join(base, rel))
		}
		fin("OK", out, ok)
	default:
		http.Error(w, "unknown op", 400)
	}
}
