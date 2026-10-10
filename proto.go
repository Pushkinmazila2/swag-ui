package main

// proto.go: "protocols" tab: HTTP/2, HTTP/3 and plain http :80 handling per site.
// All generated lines carry swag-ui tags so they can be removed again.

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const h2Tag = " # swag-ui:h2"

var (
	h2Re        = regexp.MustCompile(`(?m)^\s*http2\s+on\s*;|^\s*listen\s+[^;]*\bhttp2\b`)
	httpBlkRe   = regexp.MustCompile(`(?s)\n*# swag-ui:http begin \w+\n.*?# swag-ui:http end\n?`)
	httpBeginRe = regexp.MustCompile(`# swag-ui:http begin (\w+)`)
	listen80Re  = regexp.MustCompile(`(?m)^\s*listen\s+(\[::\]:)?80\b`)
	verRe       = regexp.MustCompile(`nginx/(\d+\.\d+\.\d+)`)
)

func h2On(s string) string {
	if h2Re.MatchString(s) {
		return s
	}
	return sslListen.ReplaceAllStringFunc(s, func(l string) string {
		m := sslListen.FindStringSubmatch(l)
		if m[2] != "" {
			return l
		}
		return l + "\n" + m[1] + "http2 on;" + h2Tag
	})
}

func h2Off(s string) string {
	var k []string
	for _, l := range strings.Split(s, "\n") {
		if !strings.Contains(l, h2Tag) {
			k = append(k, l)
		}
	}
	return strings.Join(k, "\n")
}

func h2State(c string) string {
	switch {
	case strings.Contains(c, h2Tag):
		return "ON (swag-ui)"
	case h2Re.MatchString(c):
		return "ON (manual)"
	case sslListen.MatchString(c):
		return "off"
	}
	return "n/a"
}

func h3State(c string) string {
	switch {
	case strings.Contains(c, h3Tag):
		return "ON (swag-ui)"
	case quicRe.MatchString(c):
		return "ON (manual)"
	case sslListen.MatchString(c):
		return "off"
	}
	return "n/a"
}

func httpMode(s string) string {
	if m := httpBeginRe.FindStringSubmatch(s); m != nil {
		return m[1]
	}
	if listen80Re.MatchString(s) {
		return "manual"
	}
	return "default"
}

// default: remove our block (port 80 is handled by site-confs/default.conf)
// redirect: this site is forced from http to https (301)
// plain: this site also answers on plain http (copy of the 443 server block without ssl)
func httpSet(src, mode string) (string, error) {
	if !httpBlkRe.MatchString(src) && mode == "default" {
		return src, nil
	}
	b0 := strings.TrimRight(httpBlkRe.ReplaceAllString(src, "\n"), "\n") + "\n"
	if mode == "default" {
		return b0, nil
	}
	for _, b := range parseBlocks(b0) {
		if b.Depth != 0 || b.Head != "server" || b.Close <= b.Open || !listenRe.MatchString(b0[b.Open:b.Close]) {
			continue
		}
		m := srvRe.FindStringSubmatch(b0[b.Open:b.Close])
		if m == nil {
			return "", fmt.Errorf("no server_name in the 443 server block")
		}
		names := strings.Join(strings.Fields(m[1]), " ")
		out := "# swag-ui:http begin " + mode + "\nserver {\n    listen 80;\n    listen [::]:80;\n"
		if mode == "redirect" {
			out += "    server_name " + names + ";\n    return 301 https://$host$request_uri;\n"
		} else {
			var keep []string
			for _, ln := range strings.Split(b0[b.Open+1:b.Close], "\n") {
				t := strings.TrimSpace(ln)
				if strings.HasPrefix(t, "listen ") || strings.HasPrefix(t, "http2 ") || strings.HasPrefix(t, "http3 ") ||
					strings.HasPrefix(t, "add_header Alt-Svc") || strings.Contains(t, "swag-ui:h") ||
					t == "include /config/nginx/ssl.conf;" || strings.HasPrefix(t, "ssl_") {
					continue
				}
				keep = append(keep, ln)
			}
			out += strings.Trim(strings.Join(keep, "\n"), "\n") + "\n"
		}
		return b0 + "\n" + out + "}\n# swag-ui:http end\n", nil
	}
	return "", fmt.Errorf("no server block with 'listen 443' found")
}

func port80Info() string {
	d := readBase("site-confs/default.conf")
	switch {
	case d == "":
		return "default.conf not found"
	case regexp.MustCompile(`(?m)^\s*return\s+30[12]\s+https://`).MatchString(d):
		return "redirects everything to https (global force redirect)"
	case listen80Re.MatchString(d):
		return "listens on 80, no global https redirect found"
	}
	return "no listen 80"
}

func h3Tab(w http.ResponseWriter, r *http.Request) {
	v, _ := run("nginx", "-V")
	ver := "unknown"
	if m := verRe.FindStringSubmatch(v); m != nil {
		ver = m[1]
	}
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
	fmt.Fprintf(&s, tbl+"<tr><td>nginx<td>%s</tr><tr><td>http_v2_module<td>%v</tr><tr><td>http_v3_module<td>%v</tr><tr><td>UDP 443 published<td>%s</tr><tr><td>site-confs/default.conf :80<td>%s</tr></table>", e(ver), strings.Contains(v, "http_v2_module"), strings.Contains(v, "http_v3_module"), e(udp), e(port80Info()))
	s.WriteString("<p>http :80 per site: <b>default</b> = nothing added, port 80 is handled by default.conf; <b>redirect</b> = force http &rarr; https (301) for this site; <b>plain</b> = the site also answers on plain http without redirect. Plain is a generated copy of the locations: apply again after changing them. <tt>http2 on;</tt> needs nginx 1.25.1 or newer (nginx -t rolls back otherwise).<p>")
	s.WriteString(tbl + "<tr><th>file<th>http/2<th>http/3<th>http :80<th>change</tr>")
	for _, n := range h3Files() {
		b, err := os.ReadFile(filepath.Join(base, n))
		if err != nil {
			fmt.Fprintf(&s, "<tr><td>%s<td colspan=4>missing</tr>", e(n))
			continue
		}
		c := string(b)
		h2, h3 := h2State(c), h3State(c)
		hm, cell := "-", ""
		if h2 != "n/a" {
			ck := func(st string) string {
				return map[bool]string{true: " checked", false: ""}[strings.HasPrefix(st, "ON")]
			}
			cell = fmt.Sprintf("<form method=post action=/h3/do><input type=hidden name=op value=set><input type=hidden name=f value='%s'><input type=checkbox name=h2 value=1%s> h2 <input type=checkbox name=h3 value=1%s> h3", e(n), ck(h2), ck(h3))
			if strings.HasPrefix(n, "proxy-confs/") {
				hm = httpMode(c)
				opts := []string{"default", "redirect", "plain"}
				if hm == "manual" {
					opts = append([]string{"keep"}, opts...)
				}
				cell += " http :80 <select name=http>"
				for _, o := range opts {
					sel := ""
					if o == hm || (hm == "manual" && o == "keep") {
						sel = " selected"
					}
					cell += "<option" + sel + ">" + o + "</option>"
				}
				cell += "</select>"
			}
			cell += " <input type=submit value=apply></form>"
		}
		fmt.Fprintf(&s, "<tr><td>%s<td>%s<td>%s<td>%s<td>%s</tr>", e(n), h2, h3, hm, cell)
	}
	s.WriteString("</table><p>all files: ")
	for _, p := range []string{"h2", "h3"} {
		for _, v := range []string{"on", "off"} {
			fmt.Fprintf(&s, "<form method=post action=/h3/do style=display:inline><input type=hidden name=op value=bulk><input type=hidden name=proto value=%s><input type=hidden name=val value=%s><input type=submit value='%s %s'></form> ", p, v, p, v)
		}
	}
	page(w, "h3", s.String())
}

func h3Do(w http.ResponseWriter, r *http.Request) {
	op, f := r.FormValue("op"), r.FormValue("f")
	all := h3Files()
	type chg struct {
		name string
		fn   func(string) (string, error)
	}
	var cs []chg
	switch op {
	case "set":
		if !has(all, f) {
			http.Error(w, "bad file", 400)
			return
		}
		h2, h3, mode := r.FormValue("h2") == "1", r.FormValue("h3") == "1", r.FormValue("http")
		cs = append(cs, chg{f, func(s string) (string, error) {
			if h2 {
				s = h2On(s)
			} else {
				s = h2Off(s)
			}
			if h3 {
				s = h3On(s)
			} else {
				s = h3Off(s)
			}
			if strings.HasPrefix(f, "proxy-confs/") && (mode == "default" || mode == "redirect" || mode == "plain") {
				return httpSet(s, mode)
			}
			return s, nil
		}})
	case "bulk":
		proto, on := r.FormValue("proto"), r.FormValue("val") == "on"
		if proto != "h2" && proto != "h3" {
			http.Error(w, "bad proto", 400)
			return
		}
		for _, n := range all {
			cs = append(cs, chg{n, func(s string) (string, error) {
				switch {
				case proto == "h2" && on:
					return h2On(s), nil
				case proto == "h2":
					return h2Off(s), nil
				case on:
					return h3On(s), nil
				}
				return h3Off(s), nil
			}})
		}
	default:
		http.Error(w, "bad op", 400)
		return
	}
	old, neu := map[string][]byte{}, map[string]string{}
	for _, c := range cs {
		b, err := os.ReadFile(filepath.Join(base, c.name))
		if err != nil {
			continue
		}
		ns, err := c.fn(string(b))
		if err != nil {
			result(w, "ERROR in "+c.name, err.Error(), "/h3")
			return
		}
		if ns != string(b) {
			old[c.name], neu[c.name] = b, ns
		}
	}
	if len(old) == 0 {
		result(w, "nothing to change", "", "/h3")
		return
	}
	for n, ns := range neu {
		p := filepath.Join(base, n)
		os.WriteFile(p+".bak", old[n], 0644)
		os.WriteFile(p, []byte(ns), 0644)
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
