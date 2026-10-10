package main

// f2bcfg.go: fail2ban configuration: jails, filters (rules), actions, log paths.
// Files live in /config/fail2ban. New jails are written to jail.local inside
// "# swag-ui:jail begin/end" blocks. Change = write, fail2ban-client -t, reload, rollback.

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var (
	f2bDir    = env("F2B_DIR", root+"/fail2ban")
	secHdr    = regexp.MustCompile(`^\s*\[([^\]]+)\]\s*$`)
	jkvRe     = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$`)
	f2bFileRe = regexp.MustCompile(`^(jail\.local|(jail\.d|filter\.d|action\.d)/[A-Za-z0-9_][A-Za-z0-9._-]{0,59}\.(conf|local))$`)
	f2bJailRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_-]{0,39}$`)
	f2bNameRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_-]{0,59}$`)
	f2bTimeRe = regexp.MustCompile(`^-?[0-9]{1,9}[smhdw]?$`)
	f2bPortRe = regexp.MustCompile(`^[A-Za-z0-9,:_-]{1,60}$`)
	f2bLogRe  = regexp.MustCompile(`^/config/log(/[A-Za-z0-9_*-][A-Za-z0-9._*-]{0,60}){1,5}$`)
	f2bNumRe  = regexp.MustCompile(`^[0-9]{1,5}$`)
)

func init() {
	okCmd = append(okCmd,
		regexp.MustCompile(`^fail2ban-client (-t|reload)$`),
		regexp.MustCompile(`^fail2ban-regex /config/log(/[A-Za-z0-9_-][A-Za-z0-9._-]{0,60}){1,5} /config/fail2ban/filter\.d/[A-Za-z0-9_][A-Za-z0-9._-]{0,59}\.(conf|local)$`))
	tabs = append(tabs, [2]string{"f2bcfg", "f2b jails"})
	for p, h := range map[string]http.HandlerFunc{"/f2bcfg": f2bCfgTab, "/f2bcfg/file": f2bFileTab, "/f2bcfg/do": f2bCfgDo} {
		http.HandleFunc(p, guard(h))
	}
}

type f2bJailDef struct {
	File, Name string
	Start      int
	Keys       map[string]string
	Multi      map[string]bool
	Managed    bool
}

func parseJails(src string) ([]string, []f2bJailDef) {
	lines := strings.Split(src, "\n")
	var defs []f2bJailDef
	last := ""
	for i, ln := range lines {
		t := strings.TrimSpace(ln)
		if m := secHdr.FindStringSubmatch(ln); m != nil {
			defs = append(defs, f2bJailDef{Name: m[1], Start: i, Keys: map[string]string{}, Multi: map[string]bool{},
				Managed: i > 0 && strings.Contains(lines[i-1], "swag-ui:jail begin")})
			last = ""
			continue
		}
		if t == "" {
			last = ""
			continue
		}
		if len(defs) == 0 || t[0] == '#' || t[0] == ';' {
			continue
		}
		d := &defs[len(defs)-1]
		if ln[0] == ' ' || ln[0] == '\t' {
			if last != "" {
				d.Keys[last] += " " + t
				d.Multi[last] = true
			}
			continue
		}
		if m := jkvRe.FindStringSubmatch(ln); m != nil {
			d.Keys[m[1]] = m[2]
			last = m[1]
		}
	}
	return lines, defs
}

func setKey(src, name, key, val string) (string, error) {
	lines, defs := parseJails(src)
	for k, d := range defs {
		if d.Name != name {
			continue
		}
		if d.Multi[key] {
			return "", fmt.Errorf("key %s of [%s] spans several lines: edit the file as raw text", key, name)
		}
		end := len(lines)
		if k+1 < len(defs) {
			end = defs[k+1].Start
		}
		for i := d.Start + 1; i < end; i++ {
			if m := jkvRe.FindStringSubmatch(lines[i]); m != nil && m[1] == key {
				lines[i] = key + " = " + val
				return strings.Join(lines, "\n"), nil
			}
		}
		return strings.Join(ins(lines, d.Start, key+" = "+val), "\n"), nil
	}
	return "", fmt.Errorf("jail [%s] not found", name)
}

func delJailBlock(src, name string) string {
	re := regexp.MustCompile(`(?s)\n*# swag-ui:jail begin ` + regexp.QuoteMeta(name) + `\n.*?# swag-ui:jail end ` + regexp.QuoteMeta(name) + `\n?`)
	return re.ReplaceAllString(src, "\n")
}

func readF2b(rel string) string { b, _ := os.ReadFile(filepath.Join(f2bDir, rel)); return string(b) }

func f2bNames(sub string) (r []string) {
	fs, _ := os.ReadDir(filepath.Join(f2bDir, sub))
	for _, f := range fs {
		n := f.Name()
		if !f.IsDir() && (strings.HasSuffix(n, ".conf") || strings.HasSuffix(n, ".local")) && f2bFileRe.MatchString(sub+"/"+n) {
			r = append(r, n)
		}
	}
	return
}

func f2bBase(names []string) (r []string) {
	seen := map[string]bool{}
	for _, n := range names {
		b := strings.TrimSuffix(strings.TrimSuffix(n, ".conf"), ".local")
		if !seen[b] {
			seen[b] = true
			r = append(r, b)
		}
	}
	sort.Strings(r)
	return
}

func f2bJailFiles() (r []string) {
	if fileExists(filepath.Join(f2bDir, "jail.local")) {
		r = append(r, "jail.local")
	}
	for _, n := range f2bNames("jail.d") {
		r = append(r, "jail.d/"+n)
	}
	return
}

func allJails() (defs []f2bJailDef) {
	for _, rel := range f2bJailFiles() {
		_, ds := parseJails(readF2b(rel))
		for i := range ds {
			ds[i].File = rel
		}
		defs = append(defs, ds...)
	}
	return
}

func f2bLogFiles() (r []string) {
	ds, _ := os.ReadDir(logRoot)
	for _, d := range ds {
		if d.IsDir() {
			for _, f := range listNames(filepath.Join(logRoot, d.Name()), false) {
				r = append(r, "/config/log/"+d.Name()+"/"+f)
			}
		}
	}
	return
}

func f2bApply() (string, bool) {
	o, c := run("fail2ban-client", "-t")
	if c != 0 {
		return o, false
	}
	o2, c2 := run("fail2ban-client", "reload")
	return o + o2, c2 == 0
}

func f2bChange(rel string, fn func(string) (string, error)) (string, bool) {
	if !f2bFileRe.MatchString(rel) {
		return "bad file", false
	}
	p := filepath.Join(f2bDir, rel)
	old, err := os.ReadFile(p)
	exists := err == nil
	ns, err := fn(string(old))
	if err != nil {
		return err.Error(), false
	}
	if exists && ns == string(old) {
		return "no change", true
	}
	mode := os.FileMode(0644)
	if exists {
		if fi, e2 := os.Stat(p); e2 == nil {
			mode = fi.Mode().Perm()
		}
		os.WriteFile(p+".bak", old, mode)
	}
	os.MkdirAll(filepath.Dir(p), 0755)
	if err := os.WriteFile(p, []byte(ns), mode); err != nil {
		return err.Error(), false
	}
	out, ok := f2bApply()
	if !ok {
		if exists {
			os.WriteFile(p, old, mode)
		} else {
			os.Remove(p)
		}
		return "FAILED, rolled back\n" + out, false
	}
	return out, true
}

func logState(v string) string {
	if !strings.HasPrefix(v, "/config/") {
		return "outside /config, not checked"
	}
	m, _ := filepath.Glob(filepath.Join(root, strings.TrimPrefix(v, "/config")))
	if len(m) == 0 {
		return "<b>MISSING</b>"
	}
	return fmt.Sprintf("%d file(s) found", len(m))
}

func dl(id string, vals []string) string {
	var s strings.Builder
	s.WriteString("<datalist id=" + id + ">")
	for _, v := range vals {
		s.WriteString("<option value='" + e(v) + "'>")
	}
	return s.String() + "</datalist>"
}

func usedBy(key string, defs []f2bJailDef) map[string][]string {
	m := map[string][]string{}
	for _, d := range defs {
		for _, w := range strings.FieldsFunc(d.Keys[key], func(r rune) bool { return r == ' ' || r == '[' || r == ',' }) {
			m[w] = append(m[w], d.Name)
		}
	}
	return m
}

func f2bCfgTab(w http.ResponseWriter, r *http.Request) {
	defs := allJails()
	filters, actions := f2bBase(f2bNames("filter.d")), f2bBase(f2bNames("action.d"))
	var s strings.Builder
	if len(defs) == 0 {
		s.WriteString("<b>no jails found in " + e(f2bDir) + "</b> (is the fail2ban mod enabled in SWAG and /config mounted?)<br>")
	}
	s.WriteString(dl("flt", filters) + dl("act", actions) + dl("logs", f2bLogFiles()))
	s.WriteString("<h3>jails</h3>")
	for _, d := range defs {
		k := d.Keys
		def := d.Name == "DEFAULT"
		fmt.Fprintf(&s, "<form method=post action=/f2bcfg/do><input type=hidden name=op value=setjail><input type=hidden name=f value='%s'><input type=hidden name=jail value='%s'><b>[%s]</b> (%s%s) ", e(d.File), e(d.Name), e(d.Name), e(d.File), map[bool]string{true: ", managed by swag-ui", false: ""}[d.Managed])
		if !def {
			fmt.Fprintf(&s, "<input type=checkbox name=enabled value=1%s> enabled<br>filter: <input name=filter list=flt size=24 value='%s'> port: <input name=port size=14 value='%s'> action: <input name=action list=act size=24 value='%s'><br>logpath: <input name=logpath list=logs size=60 value='%s'> %s<br>", map[bool]string{true: " checked", false: ""}[k["enabled"] == "true"], e(k["filter"]), e(k["port"]), e(k["action"]), e(k["logpath"]), logState(k["logpath"]))
		}
		fmt.Fprintf(&s, "maxretry: <input name=maxretry size=5 value='%s'> findtime: <input name=findtime size=6 value='%s'> bantime: <input name=bantime size=6 value='%s'> <input type=submit value='save + test + reload'></form>", e(k["maxretry"]), e(k["findtime"]), e(k["bantime"]))
		if d.Managed {
			fmt.Fprintf(&s, "<form method=post action=/f2bcfg/do><input type=hidden name=op value=deljail><input type=hidden name=f value='%s'><input type=hidden name=jail value='%s'><input type=submit value='delete this jail'></form>", e(d.File), e(d.Name))
		}
		s.WriteString("<hr>")
	}
	s.WriteString("Empty field = unchanged. Filters from /config/fail2ban/filter.d are suggested; built-in fail2ban filter names can be typed too.")
	s.WriteString("<h3>new jail</h3><form method=post action=/f2bcfg/do><input type=hidden name=op value=newjail>name: <input name=jail size=20> <input type=checkbox name=enabled value=1 checked> enabled<br>filter: <input name=filter list=flt size=24> port: <input name=port size=14 value='http,https'> action (optional): <input name=action list=act size=24><br>logpath: <input name=logpath list=logs size=60 value='/config/log/nginx/access.log'><br>maxretry: <input name=maxretry size=5 value=5> findtime: <input name=findtime size=6 value=10m> bantime: <input name=bantime size=6 value=1h> <input type=submit value='create + test + reload'></form>")
	s.WriteString("<h3>filters (rules)</h3>" + tbl + "<tr><th>filter<th>used by jails<th></tr>")
	fu := usedBy("filter", defs)
	for _, n := range f2bNames("filter.d") {
		fmt.Fprintf(&s, "<tr><td>%s<td>%s<td><a href='/f2bcfg/file?f=%s'>[ view / edit ]</a></tr>", e(n), e(strings.Join(fu[strings.TrimSuffix(strings.TrimSuffix(n, ".conf"), ".local")], ", ")), url.QueryEscape("filter.d/"+n))
	}
	s.WriteString("</table><form method=post action=/f2bcfg/do><input type=hidden name=op value=testfilter>test filter <input name=filter list=flt size=24> against <input name=log list=logs size=50> <input type=submit value='run fail2ban-regex'></form>")
	s.WriteString("<form method=post action=/f2bcfg/do><input type=hidden name=op value=newfilter>new filter: name <input name=name size=20><br>failregex (one per line, use &lt;HOST&gt;):<br><textarea name=failregex rows=4 cols=90 spellcheck=false></textarea><br>ignoreregex (optional):<br><textarea name=ignoreregex rows=2 cols=90 spellcheck=false></textarea><br><input type=submit value='create filter'></form>")
	s.WriteString("<h3>actions</h3>" + tbl + "<tr><th>action<th>used by jails<th></tr>")
	au := usedBy("action", defs)
	for _, n := range f2bNames("action.d") {
		fmt.Fprintf(&s, "<tr><td>%s<td>%s<td><a href='/f2bcfg/file?f=%s'>[ view / edit ]</a></tr>", e(n), e(strings.Join(au[strings.TrimSuffix(strings.TrimSuffix(n, ".conf"), ".local")], ", ")), url.QueryEscape("action.d/"+n))
	}
	s.WriteString("</table><h3>raw files</h3>")
	for _, f := range f2bJailFiles() {
		s.WriteString("<a href='/f2bcfg/file?f=" + url.QueryEscape(f) + "'>[ " + e(f) + " ]</a> ")
	}
	page(w, "f2bcfg", s.String())
}

func f2bFileTab(w http.ResponseWriter, r *http.Request) {
	f := r.URL.Query().Get("f")
	if !f2bFileRe.MatchString(f) {
		http.Error(w, "bad file", 400)
		return
	}
	page(w, "f2bcfg", fmt.Sprintf("<form method=post action=/f2bcfg/do><input type=hidden name=op value=savefile><input type=hidden name=f value='%s'>file: %s/%s<br><textarea name=c rows=34 cols=110 spellcheck=false>%s</textarea><br><input type=submit value='save + fail2ban-client -t + reload'> <a href=/f2bcfg>[ close without saving ]</a></form>", e(f), e(f2bDir), e(f), e(readF2b(f))))
}

func f2bCfgDo(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	op, back := r.FormValue("op"), "/f2bcfg"
	bad := func(m string) { result(w, "ERROR: "+m, "", back) }
	jail := strings.TrimSpace(r.FormValue("jail"))
	valid := func(key, v string) string {
		switch key {
		case "filter", "action":
			if v != "" && !f2bNameRe.MatchString(v) {
				return key + " must be a plain name"
			}
		case "port":
			if v != "" && !f2bPortRe.MatchString(v) {
				return "invalid port list"
			}
		case "logpath":
			if v != "" && !f2bLogRe.MatchString(v) {
				return "logpath must be a single path under /config/log (no '..')"
			}
		case "maxretry":
			if v != "" && !f2bNumRe.MatchString(v) {
				return "maxretry must be a number"
			}
		case "findtime", "bantime":
			if v != "" && !f2bTimeRe.MatchString(v) {
				return key + " must look like 600, 10m, 1h, 1d or -1"
			}
		}
		return ""
	}
	keys := []string{"filter", "port", "logpath", "action", "maxretry", "findtime", "bantime"}
	fin := func(msg string, out string, ok bool) {
		if !ok {
			msg = "FAILED"
		}
		result(w, msg, out, back)
	}
	switch op {
	case "setjail", "newjail":
		if !f2bJailRe.MatchString(jail) {
			bad("invalid jail name")
			return
		}
		for _, k := range keys {
			if m := valid(k, strings.TrimSpace(r.FormValue(k))); m != "" {
				bad(m)
				return
			}
		}
		en := map[bool]string{true: "true", false: "false"}[r.FormValue("enabled") == "1"]
		if op == "newjail" {
			if jail == "DEFAULT" || r.FormValue("filter") == "" || r.FormValue("logpath") == "" {
				bad("name, filter and logpath are required (name must not be DEFAULT)")
				return
			}
			for _, d := range allJails() {
				if d.Name == jail {
					bad("jail already exists in " + d.File)
					return
				}
			}
			out, ok := f2bChange("jail.local", func(s string) (string, error) {
				if s != "" && !strings.HasSuffix(s, "\n") {
					s += "\n"
				}
				b := "\n# swag-ui:jail begin " + jail + "\n[" + jail + "]\nenabled  = " + en + "\n"
				for _, k := range keys {
					if v := strings.TrimSpace(r.FormValue(k)); v != "" {
						b += fmt.Sprintf("%-9s= %s\n", k, v)
					}
				}
				return s + b + "# swag-ui:jail end " + jail + "\n", nil
			})
			fin("jail created", out, ok)
			return
		}
		file := r.FormValue("f")
		var cur *f2bJailDef
		for _, d := range allJails() {
			if d.File == file && d.Name == jail {
				d := d
				cur = &d
			}
		}
		if cur == nil {
			bad("jail not found")
			return
		}
		out, ok := f2bChange(file, func(s string) (string, error) {
			if jail != "DEFAULT" && cur.Keys["enabled"] != en {
				var err error
				if s, err = setKey(s, jail, "enabled", en); err != nil {
					return "", err
				}
			}
			for _, k := range keys {
				if v := strings.TrimSpace(r.FormValue(k)); v != "" && v != cur.Keys[k] && (jail != "DEFAULT" || k == "maxretry" || k == "findtime" || k == "bantime") {
					var err error
					if s, err = setKey(s, jail, k, v); err != nil {
						return "", err
					}
				}
			}
			return s, nil
		})
		fin("saved", out, ok)
	case "deljail":
		file := r.FormValue("f")
		managed := false
		for _, d := range allJails() {
			managed = managed || (d.File == file && d.Name == jail && d.Managed)
		}
		if !managed {
			bad("only jails created by swag-ui can be deleted here (edit others as raw text)")
			return
		}
		out, ok := f2bChange(file, func(s string) (string, error) { return delJailBlock(s, jail), nil })
		fin("jail deleted", out, ok)
	case "savefile":
		f, c := r.FormValue("f"), strings.ReplaceAll(r.FormValue("c"), "\r\n", "\n")
		if !f2bFileRe.MatchString(f) || len(c) > 65536 {
			bad("bad file or too large")
			return
		}
		if !strings.HasSuffix(c, "\n") {
			c += "\n"
		}
		out, ok := f2bChange(f, func(string) (string, error) { return c, nil })
		fin("saved", out, ok)
	case "newfilter":
		name := strings.TrimSpace(r.FormValue("name"))
		var fr []string
		for _, l := range strings.Split(strings.ReplaceAll(r.FormValue("failregex"), "\r\n", "\n"), "\n") {
			if l = strings.TrimSpace(l); l != "" {
				fr = append(fr, l)
			}
		}
		if !f2bNameRe.MatchString(name) || len(fr) == 0 || len(r.FormValue("failregex")) > 8192 {
			bad("name and at least one failregex line are required")
			return
		}
		rel := "filter.d/" + name + ".conf"
		if fileExists(filepath.Join(f2bDir, rel)) {
			bad(rel + " already exists")
			return
		}
		c := "[Definition]\nfailregex = " + strings.Join(fr, "\n            ") + "\n"
		ig := ""
		for _, l := range strings.Split(strings.ReplaceAll(r.FormValue("ignoreregex"), "\r\n", "\n"), "\n") {
			if l = strings.TrimSpace(l); l != "" {
				if ig != "" {
					ig += "\n              "
				}
				ig += l
			}
		}
		c += "ignoreregex = " + ig + "\n"
		out, ok := f2bChange(rel, func(string) (string, error) { return c, nil })
		fin("filter created: now use it in a jail", out, ok)
	case "testfilter":
		flt, lg := r.FormValue("filter"), r.FormValue("log")
		if !f2bNameRe.MatchString(flt) || !f2bLogRe.MatchString(lg) || strings.Contains(lg, "*") {
			bad("choose an existing filter and a log file under /config/log")
			return
		}
		fp := ""
		for _, ext := range []string{".local", ".conf"} {
			if fileExists(filepath.Join(f2bDir, "filter.d", flt+ext)) {
				fp = "/config/fail2ban/filter.d/" + flt + ext
				break
			}
		}
		if fp == "" {
			bad("filter file not found in filter.d")
			return
		}
		out, _ := run("fail2ban-regex", lg, fp)
		ls := strings.Split(strings.TrimSpace(out), "\n")
		if len(ls) > 60 {
			ls = ls[len(ls)-60:]
		}
		result(w, "fail2ban-regex "+flt+" on "+lg, strings.Join(ls, "\n"), back)
	default:
		http.Error(w, "unknown op", 400)
	}
}
