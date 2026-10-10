package main

// dns.go: /config/dns-conf/*.ini viewer/editor. Comments are shown; secret values are
// never sent to the browser (masked on view, restored from the saved file on save).

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var (
	secretKey = regexp.MustCompile(`(?i)(token|secret|passw|key|credential|auth)`)
	iniKV     = regexp.MustCompile(`^(\s*)([A-Za-z0-9_.-]+)\s*=\s*(.*?)\s*$`)
)

func init() {
	tabs = append(tabs, [2]string{"dns", "dns-conf"})
	http.HandleFunc("/dns", guard(dnsTab))
	http.HandleFunc("/dns/save", guard(dnsSave))
}

func dnsProviders(known []string) []string {
	m := map[string]bool{}
	for _, k := range known {
		m[k] = true
	}
	fs, _ := filepath.Glob(filepath.Join(root, "dns-conf", "*.ini"))
	for _, f := range fs {
		m[strings.TrimSuffix(filepath.Base(f), ".ini")] = true
	}
	var r []string
	for k := range m {
		if plugRe.MatchString(k) {
			r = append(r, k)
		}
	}
	sort.Strings(r)
	return r
}

// file content for the browser: comments and variables, secret values removed
func dnsView(pl string) (string, []string) {
	b, err := os.ReadFile(credPath(pl))
	if pl == "" || err != nil {
		return "", nil
	}
	var out, sec []string
	for _, l := range strings.Split(strings.TrimRight(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n"), "\n") {
		if m := iniKV.FindStringSubmatch(l); m != nil && m[3] != "" && secretKey.MatchString(m[2]) {
			sec = append(sec, m[2])
			l = m[1] + m[2] + " = "
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n") + "\n", sec
}

func iniVals(s string) map[string]string {
	m := map[string]string{}
	for _, l := range strings.Split(s, "\n") {
		if k := iniKV.FindStringSubmatch(l); k != nil && k[3] != "" {
			m[k[2]] = k[3]
		}
	}
	return m
}

// empty values in the new text keep the secret saved in the old file
func mergeCred(old, nw string) string {
	ov := iniVals(old)
	var out []string
	for _, l := range strings.Split(strings.TrimRight(strings.ReplaceAll(nw, "\r\n", "\n"), "\n"), "\n") {
		if m := iniKV.FindStringSubmatch(l); m != nil && m[3] == "" && ov[m[2]] != "" {
			l = m[1] + m[2] + " = " + ov[m[2]]
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n") + "\n"
}

// set key = val, keeping all comments: replaces the live line, else the commented example, else appends
func iniSet(content, key, val string) string {
	lines := strings.Split(strings.TrimRight(content, "\n"), "\n")
	if content == "" {
		lines = nil
	}
	live := regexp.MustCompile(`^\s*` + regexp.QuoteMeta(key) + `\s*=`)
	cm := regexp.MustCompile(`^\s*#\s*` + regexp.QuoteMeta(key) + `\s*=`)
	ci := -1
	for i, l := range lines {
		if live.MatchString(l) {
			lines[i] = key + " = " + val
			return strings.Join(lines, "\n") + "\n"
		}
		if ci < 0 && cm.MatchString(l) {
			ci = i
		}
	}
	if ci >= 0 {
		lines[ci] = key + " = " + val
	} else {
		lines = append(lines, key+" = "+val)
	}
	return strings.Join(lines, "\n") + "\n"
}

func writeCred(pl, content string) error {
	p := credPath(pl)
	os.MkdirAll(filepath.Dir(p), 0755)
	if err := os.WriteFile(p+".tmp", []byte(content), 0600); err != nil {
		return err
	}
	return os.Rename(p+".tmp", p)
}

// dedicated forms: one variable, rest of the file (comments) preserved; empty = keep saved
func saveKey(pl, key, val string, re *regexp.Regexp) error {
	if val == "" {
		if credSaved(pl, re) {
			return nil
		}
		return fmt.Errorf("no saved credentials for %s, fill in the token", pl)
	}
	b, _ := os.ReadFile(credPath(pl))
	return writeCred(pl, iniSet(string(b), key, val))
}

// whole-file form: empty values keep saved secrets
func saveWhole(pl, content string, re *regexp.Regexp) error {
	if strings.TrimSpace(content) == "" {
		if credSaved(pl, re) {
			return nil
		}
		return fmt.Errorf("no saved credentials for %s, fill in the credentials field", pl)
	}
	b, _ := os.ReadFile(credPath(pl))
	return writeCred(pl, mergeCred(string(b), content))
}

func dnsTab(w http.ResponseWriter, r *http.Request) {
	pl := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("pl")))
	var s strings.Builder
	fmt.Fprintf(&s, "files: %s/dns-conf/*.ini. Variables and # comments are shown; secret values are never sent to the browser.<p>", e(root))
	for _, p := range dnsProviders(nil) {
		if p == pl {
			s.WriteString("<b>[ " + e(p) + " ]</b> ")
		} else {
			s.WriteString("<a href='/dns?pl=" + e(p) + "'>[ " + e(p) + " ]</a> ")
		}
	}
	s.WriteString("<form method=get action=/dns>other provider: <input name=pl size=20> <input type=submit value=open></form>")
	if plugRe.MatchString(pl) {
		v, sec := dnsView(pl)
		note := "file does not exist yet, it will be created (mode 0600)"
		if fileExists(credPath(pl)) {
			note = "file exists"
		}
		if len(sec) > 0 {
			note += "; secret values saved for: " + strings.Join(sec, ", ") + " (leave them empty to keep)"
		}
		fmt.Fprintf(&s, "<hr><b>%s.ini</b>: %s<form method=post action=/dns/save><input type=hidden name=pl value='%s'><textarea name=content rows=24 cols=100 spellcheck=false>%s</textarea><br><input type=submit value=save></form>Uncomment a line (remove #) and fill in the value to use it. No nginx reload is needed; certbot reads the file on the next issue/renew.", e(pl), e(note), e(pl), e(v))
	}
	page(w, "dns", s.String())
}

func dnsSave(w http.ResponseWriter, r *http.Request) {
	pl, c := strings.ToLower(r.FormValue("pl")), r.FormValue("content")
	if !plugRe.MatchString(pl) || len(c) > 16384 {
		http.Error(w, "bad input", 400)
		return
	}
	var err error
	if strings.TrimSpace(c) != "" {
		b, _ := os.ReadFile(credPath(pl))
		err = writeCred(pl, mergeCred(string(b), c))
	}
	if err != nil {
		result(w, "ERROR: "+err.Error(), "", "/dns?pl="+pl)
		return
	}
	http.Redirect(w, r, "/dns?pl="+pl, 303)
}
