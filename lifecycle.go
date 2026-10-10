package main

// lifecycle.go: ACME lifecycle tab (replaces the old certs/domains view).
// Data comes from certbot's own files: live/ certs, renewal/*.conf, letsencrypt.log, SWAG crontab.

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	acmeTS     = regexp.MustCompile(`^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d),\d+:`)
	acmeProc   = regexp.MustCompile(`Processing /config/etc/letsencrypt/renewal/([A-Za-z0-9._-]+)\.conf`)
	acmeFail   = regexp.MustCompile(`Failed to renew certificate ([A-Za-z0-9._-]+) with error: (.*)$`)
	acmeOK     = regexp.MustCompile(`new certificate deployed (?:with|without) reload, fullchain is /config/etc/letsencrypt/live/([A-Za-z0-9._-]+)/`)
	acmeNot    = regexp.MustCompile(`not yet due for renewal`)
	renewCmdRe = regexp.MustCompile(`^certbot renew --non-interactive --cert-name [A-Za-z0-9][A-Za-z0-9.-]{0,99}( --force-renewal)? --config-dir /config/etc/letsencrypt --work-dir /tmp/letsencrypt-lib --logs-dir /config/log/letsencrypt$`)

	rMu  sync.Mutex
	rCur *rjob
)

func init() {
	okCmd = append(okCmd, renewCmdRe)
	http.HandleFunc("/certs/do", guard(certsDo))
	http.HandleFunc("/certs/job", guard(certsJob))
}

type acmeEv struct {
	Attempt, Fail, OK, Checked time.Time
	Reason                     string
}

func readTail(p string, max int64) string {
	f, err := os.Open(p)
	if err != nil {
		return ""
	}
	defer f.Close()
	st, _ := f.Stat()
	if st.Size() > max {
		f.Seek(st.Size()-max, 0)
	}
	b, _ := io.ReadAll(f)
	return string(b)
}

func parseACME(dir string) map[string]*acmeEv {
	ev := map[string]*acmeEv{}
	get := func(n string) *acmeEv {
		if ev[n] == nil {
			ev[n] = &acmeEv{}
		}
		return ev[n]
	}
	var names []string
	for i := 9; i >= 1; i-- {
		names = append(names, fmt.Sprintf("letsencrypt.log.%d", i))
	}
	names = append(names, "letsencrypt.log")
	var ts time.Time
	cur := ""
	for _, n := range names {
		for _, l := range strings.Split(readTail(filepath.Join(dir, n), 8<<20), "\n") {
			if m := acmeTS.FindStringSubmatch(l); m != nil {
				if t, err := time.ParseInLocation("2006-01-02 15:04:05", m[1], time.Local); err == nil {
					ts = t
				}
			}
			if m := acmeProc.FindStringSubmatch(l); m != nil {
				cur = m[1]
				get(cur).Attempt = ts
			}
			if m := acmeFail.FindStringSubmatch(l); m != nil {
				x := get(m[1])
				x.Fail, x.Reason = ts, strings.TrimSpace(m[2])
			}
			if m := acmeOK.FindStringSubmatch(l); m != nil {
				get(m[1]).OK = ts
			}
			if cur != "" && acmeNot.MatchString(l) {
				get(cur).Checked = ts
			}
		}
	}
	return ev
}

func certNotBefore(name string) time.Time {
	b, err := os.ReadFile(filepath.Join(le, name, "fullchain.pem"))
	if err != nil {
		return time.Time{}
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return time.Time{}
	}
	if x, err := x509.ParseCertificate(blk.Bytes); err == nil {
		return x.NotBefore
	}
	return time.Time{}
}

func renewConf(name string) (auth, server string, before int) {
	b, _ := os.ReadFile(filepath.Join(root, "etc", "letsencrypt", "renewal", name+".conf"))
	g := func(k string) string {
		m := regexp.MustCompile(`(?m)^\s*` + k + `\s*=\s*(.+?)\s*$`).FindStringSubmatch(string(b))
		if m == nil {
			return ""
		}
		return m[1]
	}
	before = 30
	if m := regexp.MustCompile(`^(\d+)\s*days?`).FindStringSubmatch(g("renew_before_expiry")); m != nil {
		before, _ = strconv.Atoi(m[1])
	}
	return g("authenticator"), g("server"), before
}

// ---- cron (SWAG renews from its own crontab) ----

func cronLine() string {
	b, _ := os.ReadFile(filepath.Join(root, "crontabs", "root"))
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "#") && (strings.Contains(l, "renew") || strings.Contains(l, "certbot")) {
			return l
		}
	}
	return ""
}

func cronField(f string, v, lo, hi int) bool {
	for _, part := range strings.Split(f, ",") {
		step, rng, slash := 1, part, strings.Index(part, "/")
		if slash >= 0 {
			step, _ = strconv.Atoi(part[slash+1:])
			rng = part[:slash]
		}
		a, b := lo, hi
		if rng != "*" {
			if j := strings.Index(rng, "-"); j >= 0 {
				a, _ = strconv.Atoi(rng[:j])
				b, _ = strconv.Atoi(rng[j+1:])
			} else {
				a, _ = strconv.Atoi(rng)
				if slash < 0 {
					b = a
				}
			}
		}
		if step < 1 {
			step = 1
		}
		if v >= a && v <= b && (v-a)%step == 0 {
			return true
		}
	}
	return false
}

func cronNext(spec string, from time.Time) (time.Time, bool) {
	f := strings.Fields(spec)
	if len(f) < 5 {
		return time.Time{}, false
	}
	t := from.Truncate(time.Minute).Add(time.Minute)
	for i := 0; i < 366*24*60; i++ {
		dom := cronField(f[2], t.Day(), 1, 31)
		dow := cronField(f[4], int(t.Weekday()), 0, 7) || (t.Weekday() == 0 && cronField(f[4], 7, 0, 7))
		day := dom && dow
		switch {
		case f[2] == "*" && f[4] != "*":
			day = dow
		case f[2] != "*" && f[4] == "*":
			day = dom
		case f[2] != "*" && f[4] != "*":
			day = dom || dow
		}
		if day && cronField(f[3], int(t.Month()), 1, 12) && cronField(f[1], t.Hour(), 0, 23) && cronField(f[0], t.Minute(), 0, 59) {
			return t, true
		}
		t = t.Add(time.Minute)
	}
	return time.Time{}, false
}

func ft(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Format("2006-01-02 15:04")
}

func certsTab(w http.ResponseWriter, r *http.Request) {
	cs, err := loadCerts()
	ev := parseACME(filepath.Join(logRoot, "letsencrypt"))
	cl := cronLine()
	next, hasNext := cronNext(cl, time.Now())
	var s strings.Builder
	if err != nil {
		s.WriteString("<b>ERROR " + e(le) + ": " + e(err.Error()) + "</b><br>")
	}
	if cl == "" {
		s.WriteString("renewal schedule: not found in " + e(root) + "/crontabs/root (next check unknown)<br>")
	} else {
		fmt.Fprintf(&s, "renewal schedule (SWAG cron): <tt>%s</tt>. Times are in the swag-ui container timezone; log times are read as the same zone.<br>", e(cl))
	}
	if j := rCur; j != nil {
		s.WriteString("<a href=/certs/job>[ last / running renewal ]</a><br>")
	}
	s.WriteString("<h3>ACME lifecycle</h3>" + tbl + "<tr><th>certificate<th>status<th>expires<th>renew from<th>next check<th>last attempt<th>last success<th>last failure<th>failure reason<th>actions</tr>")
	for _, c := range cs {
		x := ev[c.Name]
		if x == nil {
			x = &acmeEv{}
		}
		auth, server, before := renewConf(c.Name)
		ok := certNotBefore(c.Name)
		if x.OK.After(ok) {
			ok = x.OK
		}
		att := x.Attempt
		reason := "-"
		if !x.Fail.IsZero() {
			reason = e(x.Reason)
			if !x.Fail.After(ok) {
				reason += " (resolved: a later renewal succeeded)"
			}
		}
		info := e(strings.Join(c.SANs, " "))
		if auth != "" {
			info += "<br>" + e(auth)
		}
		if strings.Contains(server, "staging") {
			info += "<br><b>STAGING (not trusted)</b>"
		}
		nx := "-"
		if hasNext {
			nx = ft(next)
		}
		fmt.Fprintf(&s, "<tr><td>%s<br>%s<td>%s<td>%s (%d d)<td>%s<td>%s<td>%s<td>%s<td>%s<td>%s<td>", e(c.Name), info, c.status(), c.NotAfter.Format("2006-01-02"), c.days(), ft(c.NotAfter.AddDate(0, 0, -before)), nx, ft(att), ft(ok), ft(x.Fail), reason)
		fmt.Fprintf(&s, "<form method=post action=/certs/do><input type=hidden name=name value='%s'><input type=hidden name=op value=renew><input type=submit value='renew now'></form>", e(c.Name))
		fmt.Fprintf(&s, "<form method=post action=/certs/do><input type=hidden name=name value='%s'><input type=hidden name=op value=force><input type=checkbox name=confirm value=1> rate limits<br><input type=submit value='force renewal'></form></tr>", e(c.Name))
	}
	s.WriteString("</table><p>renew now: runs the renewal check immediately, certbot renews only certificates that are due. force renewal: issues a new certificate even if it is not due; Let's Encrypt limits duplicate certificates (5 per week), so use it sparingly.")
	s.WriteString("<h3>hosts from active proxy-confs</h3>" + tbl + "<tr><th>conf<th>host<th>cert<th>days<th>status</tr>")
	for _, h := range hostRows(cs) {
		fmt.Fprintf(&s, "<tr><td>%s<td>%s<td>%s<td>%s<td>%s</tr>", e(h.Conf), e(h.Host), e(h.Cert), h.Days, h.Status)
	}
	s.WriteString("</table>")
	page(w, "certs", s.String())
}

type rjob struct {
	Name       string
	Force      bool
	Start, End time.Time
	Done, OK   bool
	Out        string
}

func renewArgs(name string, force bool) []string {
	a := []string{"certbot", "renew", "--non-interactive", "--cert-name", name}
	if force {
		a = append(a, "--force-renewal")
	}
	return append(a, "--config-dir", "/config/etc/letsencrypt", "--work-dir", "/tmp/letsencrypt-lib", "--logs-dir", "/config/log/letsencrypt")
}

func certsDo(w http.ResponseWriter, r *http.Request) {
	name, force := r.FormValue("name"), r.FormValue("op") == "force"
	cs, _ := loadCerts()
	known := false
	for _, c := range cs {
		known = known || c.Name == name
	}
	if !known {
		http.Error(w, "unknown certificate", 400)
		return
	}
	if force && r.FormValue("confirm") != "1" {
		result(w, "tick the 'rate limits' box to confirm the forced renewal", "", "/certs")
		return
	}
	args := renewArgs(name, force)
	if !cmdAllowed(args) {
		result(w, "rejected by the command whitelist", "", "/certs")
		return
	}
	rMu.Lock()
	if rCur != nil && !rCur.Done {
		rMu.Unlock()
		result(w, "another renewal is still running", "", "/certs/job")
		return
	}
	j := &rjob{Name: name, Force: force, Start: time.Now()}
	rCur = j
	rMu.Unlock()
	go func() {
		out, code := run(args...)
		if code == 0 && isAuto() {
			o2, _ := applyCfg(true)
			out += "\n--- nginx -t + reload ---\n" + o2
		}
		rMu.Lock()
		j.Out, j.OK, j.Done, j.End = out, code == 0, true, time.Now()
		rMu.Unlock()
	}()
	http.Redirect(w, r, "/certs/job", 303)
}

func certsJob(w http.ResponseWriter, r *http.Request) {
	rMu.Lock()
	var j rjob
	if rCur != nil {
		j = *rCur
	}
	rMu.Unlock()
	if j.Name == "" {
		http.Redirect(w, r, "/certs", 303)
		return
	}
	mode := map[bool]string{true: "forced renewal", false: "renewal check"}[j.Force]
	var s strings.Builder
	if !j.Done {
		fmt.Fprintf(&s, "<meta http-equiv=refresh content=3><b>RUNNING</b> %s of %s, %ds<p>letsencrypt.log (tail):", mode, e(j.Name), int(time.Since(j.Start).Seconds()))
		ls, _ := tailLines(filepath.Join(logRoot, "letsencrypt", "letsencrypt.log"), 25, "")
		s.WriteString("<pre>" + e(strings.Join(ls, "\n")) + "</pre>")
	} else {
		fmt.Fprintf(&s, "<b>%s</b> %s of %s in %ds<pre>%s</pre>", map[bool]string{true: "SUCCESS", false: "FAILED"}[j.OK], mode, e(j.Name), int(j.End.Sub(j.Start).Seconds()), e(j.Out))
		if j.OK && !isAuto() {
			s.WriteString("A renewed certificate is served only after a reload (manual mode):<form method=post action=/reload><input type=submit value='nginx -t + reload now'></form>")
		}
	}
	page(w, "certs", s.String()+"<a href=/certs>[ back ]</a>")
}
