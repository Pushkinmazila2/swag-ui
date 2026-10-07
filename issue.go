package main

// issue.go: certificate issuance via certbot inside SWAG (DNS-01).
// Dedicated forms for DuckDNS and Cloudflare, generic form for other providers.

import (
	"fmt"
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
	// the only certbot invocation guard will accept (values never start with '-')
	certRe  = regexp.MustCompile(`^certbot certonly --non-interactive --agree-tos --renew-by-default --email [A-Za-z0-9][A-Za-z0-9._+@-]{2,127} --cert-name [A-Za-z0-9][A-Za-z0-9.-]{0,252} --authenticator dns-[a-z0-9]{2,30} --dns-[a-z0-9]{2,30}-credentials /config/dns-conf/[a-z0-9]{2,30}\.ini --dns-[a-z0-9]{2,30}-propagation-seconds [0-9]{1,3}( --staging)?( -d [A-Za-z0-9*][A-Za-z0-9.*-]{0,99}){1,4} --config-dir /config/etc/letsencrypt --work-dir /tmp/letsencrypt-lib --logs-dir /config/log/letsencrypt$`)
	subRe   = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	domRe   = regexp.MustCompile(`^(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)
	plugRe  = regexp.MustCompile(`^[a-z0-9]{2,30}$`)
	mailRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$`)
	tokDuck = regexp.MustCompile(`^[A-Za-z0-9-]{16,64}$`)
	tokCF   = regexp.MustCompile(`^[A-Za-z0-9_-]{20,80}$`)
	hasDuck = regexp.MustCompile(`(?m)^\s*dns_duckdns_token\s*=\s*\S{8,}`)
	hasCF   = regexp.MustCompile(`(?m)^\s*dns_cloudflare_api_token\s*=\s*\S{8,}`)
	hasAny  = regexp.MustCompile(`(?m)^\s*[^#\s]`)

	jobMu  sync.Mutex
	curJob *job
)

func init() {
	hc.Timeout = 10 * time.Minute // certbot exec may run for minutes (UI and guard)
	okCmd = append(okCmd, certRe)
	tabs = append(tabs, [2]string{"issue", "issue cert"})
	for p, h := range map[string]http.HandlerFunc{"/issue": issueTab, "/issue/do": issueDo, "/issue/job": issueJob} {
		http.HandleFunc(p, guard(h))
	}
}

type issueReq struct {
	Plugin, Email string
	Domains       []string
	Prop          int
	Staging       bool
}

func (q issueReq) name() string { return strings.TrimPrefix(q.Domains[0], "*.") }

func (q issueReq) args() []string {
	a := []string{"certbot", "certonly", "--non-interactive", "--agree-tos", "--renew-by-default", "--email", q.Email,
		"--cert-name", q.name(), "--authenticator", "dns-" + q.Plugin,
		"--dns-" + q.Plugin + "-credentials", "/config/dns-conf/" + q.Plugin + ".ini",
		"--dns-" + q.Plugin + "-propagation-seconds", strconv.Itoa(q.Prop)}
	if q.Staging {
		a = append(a, "--staging")
	}
	for _, d := range q.Domains {
		a = append(a, "-d", d)
	}
	return append(a, "--config-dir", "/config/etc/letsencrypt", "--work-dir", "/tmp/letsencrypt-lib", "--logs-dir", "/config/log/letsencrypt")
}

func credPath(pl string) string { return filepath.Join(root, "dns-conf", pl+".ini") }

func credSaved(pl string, re *regexp.Regexp) bool {
	b, _ := os.ReadFile(credPath(pl))
	return re.Match(b)
}

// write credentials (0600); empty content = keep the saved file if it is valid
func saveCred(pl, content string, re *regexp.Regexp) error {
	if content == "" {
		if credSaved(pl, re) {
			return nil
		}
		return fmt.Errorf("no saved credentials for %s, fill in the credentials field", pl)
	}
	p := credPath(pl)
	os.MkdirAll(filepath.Dir(p), 0755)
	if err := os.WriteFile(p+".tmp", []byte(content), 0600); err != nil {
		return err
	}
	return os.Rename(p+".tmp", p)
}

func saved(pl string, re *regexp.Regexp) string {
	if credSaved(pl, re) {
		return "saved: yes (leave empty to reuse)"
	}
	return "saved: no"
}

const common = `<br>email (Let's Encrypt notices): <input name=email size=30><br>propagation seconds: <input name=prop value=%d size=4><br><input type=checkbox name=staging value=1 checked> staging: test certificate, NOT trusted by browsers. Untick for the real one (run staging first, limits are strict).<br><input type=submit value='issue certificate'></form>`

func issueTab(w http.ResponseWriter, r *http.Request) {
	const plugins = "aliyun azure cloudflare cpanel desec digitalocean dnsimple dnsmadeeasy dnspod domeneshop dynu gandi gehirn godaddy google he hetzner infomaniak inwx ionos linode loopia luadns namecheap netcup njalla nsone ovh porkbun rfc2136 sakuracloud transip vultr"
	var dl strings.Builder
	for _, p := range strings.Fields(plugins) {
		dl.WriteString("<option value=" + p + ">")
	}
	jobLink := ""
	if curJob != nil {
		jobLink = "<a href=/issue/job>[ last / running job ]</a>"
	}
	page(w, "issue", jobLink+fmt.Sprintf(`
<h3>DuckDNS: free wildcard domain</h3>
<ol>
<li>Go to <a href="https://www.duckdns.org" target=_blank>duckdns.org</a> and log in (Google, GitHub, Reddit...).</li>
<li>In the <b>domains</b> field enter the name you want (for example <tt>myhome</tt> gives myhome.duckdns.org) and click <b>add domain</b>. Set its current ip to your server's public IP.</li>
<li>Copy the <b>token</b> shown at the top of the page and paste it below.</li>
<li>Did not manage to copy it in time, or lost it? You can recreate the token on the DuckDNS website: click the three horizontal bars (&#9776;) above the login, then generate a new token. Use the new one everywhere the old one was used.</li>
</ol>
Everything under <tt>*.myhome.duckdns.org</tt> resolves to the same IP automatically, so one wildcard certificate covers all your services.
<form method=post action=/issue/do><input type=hidden name=kind value=duckdns>
domain: <input name=domain size=20>.duckdns.org<br>
token: <input type=password name=token size=50> %s`+common+`
<hr>
<h3>Cloudflare</h3>
<ol>
<li>The domain must be added to Cloudflare and <b>Active</b> (your registrar uses the Cloudflare nameservers).</li>
<li>Open <a href="https://dash.cloudflare.com/profile/api-tokens" target=_blank>My Profile &rarr; API Tokens</a> &rarr; <b>Create Token</b> &rarr; template <b>Edit zone DNS</b>.</li>
<li>Permissions: <tt>Zone / DNS / Edit</tt>. Click <b>Add more</b> and also add <tt>Zone / Zone / Read</tt>.</li>
<li>Zone Resources: <tt>Include / Specific zone</tt> &rarr; choose your domain. Continue &rarr; <b>Create Token</b>.</li>
<li>Copy the token right away: Cloudflare shows it only once (if lost, use <b>Roll</b> on the token page). Paste it below. Do not use the Global API Key.</li>
</ol>
<form method=post action=/issue/do><input type=hidden name=kind value=cloudflare>
domain (apex, e.g. example.com): <input name=domain size=30><br>
<input type=checkbox name=wildcard value=1 checked> also *.domain (wildcard)<br>
API token: <input type=password name=token size=60> %s`+common+`
<hr>
<h3>Other providers</h3>
Provider is the SWAG DNSPLUGIN name. Credentials are written to <tt>/config/dns-conf/&lt;provider&gt;.ini</tt> (SWAG ships a sample file there with the exact keys for each provider, use it as the template). Route53 is not supported by this form.
<form method=post action=/issue/do><input type=hidden name=kind value=other>
provider: <input name=plugin list=plugins size=20><datalist id=plugins>%s</datalist><br>
domains (space or comma, up to 4, e.g. <tt>example.com *.example.com</tt>): <input name=domains size=50><br>
credentials (ini content): <br><textarea name=cred rows=6 cols=70 spellcheck=false placeholder="dns_ovh_endpoint = ovh-eu"></textarea>`+common, saved("duckdns", hasDuck), 60, saved("cloudflare", hasCF), 30, dl.String(), 60))
}

type job struct {
	Q          issueReq
	Start, End time.Time
	Done, OK   bool
	Out        string
}

func startJob(q issueReq) error {
	jobMu.Lock()
	defer jobMu.Unlock()
	if curJob != nil && !curJob.Done {
		return fmt.Errorf("another issuance is still running")
	}
	j := &job{Q: q, Start: time.Now()}
	curJob = j
	go func() {
		out, code := run(q.args()...)
		if code == 0 && isAuto() {
			o2, _ := applyCfg(true)
			out += "\n--- nginx -t + reload ---\n" + o2
		}
		jobMu.Lock()
		j.Out, j.OK, j.Done, j.End = out, code == 0, true, time.Now()
		jobMu.Unlock()
	}()
	return nil
}

func issueDo(w http.ResponseWriter, r *http.Request) {
	fail := func(m string) { result(w, "ERROR: "+m, "", "/issue") }
	r.ParseForm()
	prop, _ := strconv.Atoi(r.FormValue("prop"))
	if prop < 10 || prop > 600 {
		prop = 60
	}
	q := issueReq{Email: strings.TrimSpace(r.FormValue("email")), Prop: prop, Staging: r.FormValue("staging") == "1"}
	if !mailRe.MatchString(q.Email) {
		fail("invalid email")
		return
	}
	tok, dom := strings.TrimSpace(r.FormValue("token")), strings.ToLower(strings.TrimSpace(r.FormValue("domain")))
	var err error
	switch r.FormValue("kind") {
	case "duckdns":
		sub := strings.TrimSuffix(dom, ".duckdns.org")
		if !subRe.MatchString(sub) || (tok != "" && !tokDuck.MatchString(tok)) {
			fail("invalid DuckDNS name or token")
			return
		}
		d := sub + ".duckdns.org"
		q.Plugin, q.Domains = "duckdns", []string{d, "*." + d}
		c := ""
		if tok != "" {
			c = "dns_duckdns_token = " + tok + "\n"
		}
		err = saveCred("duckdns", c, hasDuck)
	case "cloudflare":
		if !domRe.MatchString(dom) || strings.HasPrefix(dom, "*") || (tok != "" && !tokCF.MatchString(tok)) {
			fail("invalid domain or token")
			return
		}
		q.Plugin, q.Domains = "cloudflare", []string{dom}
		if r.FormValue("wildcard") == "1" {
			q.Domains = append(q.Domains, "*."+dom)
		}
		c := ""
		if tok != "" {
			c = "dns_cloudflare_api_token = " + tok + "\n"
		}
		err = saveCred("cloudflare", c, hasCF)
	case "other":
		q.Plugin = strings.ToLower(strings.TrimSpace(r.FormValue("plugin")))
		for _, d := range strings.FieldsFunc(strings.ToLower(r.FormValue("domains")), func(c rune) bool { return c == ' ' || c == ',' || c == '\n' || c == '\t' }) {
			if !domRe.MatchString(d) {
				fail("invalid domain: " + d)
				return
			}
			q.Domains = append(q.Domains, d)
		}
		c := strings.ReplaceAll(strings.TrimSpace(r.FormValue("cred")), "\r\n", "\n")
		if !plugRe.MatchString(q.Plugin) || len(q.Domains) == 0 || len(q.Domains) > 4 || len(c) > 4096 {
			fail("invalid provider or domains")
			return
		}
		if c != "" {
			c += "\n"
		}
		err = saveCred(q.Plugin, c, hasAny)
	default:
		fail("unknown form")
		return
	}
	if err != nil {
		fail(err.Error())
		return
	}
	if !cmdAllowed(q.args()) {
		fail("parameters rejected by the command whitelist")
		return
	}
	if err := startJob(q); err != nil {
		fail(err.Error())
		return
	}
	http.Redirect(w, r, "/issue/job", 303)
}

// does nginx actually serve the new certificate? (ssl.conf -> real file)
func sslCheck(name string) string {
	want, _ := filepath.EvalSymlinks(filepath.Join(le, name, "fullchain.pem"))
	b, _ := os.ReadFile(filepath.Join(base, "ssl.conf"))
	m := regexp.MustCompile(`(?m)^\s*ssl_certificate\s+([^;]+);`).FindStringSubmatch(string(b))
	if m == nil {
		return "ssl.conf has no ssl_certificate line, check it manually."
	}
	got, err := filepath.EvalSymlinks(strings.TrimSpace(m[1]))
	if err == nil && got == want {
		return "nginx is configured to serve this certificate."
	}
	return fmt.Sprintf("<b>nginx does NOT serve this certificate yet.</b> ssl.conf uses %s. Set URL=%s in the SWAG environment (SWAG links its certificate by URL on start) or point ssl_certificate to /config/etc/letsencrypt/live/%s/fullchain.pem.", e(strings.TrimSpace(m[1])), e(name), e(name))
}

func envSnippet(q issueReq) string {
	l := []string{"URL=" + q.name(), "VALIDATION=dns", "DNSPLUGIN=" + q.Plugin, "EMAIL=" + q.Email}
	for _, d := range q.Domains {
		if strings.HasPrefix(d, "*.") {
			l = append(l, "SUBDOMAINS=wildcard")
			break
		}
	}
	if q.Staging {
		l = append(l, "STAGING=true")
	}
	return strings.Join(l, "\n")
}

func issueJob(w http.ResponseWriter, r *http.Request) {
	jobMu.Lock()
	jp := curJob
	var j job
	if jp != nil {
		j = *jp
	}
	jobMu.Unlock()
	if jp == nil {
		http.Redirect(w, r, "/issue", 303)
		return
	}
	var s strings.Builder
	doms := e(strings.Join(j.Q.Domains, " "))
	if !j.Done {
		fmt.Fprintf(&s, "<meta http-equiv=refresh content=3><b>RUNNING</b> %ds (DNS propagation wait is %ds)<br>domains: %s<p>letsencrypt.log (tail):", int(time.Since(j.Start).Seconds()), j.Q.Prop, doms)
		ls, _ := tailLines(filepath.Join(logRoot, "letsencrypt", "letsencrypt.log"), 25, "")
		s.WriteString("<pre>" + e(strings.Join(ls, "\n")) + "</pre>")
	} else {
		st := map[bool]string{true: "SUCCESS", false: "FAILED"}[j.OK]
		fmt.Fprintf(&s, "<b>%s</b> in %ds<br>domains: %s<pre>%s</pre>", st, int(j.End.Sub(j.Start).Seconds()), doms, e(j.Out))
		if j.OK {
			cs, _ := loadCerts()
			for _, c := range cs {
				if c.Name == j.Q.name() {
					fmt.Fprintf(&s, "issuer: %s, expires %s (%d days)<br>", e(c.Issuer), c.NotAfter.Format("2006-01-02"), c.days())
				}
			}
			if j.Q.Staging {
				s.WriteString("<b>This is a STAGING certificate (not trusted). Run again with staging unticked for the real one.</b><br>")
			}
			s.WriteString(sslCheck(j.Q.name()) + "<br>")
			if !isAuto() {
				s.WriteString("<form method=post action=/reload><input type=submit value='nginx -t + reload now'></form>")
			}
			s.WriteString("<h3>keep it in the SWAG environment</h3>so a re-created container issues and renews the same way. Certbot also stored a renewal config in /config/etc/letsencrypt/renewal/.<pre>" + e(envSnippet(j.Q)) + "</pre>")
		}
	}
	s.WriteString("<a href=/issue>[ back ]</a>")
	page(w, "issue", s.String())
}
