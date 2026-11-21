// Linux availability checks and bounded recovery. Standard library only.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Service struct {
	ID, Kind, Target, Expect, Unit, Policy           string
	Dependencies                                     []string
	Timeout, Failures, Cooldown, MaxRestarts, Window int
}
type Result struct {
	Healthy bool
	Message string
}
type ServiceState struct {
	Healthy    bool    `json:"healthy"`
	Failures   int     `json:"failures"`
	Down       bool    `json:"down"`
	Checked    int64   `json:"checked"`
	Message    string  `json:"message"`
	Attempts   []int64 `json:"attempts,omitempty"`
	LastNotice string  `json:"last_notice,omitempty"`
}
type State struct {
	Version  int                      `json:"version"`
	Services map[string]*ServiceState `json:"services"`
}
type Event struct {
	Module         string `json:"module"`
	Host           string `json:"host"`
	Service        string `json:"service"`
	Event          string `json:"event"`
	Timestamp      string `json:"timestamp"`
	Message        string `json:"message"`
	Failures       int    `json:"failures"`
	RecoveryResult string `json:"recovery_result,omitempty"`
}
type Monitor struct {
	Services []Service
	Dir, Log string
	Output   io.Writer
	Now      func() time.Time
	Probe    func(context.Context, Service) Result
	Restart  func(context.Context, Service) error
}

var namePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.@:-]{0,127}$`)

func safePath(p string) error {
	if !filepath.IsAbs(p) || filepath.Clean(p) != p {
		return fmt.Errorf("use a canonical absolute path: %s", p)
	}
	current := string(os.PathSeparator)
	for _, component := range strings.Split(strings.TrimPrefix(p, "/"), "/") {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink refused: %s", current)
		}
	}
	return nil
}
func privateFile(p string) ([]byte, error) {
	if err := safePath(p); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
		return nil, fmt.Errorf("file must be regular, owned by current UID and not group/world writable: %s", p)
	}
	if info.Size() > 1024*1024 {
		return nil, fmt.Errorf("file exceeds 1 MiB: %s", p)
	}
	return io.ReadAll(io.LimitReader(f, 1024*1024+1))
}
func privateDir(p string) error {
	if err := safePath(p); err != nil {
		return err
	}
	if err := os.MkdirAll(p, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(p)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("state directory must be owned by current UID and mode 700: %s", p)
	}
	return nil
}
func atomicWrite(p string, data []byte) error {
	if err := safePath(p); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(p), ".hunter-watch-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(tmp, p); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(p))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
func positive(s string, max int) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > max {
		return 0, fmt.Errorf("expected integer 1..%d, got %q", max, s)
	}
	return n, nil
}
func readConfig(p string) ([]Service, error) {
	b, err := privateFile(p)
	if err != nil {
		return nil, err
	}
	var services []Service
	ids := map[string]int{}
	scanner := bufio.NewScanner(strings.NewReader(string(b)))
	scanner.Buffer(make([]byte, 4096), 16384)
	line := 0
	for scanner.Scan() {
		line++
		raw := strings.TrimSpace(scanner.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		f := strings.Split(raw, "|")
		if len(f) != 12 {
			return nil, fmt.Errorf("config line %d: need 12 pipe-separated fields", line)
		}
		for i := range f {
			f[i] = strings.TrimSpace(f[i])
			if f[i] == "" || strings.ContainsAny(f[i], "\x00\r\n") {
				return nil, fmt.Errorf("config line %d: empty/control field", line)
			}
		}
		s := Service{ID: f[0], Kind: f[1], Target: f[2], Expect: f[3], Unit: f[4], Policy: f[6]}
		if !namePattern.MatchString(s.ID) || (s.Unit != "-" && !namePattern.MatchString(s.Unit)) {
			return nil, fmt.Errorf("line %d: invalid ID or unit", line)
		}
		if _, exists := ids[s.ID]; exists {
			return nil, fmt.Errorf("duplicate service: %s", s.ID)
		}
		if f[5] != "-" {
			s.Dependencies = strings.Split(f[5], ",")
			for _, d := range s.Dependencies {
				if !namePattern.MatchString(d) {
					return nil, fmt.Errorf("invalid dependency: %s", d)
				}
			}
		}
		if s.Policy != "alert" && s.Policy != "auto" {
			return nil, fmt.Errorf("invalid policy: %s", s.Policy)
		}
		if s.Policy == "auto" && s.Unit == "-" {
			return nil, fmt.Errorf("auto recovery requires an explicit unit: %s", s.ID)
		}
		numbers := []*int{&s.Timeout, &s.Failures, &s.Cooldown, &s.MaxRestarts, &s.Window}
		for i, max := range []int{60, 100, 86400, 100, 86400} {
			value, e := positive(f[i+7], max)
			if e != nil {
				return nil, fmt.Errorf("line %d: %w", line, e)
			}
			*numbers[i] = value
		}
		switch s.Kind {
		case "http":
			u, e := url.Parse(s.Target)
			if e != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil {
				return nil, fmt.Errorf("invalid HTTP URL or credentials in URL: %s", s.ID)
			}
			code := strings.SplitN(s.Expect, ":", 2)[0]
			n, e := strconv.Atoi(code)
			if e != nil || n < 100 || n > 599 {
				return nil, fmt.Errorf("invalid HTTP status: %s", s.ID)
			}
		case "tcp":
			if _, _, e := net.SplitHostPort(s.Target); e != nil || s.Expect != "-" {
				return nil, fmt.Errorf("invalid TCP host:port/expect: %s", s.ID)
			}
		case "dns":
			parts := strings.SplitN(s.Target, "/", 2)
			if len(parts) != 2 || parts[1] == "" || net.ParseIP(strings.TrimSuffix(parts[1], ".")) != nil {
				return nil, fmt.Errorf("DNS needs serverIP:port/name: %s", s.ID)
			}
			host, _, e := net.SplitHostPort(parts[0])
			if e != nil || net.ParseIP(host) == nil || (s.Expect != "-" && net.ParseIP(s.Expect) == nil) {
				return nil, fmt.Errorf("invalid DNS server or expected address: %s", s.ID)
			}
		case "unit":
			if !namePattern.MatchString(s.Target) || s.Expect != "-" {
				return nil, fmt.Errorf("invalid unit probe: %s", s.ID)
			}
		case "disk":
			if !filepath.IsAbs(s.Target) {
				return nil, fmt.Errorf("disk path must be absolute: %s", s.ID)
			}
			parts := strings.Split(s.Expect, ":")
			if len(parts) > 2 {
				return nil, fmt.Errorf("invalid disk threshold: %s", s.ID)
			}
			for _, part := range parts {
				if _, e := positive(part, 100); e != nil {
					return nil, e
				}
			}
		case "mysql":
			if !filepath.IsAbs(s.Target) || s.Expect != "1" {
				return nil, fmt.Errorf("mysql needs private defaults file and expect=1: %s", s.ID)
			}
		case "postgres":
			parts := strings.SplitN(s.Target, "@", 2)
			if len(parts) != 2 || !namePattern.MatchString(parts[0]) || !filepath.IsAbs(parts[1]) || s.Expect != "1" {
				return nil, fmt.Errorf("postgres needs serviceName@absoluteServiceFile and expect=1: %s", s.ID)
			}
		default:
			return nil, fmt.Errorf("unsupported check kind: %s", s.Kind)
		}
		ids[s.ID] = len(services)
		services = append(services, s)
		if len(services) > 256 {
			return nil, fmt.Errorf("maximum 256 checks")
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(services) == 0 {
		return nil, fmt.Errorf("no checks configured")
	}
	visiting, done := map[string]bool{}, map[string]bool{}
	var visit func(string) error
	visit = func(id string) error {
		if visiting[id] {
			return fmt.Errorf("dependency cycle at %s", id)
		}
		if done[id] {
			return nil
		}
		index, ok := ids[id]
		if !ok {
			return fmt.Errorf("unknown dependency: %s", id)
		}
		visiting[id] = true
		for _, d := range services[index].Dependencies {
			if e := visit(d); e != nil {
				return e
			}
		}
		visiting[id] = false
		done[id] = true
		return nil
	}
	for _, s := range services {
		if e := visit(s.ID); e != nil {
			return nil, e
		}
	}
	return services, nil
}

func command(ctx context.Context, env []string, program string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, program, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		e := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if e == syscall.ESRCH {
			return os.ErrProcessDone
		}
		return e
	}
	cmd.WaitDelay = time.Second
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/sbin:/usr/local/bin", "LC_ALL=C"}
	cmd.Env = append(cmd.Env, env...)
	var output boundedBuffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	err := cmd.Run()
	return strings.TrimSpace(output.String()), err
}

type boundedBuffer struct {
	data []byte
	mu   sync.Mutex
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	if len(b.data) < 8192 {
		left := 8192 - len(b.data)
		if len(p) > left {
			p = p[:left]
		}
		b.data = append(b.data, p...)
	}
	return n, nil
}
func (b *boundedBuffer) String() string { return string(b.data) }
func sensitive(unit string) bool {
	name := strings.ToLower(strings.Split(unit, ".")[0])
	for _, prefix := range []string{"ssh", "network", "systemd-network", "systemd-resolved", "firewall", "ufw", "iptables", "nftables", "pam", "sssd", "winbind", "mysql", "mariadb", "postgres", "wazuh", "auditd"} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}
func nativeService(ctx context.Context, s Service, action string) error {
	unit := s.Unit
	if action == "status" {
		unit = s.Target
	}
	if !namePattern.MatchString(unit) {
		return fmt.Errorf("invalid service name")
	}
	if action == "restart" && (os.Geteuid() != 0 || sensitive(unit)) {
		return fmt.Errorf("recovery requires root and refuses sensitive units")
	}
	if info, e := os.Stat("/run/systemd/system"); e == nil && info.IsDir() {
		if action == "status" {
			_, e = command(ctx, nil, "systemctl", "is-active", "--quiet", unit)
		} else {
			_, e = command(ctx, nil, "systemctl", "restart", unit)
		}
		return e
	}
	if _, e := exec.LookPath("rc-service"); e == nil {
		_, e = command(ctx, nil, "rc-service", strings.TrimSuffix(unit, ".service"), action)
		return e
	}
	_, e := command(ctx, nil, "service", strings.TrimSuffix(unit, ".service"), action)
	return e
}
func probe(ctx context.Context, s Service) Result {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(s.Timeout)*time.Second)
	defer cancel()
	bad := func(message string) Result { return Result{Message: message} }
	switch s.Kind {
	case "http":
		transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: time.Duration(s.Timeout) * time.Second}).DialContext, TLSHandshakeTimeout: time.Duration(s.Timeout) * time.Second, DisableKeepAlives: true}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		req, e := http.NewRequestWithContext(ctx, "GET", s.Target, nil)
		if e != nil {
			return bad("invalid request")
		}
		resp, e := client.Do(req)
		if e != nil {
			var ue *url.Error
			if errors.As(e, &ue) {
				e = ue.Err
			}
			return bad("HTTP request failed: " + e.Error())
		}
		defer resp.Body.Close()
		parts := strings.SplitN(s.Expect, ":", 2)
		code, _ := strconv.Atoi(parts[0])
		if resp.StatusCode != code {
			return bad(fmt.Sprintf("HTTP %d; expected %d", resp.StatusCode, code))
		}
		if len(parts) == 2 {
			body, e := io.ReadAll(io.LimitReader(resp.Body, 65537))
			if e != nil {
				return bad("HTTP body read failed")
			}
			if len(body) > 65536 {
				return bad("HTTP body exceeds 64 KiB match limit")
			}
			if !strings.Contains(string(body), parts[1]) {
				return bad("HTTP expected body text missing")
			}
		}
	case "tcp":
		c, e := (&net.Dialer{}).DialContext(ctx, "tcp", s.Target)
		if e != nil {
			return bad("TCP connect failed: " + e.Error())
		}
		c.Close()
	case "dns":
		parts := strings.SplitN(s.Target, "/", 2)
		resolver := &net.Resolver{PreferGo: true, Dial: func(c context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(c, network, parts[0])
		}}
		addresses, e := resolver.LookupIPAddr(ctx, strings.TrimSuffix(parts[1], ".")+".")
		if e != nil {
			return bad("DNS query failed: " + e.Error())
		}
		if len(addresses) == 0 {
			return bad("DNS returned no addresses")
		}
		if s.Expect != "-" {
			found := false
			expected := net.ParseIP(s.Expect)
			for _, a := range addresses {
				if a.IP.Equal(expected) {
					found = true
				}
			}
			if !found {
				return bad("DNS expected address missing")
			}
		}
	case "unit":
		if e := nativeService(ctx, s, "status"); e != nil {
			return bad("service not active: " + e.Error())
		}
	case "disk":
		var st syscall.Statfs_t
		if e := syscall.Statfs(s.Target, &st); e != nil {
			return bad("filesystem query failed: " + e.Error())
		}
		if st.Blocks == 0 {
			return bad("filesystem reports no blocks")
		}
		parts := strings.Split(s.Expect, ":")
		min, _ := strconv.Atoi(parts[0])
		free := float64(st.Bavail) * 100 / float64(st.Blocks)
		if free < float64(min) {
			return bad(fmt.Sprintf("disk free %.1f%% below %d%%", free, min))
		}
		if len(parts) == 2 && st.Files > 0 {
			min, _ = strconv.Atoi(parts[1])
			free = float64(st.Ffree) * 100 / float64(st.Files)
			if free < float64(min) {
				return bad(fmt.Sprintf("inodes free %.1f%% below %d%%", free, min))
			}
		}
	case "mysql":
		b, e := privateFile(s.Target)
		if e != nil {
			return bad("database defaults file unavailable: " + e.Error())
		}
		_ = b
		info, e := os.Stat(s.Target)
		if e != nil || info.Mode().Perm()&0077 != 0 {
			return bad("database defaults file must be mode 600")
		}
		client := "mariadb"
		if _, e := exec.LookPath(client); e != nil {
			client = "mysql"
		}
		out, e := command(ctx, nil, client, "--defaults-extra-file="+s.Target, "--batch", "--skip-column-names", "--connect-timeout="+strconv.Itoa(s.Timeout), "--execute=SELECT 1")
		if e != nil {
			return bad("database SELECT 1 failed: " + e.Error())
		}
		if out != "1" {
			return bad("database unexpected SELECT 1 result")
		}
	case "postgres":
		parts := strings.SplitN(s.Target, "@", 2)
		if _, e := privateFile(parts[1]); e != nil {
			return bad("PostgreSQL service file unavailable: " + e.Error())
		}
		info, e := os.Stat(parts[1])
		if e != nil || info.Mode().Perm()&0077 != 0 {
			return bad("PostgreSQL service file must be mode 600")
		}
		out, e := command(ctx, []string{"PGSERVICEFILE=" + parts[1], "PGCONNECT_TIMEOUT=" + strconv.Itoa(s.Timeout)}, "psql", "--no-psqlrc", "--no-password", "--tuples-only", "--no-align", "--dbname=service="+parts[0], "--command=SELECT 1")
		if e != nil {
			return bad("database SELECT 1 failed: " + e.Error())
		}
		if out != "1" {
			return bad("database unexpected SELECT 1 result")
		}
	default:
		return bad("unsupported check")
	}
	return Result{Healthy: true, Message: "check passed"}
}

func (m *Monitor) lock() (*os.File, error) {
	if e := privateDir(m.Dir); e != nil {
		return nil, e
	}
	p := filepath.Join(m.Dir, "lock")
	if e := safePath(p); e != nil {
		return nil, e
	}
	f, e := os.OpenFile(p, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return nil, e
	}
	info, e := f.Stat()
	if e != nil {
		f.Close()
		return nil, e
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Geteuid() || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		f.Close()
		return nil, fmt.Errorf("unsafe lock file")
	}
	if e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		f.Close()
		return nil, fmt.Errorf("another watchdog operation holds state lock: %w", e)
	}
	return f, nil
}
func (m *Monitor) load() (*State, error) {
	p := filepath.Join(m.Dir, "state.json")
	b, e := privateFile(p)
	if os.IsNotExist(e) {
		return &State{Version: 1, Services: map[string]*ServiceState{}}, nil
	}
	if e != nil {
		return nil, e
	}
	var state State
	if e = json.Unmarshal(b, &state); e != nil || state.Version != 1 || state.Services == nil {
		return nil, fmt.Errorf("invalid state; recovery refused (preserve state and inspect)")
	}
	for id, s := range state.Services {
		if !namePattern.MatchString(id) || s == nil || s.Failures < 0 || s.Failures > 1000000 || s.Checked < 0 || len(s.Attempts) > 10000 {
			return nil, fmt.Errorf("invalid persisted service state")
		}
		var previous int64
		for _, attempt := range s.Attempts {
			if attempt < 1 || attempt < previous {
				return nil, fmt.Errorf("invalid persisted recovery history")
			}
			previous = attempt
		}
	}
	return &state, nil
}
func (m *Monitor) save(state *State) error {
	b, e := json.MarshalIndent(state, "", "  ")
	if e != nil {
		return e
	}
	return atomicWrite(filepath.Join(m.Dir, "state.json"), append(b, '\n'))
}
func (m *Monitor) owner() (string, error) {
	b, e := privateFile(filepath.Join(m.Dir, "recovery-owner"))
	if os.IsNotExist(e) {
		return "", nil
	}
	if e != nil {
		return "", e
	}
	owner := strings.TrimSpace(string(b))
	if owner != "local" && owner != "wazuh" {
		return "", fmt.Errorf("invalid recovery owner; refusing recovery")
	}
	return owner, nil
}
func (m *Monitor) emit(s Service, state *ServiceState, event, message, result string) error {
	host, _ := os.Hostname()
	entry := Event{Module: "hunter_watchdog", Host: host, Service: s.ID, Event: event, Timestamp: m.Now().UTC().Format(time.RFC3339), Message: message, Failures: state.Failures, RecoveryResult: result}
	b, e := json.Marshal(entry)
	if e != nil {
		return e
	}
	b = append(b, '\n')
	if m.Log != "" {
		if e = safePath(m.Log); e != nil {
			return e
		}
		if info, err := os.Lstat(m.Log); err == nil {
			st, ok := info.Sys().(*syscall.Stat_t)
			if !ok || int(st.Uid) != os.Geteuid() || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
				return fmt.Errorf("unsafe log file")
			}
			if info.Size() > 5*1024*1024 {
				for i := 4; i >= 1; i-- {
					old := fmt.Sprintf("%s.%d", m.Log, i)
					if e = safePath(old); e != nil {
						return e
					}
					if i == 4 {
						if e = os.Remove(old); e != nil && !os.IsNotExist(e) {
							return e
						}
					} else {
						if e = os.Rename(old, fmt.Sprintf("%s.%d", m.Log, i+1)); e != nil && !os.IsNotExist(e) {
							return e
						}
					}
				}
				if e = os.Rename(m.Log, m.Log+".1"); e != nil {
					return e
				}
			}
		} else if !os.IsNotExist(err) {
			return err
		}
		f, e := os.OpenFile(m.Log, os.O_WRONLY|os.O_CREATE|os.O_APPEND|syscall.O_NOFOLLOW, 0600)
		if e != nil {
			return e
		}
		_, e = f.Write(b)
		closeErr := f.Close()
		if e != nil {
			return e
		}
		if closeErr != nil {
			return closeErr
		}
	}
	if m.Output != nil {
		_, e = m.Output.Write(b)
	}
	return e
}
func (m *Monitor) probeAll(ctx context.Context) map[string]Result {
	results := map[string]Result{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	slots := make(chan struct{}, 8)
	for _, s := range m.Services {
		wg.Add(1)
		go func(s Service) {
			defer wg.Done()
			select {
			case slots <- struct{}{}:
			case <-ctx.Done():
				mu.Lock()
				results[s.ID] = Result{Message: "check cancelled"}
				mu.Unlock()
				return
			}
			r := m.Probe(ctx, s)
			<-slots
			mu.Lock()
			results[s.ID] = r
			mu.Unlock()
		}(s)
	}
	wg.Wait()
	return results
}
func (m *Monitor) depsHealthy(s Service, results map[string]Result) (bool, string) {
	byID := make(map[string]Service, len(m.Services))
	for _, configured := range m.Services {
		byID[configured.ID] = configured
	}
	visited := map[string]bool{}
	var visit func(Service) (bool, string)
	visit = func(current Service) (bool, string) {
		for _, id := range current.Dependencies {
			if visited[id] {
				continue
			}
			visited[id] = true
			r, observed := results[id]
			dependency, configured := byID[id]
			if !observed || !configured || !r.Healthy {
				return false, id
			}
			if ok, failed := visit(dependency); !ok {
				return false, failed
			}
		}
		return true, ""
	}
	return visit(s)
}
func (m *Monitor) recover(ctx context.Context, s Service, st *ServiceState, state *State, results map[string]Result) error {
	now := m.Now().Unix()
	recent := []int64{}
	for _, t := range st.Attempts {
		if t > now-int64(s.Window) {
			recent = append(recent, t)
		}
	}
	st.Attempts = recent
	reason := ""
	if s.Policy != "auto" || s.Unit == "-" {
		reason = "service is alert-only"
	} else if sensitive(s.Unit) {
		reason = "sensitive unit is alert-only"
	} else if ok, dep := m.depsHealthy(s, results); !ok {
		reason = "dependency unavailable: " + dep
	} else if len(recent) >= s.MaxRestarts {
		reason = "rolling restart limit reached"
	} else if len(recent) > 0 && now-recent[len(recent)-1] < int64(s.Cooldown) {
		reason = "recovery cooldown active"
	}
	if reason != "" {
		event := "RECOVERY_SUPPRESSED"
		if strings.HasPrefix(reason, "dependency") {
			event = "DEPENDENCY_DOWN"
		}
		if strings.HasPrefix(reason, "rolling") {
			event = "RECOVERY_EXHAUSTED"
		}
		if st.LastNotice != reason {
			st.LastNotice = reason
			return m.emit(s, st, event, reason, "not attempted")
		}
		return nil
	}
	// Counters reach durable state before a privileged action can start.
	st.Attempts = append(st.Attempts, now)
	st.LastNotice = ""
	if e := m.save(state); e != nil {
		return e
	}
	if e := m.emit(s, st, "RECOVERY_ATTEMPT", "restarting allowlisted service", "attempting"); e != nil {
		return e
	}
	rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	e := m.Restart(rctx, s)
	cancel()
	if e != nil {
		st.LastNotice = "restart command failed"
		return m.emit(s, st, "RECOVERY_FAILED", "restart command failed: "+e.Error(), "failed")
	}
	// A successful service-manager command is not proof of application health.
	// Give a newly started application one probe timeout to become ready.
	postCtx, postCancel := context.WithTimeout(ctx, time.Duration(s.Timeout)*time.Second)
	defer postCancel()
	var r Result
readiness:
	for {
		r = m.Probe(postCtx, s)
		if r.Healthy {
			break
		}
		select {
		case <-postCtx.Done():
			break readiness
		case <-time.After(250 * time.Millisecond):
		}
	}
	st.Healthy = r.Healthy
	st.Message = r.Message
	st.Checked = m.Now().Unix()
	if r.Healthy {
		st.Failures = 0
		st.Down = false
		st.LastNotice = ""
		return m.emit(s, st, "RECOVERED", "service passed its check after recovery", "healthy")
	}
	return m.emit(s, st, "RECOVERY_FAILED", "service still fails its functional check", "unhealthy")
}
func (m *Monitor) Tick(ctx context.Context) error {
	lock, e := m.lock()
	if e != nil {
		return e
	}
	defer lock.Close()
	state, e := m.load()
	if e != nil {
		return e
	}
	owner, e := m.owner()
	if e != nil {
		return e
	}
	results := m.probeAll(ctx)
	for _, s := range m.Services {
		st, exists := state.Services[s.ID]
		if !exists {
			st = &ServiceState{}
			state.Services[s.ID] = st
		}
		r := results[s.ID]
		wasDown := st.Down
		st.Healthy = r.Healthy
		st.Message = r.Message
		st.Checked = m.Now().Unix()
		if r.Healthy {
			st.Failures = 0
			st.Down = false
			st.LastNotice = ""
			event := "OK"
			if !exists {
				event = "UP"
			} else if wasDown {
				event = "RECOVERED"
			}
			if e = m.emit(s, st, event, r.Message, ""); e != nil {
				return e
			}
			continue
		}
		if st.Failures < 1000000 {
			st.Failures++
		}
		event := "PENDING"
		if st.Failures >= s.Failures {
			st.Down = true
			if !wasDown {
				event = "DOWN"
			}
		}
		if e = m.emit(s, st, event, r.Message, ""); e != nil {
			return e
		}
		if st.Down && owner == "local" {
			if e = m.recover(ctx, s, st, state, results); e != nil {
				return e
			}
		}
	}
	return m.save(state)
}
func (m *Monitor) Respond(ctx context.Context, input io.Reader) error {
	var request struct {
		Command    string `json:"command"`
		Parameters struct {
			Alert struct {
				Rule struct {
					ID string `json:"id"`
				} `json:"rule"`
				Data struct{ Module, Service, Event string } `json:"data"`
			} `json:"alert"`
		} `json:"parameters"`
	}
	if e := json.NewDecoder(io.LimitReader(input, 65536)).Decode(&request); e != nil {
		return fmt.Errorf("invalid Wazuh request: %w", e)
	}
	if request.Command == "delete" {
		return nil
	}
	alert := request.Parameters.Alert
	if request.Command != "add" || alert.Rule.ID != "100710" || alert.Data.Module != "hunter_watchdog" || alert.Data.Event != "DOWN" {
		return fmt.Errorf("Wazuh request is not an allowed DOWN trigger")
	}
	var selected *Service
	for i := range m.Services {
		if m.Services[i].ID == alert.Data.Service {
			selected = &m.Services[i]
			break
		}
	}
	if selected == nil {
		return fmt.Errorf("service is not configured")
	}
	lock, e := m.lock()
	if e != nil {
		return e
	}
	defer lock.Close()
	owner, e := m.owner()
	if e != nil {
		return e
	}
	if owner != "wazuh" {
		return fmt.Errorf("Wazuh recovery is not enabled")
	}
	state, e := m.load()
	if e != nil {
		return e
	}
	st := state.Services[selected.ID]
	if st == nil || !st.Down || st.Failures < selected.Failures {
		return fmt.Errorf("service has no confirmed local failure")
	}
	results := m.probeAll(ctx)
	if results[selected.ID].Healthy {
		return m.emit(*selected, st, "RECOVERY_SUPPRESSED", "fresh check is healthy; no restart", "not needed")
	}
	if e = m.recover(ctx, *selected, st, state, results); e != nil {
		return e
	}
	return m.save(state)
}

func (m *Monitor) tickReported(ctx context.Context) error {
	if err := m.Tick(ctx); err != nil {
		// Keep operational failures visible to log collectors when the event log
		// itself is available. Never change recovery state to work around an error.
		if logErr := m.emit(Service{ID: "watchdog"}, &ServiceState{}, "CHECK_ERROR", err.Error(), "not attempted"); logErr != nil {
			return fmt.Errorf("%w; could not log CHECK_ERROR: %v", err, logErr)
		}
		return err
	}
	return nil
}

func run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: hunter-watch validate|check|watch|status|enable-recovery|disable-recovery|respond [--config PATH --state-dir PATH --log PATH --interval N --owner local|wazuh]")
	}
	action := args[0]
	flags := flag.NewFlagSet("hunter-watch", flag.ContinueOnError)
	config := flags.String("config", "/etc/hunter-watch/services.conf", "private check manifest")
	base := flags.String("state-dir", "/.x86", "hunter state store")
	log := flags.String("log", "/var/log/hunter-watch.jsonl", "JSONL log; empty disables file logging")
	interval := flags.Int("interval", 30, "seconds between check cycles")
	owner := flags.String("owner", "local", "local or wazuh")
	if e := flags.Parse(args[1:]); e != nil {
		return e
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected positional argument")
	}
	if *interval < 1 || *interval > 86400 {
		return fmt.Errorf("interval must be 1..86400 seconds")
	}
	m := Monitor{Dir: filepath.Join(*base, "watchdog"), Log: *log, Output: os.Stdout, Now: time.Now, Probe: probe, Restart: func(ctx context.Context, s Service) error { return nativeService(ctx, s, "restart") }}
	if e := safePath(*base); e != nil {
		return e
	}
	if action == "status" {
		state, e := m.load()
		if e != nil {
			return e
		}
		mode, e := m.owner()
		if e != nil {
			return e
		}
		if mode == "" {
			mode = "monitor-only"
		}
		out := struct {
			Mode  string `json:"recovery_mode"`
			State *State `json:"state"`
		}{mode, state}
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(out)
	}
	if action == "disable-recovery" {
		if os.Geteuid() != 0 {
			return fmt.Errorf("root required to change recovery policy")
		}
		lock, e := m.lock()
		if e != nil {
			return e
		}
		defer lock.Close()
		p := filepath.Join(m.Dir, "recovery-owner")
		if e = safePath(p); e != nil {
			return e
		}
		e = os.Remove(p)
		if os.IsNotExist(e) {
			e = nil
		}
		return e
	}
	services, e := readConfig(*config)
	if e != nil {
		return e
	}
	m.Services = services
	if action == "validate" {
		fmt.Printf("Valid manifest: %d checks\n", len(services))
		return nil
	}
	if action == "enable-recovery" {
		if os.Geteuid() != 0 {
			return fmt.Errorf("root required to enable recovery")
		}
		if *owner != "local" && *owner != "wazuh" {
			return fmt.Errorf("owner must be local or wazuh")
		}
		lock, e := m.lock()
		if e != nil {
			return e
		}
		defer lock.Close()
		if _, e = m.load(); e != nil {
			return e
		}
		return atomicWrite(filepath.Join(m.Dir, "recovery-owner"), []byte(*owner+"\n"))
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	switch action {
	case "check":
		return m.tickReported(ctx)
	case "respond":
		return m.Respond(ctx, os.Stdin)
	case "watch":
		if e = m.tickReported(ctx); e != nil {
			return e
		}
		ticker := time.NewTicker(time.Duration(*interval) * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
				if e = m.tickReported(ctx); e != nil {
					fmt.Fprintln(os.Stderr, "hunter-watch:", e)
				}
			}
		}
	default:
		return fmt.Errorf("unknown command: %s", action)
	}
}
func main() {
	// Resolve helper commands through a fixed system path, never a caller's PATH.
	os.Setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/sbin:/usr/local/bin")
	if e := run(os.Args[1:]); e != nil {
		fmt.Fprintln(os.Stderr, "hunter-watch:", e)
		os.Exit(1)
	}
}
