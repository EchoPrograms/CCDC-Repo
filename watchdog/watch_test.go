package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writePrivate(t *testing.T, p, text string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
}
func fixture(t *testing.T) (*Monitor, *bytes.Buffer, *time.Time, *bool, *int) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "state")
	if err := privateDir(dir); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1700000000, 0)
	healthy := false
	restarts := 0
	output := &bytes.Buffer{}
	m := &Monitor{
		Services: []Service{{ID: "web", Kind: "http", Unit: "apache2", Policy: "auto", Timeout: 1, Failures: 3, Cooldown: 300, MaxRestarts: 2, Window: 900}},
		Dir:      dir, Output: output, Now: func() time.Time { return now },
		Probe:   func(context.Context, Service) Result { return Result{Healthy: healthy, Message: "fixture health"} },
		Restart: func(context.Context, Service) error { restarts++; return errors.New("fixture restart failed") },
	}
	return m, output, &now, &healthy, &restarts
}
func tick(t *testing.T, m *Monitor) {
	t.Helper()
	if err := m.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
}
func events(t *testing.T, output *bytes.Buffer) []Event {
	t.Helper()
	var all []Event
	d := json.NewDecoder(bytes.NewReader(output.Bytes()))
	for {
		var e Event
		if err := d.Decode(&e); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		all = append(all, e)
	}
	return all
}
func count(t *testing.T, output *bytes.Buffer, kind string) int {
	t.Helper()
	n := 0
	for _, e := range events(t, output) {
		if e.Event == kind {
			n++
		}
	}
	return n
}

func TestManifestRejectsInvalidOrUnsafeInput(t *testing.T) {
	valid := "web|http|http://127.0.0.1/|200:ready|apache2|-|auto|5|3|300|2|900\n"
	tests := map[string]string{
		"empty": "# no checks\n", "missing field": "web|http\n",
		"duplicate":          valid + valid,
		"credentials":        strings.Replace(valid, "http://127.0.0.1/", "http://user:secret@localhost/", 1),
		"command unit":       strings.Replace(valid, "apache2", "apache2;id", 1),
		"no recovery unit":   strings.Replace(valid, "apache2", "-", 1),
		"zero timeout":       strings.Replace(valid, "|5|3|", "|0|3|", 1),
		"missing dependency": strings.Replace(valid, "apache2|-", "apache2|db", 1),
		"cycle":              strings.Replace(valid, "apache2|-", "apache2|db", 1) + "db|tcp|127.0.0.1:3306|-|-|web|alert|5|3|300|2|900\n",
		"DNS literal bypass": "dns|dns|127.0.0.1:53/192.0.2.10|192.0.2.10|-|-|alert|5|3|300|2|900\n",
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "config")
			writePrivate(t, p, body)
			if _, err := readConfig(p); err == nil {
				t.Fatal("accepted invalid manifest")
			}
		})
	}
	p := filepath.Join(t.TempDir(), "config")
	writePrivate(t, p, valid)
	if _, err := readConfig(p); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0666); err != nil {
		t.Fatal(err)
	}
	if _, err := readConfig(p); err == nil {
		t.Fatal("accepted writable configuration")
	}
	if err := os.Chmod(p, 0600); err != nil {
		t.Fatal(err)
	}
	link := p + "-link"
	if err := os.Symlink(p, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readConfig(link); err == nil {
		t.Fatal("accepted symlink")
	}
}

func TestMonitorOnlyThresholdAndTransitionsPersist(t *testing.T) {
	m, output, _, healthy, restarts := fixture(t)
	tick(t, m)
	tick(t, m)
	if count(t, output, "DOWN") != 0 {
		t.Fatal("DOWN before threshold")
	}
	// A new process must inherit the failure count, not start over.
	next := *m
	tick(t, &next)
	tick(t, &next)
	if count(t, output, "DOWN") != 1 || *restarts != 0 {
		t.Fatal("monitor-only triggered recovery or repeated DOWN")
	}
	*healthy = true
	tick(t, &next)
	tick(t, &next)
	if count(t, output, "RECOVERED") != 1 || count(t, output, "OK") != 1 {
		t.Fatal("missing recovery transition or healthy sample")
	}
	st, err := next.load()
	if err != nil || st.Services["web"].Down || st.Services["web"].Failures != 0 {
		t.Fatalf("bad persisted recovery state: %v %v", st, err)
	}
}

func TestLocalRecoveryCooldownBudgetAndExpiry(t *testing.T) {
	m, output, now, _, restarts := fixture(t)
	writePrivate(t, filepath.Join(m.Dir, "recovery-owner"), "local\n")
	for i := 0; i < 3; i++ {
		tick(t, m)
	}
	if *restarts != 1 {
		t.Fatal("first attempt missing")
	}
	next := *m
	*now = now.Add(299 * time.Second)
	tick(t, &next)
	if *restarts != 1 {
		t.Fatal("cooldown bypassed across process restart")
	}
	*now = now.Add(time.Second)
	tick(t, &next)
	if *restarts != 2 {
		t.Fatal("second attempt missing after cooldown")
	}
	*now = now.Add(300 * time.Second)
	tick(t, &next)
	if *restarts != 2 || count(t, output, "RECOVERY_EXHAUSTED") != 1 {
		t.Fatal("rolling cap not enforced")
	}
	*now = now.Add(301 * time.Second)
	tick(t, &next)
	if *restarts != 3 {
		t.Fatal("rolling budget did not expire")
	}
}

func TestRecoveryRequiresFunctionalSuccess(t *testing.T) {
	m, output, _, healthy, restarts := fixture(t)
	m.Services[0].Failures = 1
	writePrivate(t, filepath.Join(m.Dir, "recovery-owner"), "local\n")
	m.Restart = func(context.Context, Service) error { *restarts++; return nil }
	tick(t, m)
	if count(t, output, "RECOVERED") != 0 || count(t, output, "RECOVERY_FAILED") != 1 {
		t.Fatal("successful restart command incorrectly marked healthy")
	}
	// A real successful repair changes the health probe too.
	m.Restart = func(context.Context, Service) error { *healthy = true; return nil }
	st, _ := m.load()
	st.Services["web"].Attempts = nil
	if err := m.save(st); err != nil {
		t.Fatal(err)
	}
	tick(t, m)
	if count(t, output, "RECOVERED") != 1 {
		t.Fatal("functional recovery missing")
	}
}

func TestTransitiveDependenciesAndSensitiveUnits(t *testing.T) {
	m, output, _, _, restarts := fixture(t)
	m.Services[0].Failures = 1
	m.Services[0].Dependencies = []string{"api"}
	m.Services = append(m.Services, Service{ID: "api", Dependencies: []string{"db"}, Policy: "alert", Failures: 1}, Service{ID: "db", Policy: "alert", Failures: 1})
	m.Probe = func(_ context.Context, s Service) Result { return Result{Healthy: s.ID == "api"} }
	writePrivate(t, filepath.Join(m.Dir, "recovery-owner"), "local\n")
	tick(t, m)
	if *restarts != 0 || count(t, output, "DEPENDENCY_DOWN") == 0 {
		t.Fatal("failed transitive dependency did not block restart")
	}
	for _, unit := range []string{"sshd", "networking", "nftables", "sssd", "mysql", "postgresql@14", "wazuh-agent", "auditd"} {
		t.Run(unit, func(t *testing.T) {
			m, _, _, _, restarts := fixture(t)
			m.Services[0].Failures = 1
			m.Services[0].Unit = unit
			writePrivate(t, filepath.Join(m.Dir, "recovery-owner"), "local\n")
			tick(t, m)
			if *restarts != 0 {
				t.Fatal("sensitive unit restarted")
			}
		})
	}
}

func TestCorruptStateLogAndLockFailClosed(t *testing.T) {
	for name, state := range map[string]string{
		"malformed": "{", "version": `{"version":2,"services":{}}`,
		"negative history":  `{"version":1,"services":{"web":{"attempts":[-1]}}}`,
		"unordered history": `{"version":1,"services":{"web":{"attempts":[9,1]}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			m, _, _, _, restarts := fixture(t)
			writePrivate(t, filepath.Join(m.Dir, "recovery-owner"), "local\n")
			writePrivate(t, filepath.Join(m.Dir, "state.json"), state)
			if err := m.Tick(context.Background()); err == nil || *restarts != 0 {
				t.Fatal("corrupt state not refused")
			}
		})
	}
	m, _, _, _, restarts := fixture(t)
	m.Services[0].Failures = 1
	writePrivate(t, filepath.Join(m.Dir, "recovery-owner"), "local\n")
	m.Log = filepath.Join(m.Dir, "missing", "events.jsonl")
	if err := m.Tick(context.Background()); err == nil || *restarts != 0 {
		t.Fatal("recovered without log")
	}
	m.Log = ""
	lock, err := m.lock()
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Tick(context.Background()); err == nil {
		t.Fatal("concurrent tick acquired lock")
	}
	lock.Close()
	tick(t, m)
}

func arRequest(module, service, event, rule string) string {
	return fmt.Sprintf(`{"command":"add","parameters":{"alert":{"rule":{"id":%q},"data":{"module":%q,"service":%q,"event":%q}}}}`, rule, module, service, event)
}
func TestWazuhResponseAllowlistFreshnessAndSharedBudget(t *testing.T) {
	m, _, now, healthy, restarts := fixture(t)
	m.Services[0].Failures = 1
	tick(t, m)
	writePrivate(t, filepath.Join(m.Dir, "recovery-owner"), "wazuh\n")
	request := arRequest("hunter_watchdog", "web", "DOWN", "100710")
	for _, bad := range []string{
		arRequest("other", "web", "DOWN", "100710"), arRequest("hunter_watchdog", "unknown", "DOWN", "100710"),
		arRequest("hunter_watchdog", "web", "OK", "100710"), arRequest("hunter_watchdog", "web", "DOWN", "1"),
	} {
		if err := m.Respond(context.Background(), strings.NewReader(bad)); err == nil {
			t.Fatal("untrusted AR accepted")
		}
	}
	*healthy = true
	if err := m.Respond(context.Background(), strings.NewReader(request)); err != nil {
		t.Fatal(err)
	}
	if *restarts != 0 {
		t.Fatal("stale DOWN restarted healthy service")
	}
	*healthy = false
	if err := m.Respond(context.Background(), strings.NewReader(request)); err != nil {
		t.Fatal(err)
	}
	if err := m.Respond(context.Background(), strings.NewReader(request)); err != nil {
		t.Fatal(err)
	}
	if *restarts != 1 {
		t.Fatal("AR cooldown bypassed")
	}
	*now = now.Add(300 * time.Second)
	if err := m.Respond(context.Background(), strings.NewReader(request)); err != nil {
		t.Fatal(err)
	}
	writePrivate(t, filepath.Join(m.Dir, "recovery-owner"), "local\n")
	if err := m.Respond(context.Background(), strings.NewReader(request)); err == nil {
		t.Fatal("local and AR both own recovery")
	}
	*now = now.Add(300 * time.Second)
	tick(t, m)
	if *restarts != 2 {
		t.Fatal("owner change reset persisted budget")
	}
	if err := m.Respond(context.Background(), strings.NewReader(`{"command":"delete"}`)); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPAndTCPFunctionalProbes(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("sandbox cannot bind TCP; run in VM: %v", err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ready":
			io.WriteString(w, "database ready")
		case "/redirect":
			http.Redirect(w, r, "/ready", http.StatusFound)
		case "/slow":
			select {
			case <-r.Context().Done():
			case <-time.After(3 * time.Second):
			}
		default:
			http.Error(w, "broken", 503)
		}
	})}
	go server.Serve(listener)
	defer server.Close()
	base := "http://" + listener.Addr().String()
	for _, c := range []struct {
		path, expect string
		healthy      bool
	}{
		{"/ready", "200:database ready", true}, {"/ready", "200:absent", false},
		{"/broken", "200", false}, {"/redirect", "200", false}, {"/slow", "200", false},
	} {
		r := probe(context.Background(), Service{Kind: "http", Target: base + c.path, Expect: c.expect, Timeout: 1})
		if r.Healthy != c.healthy {
			t.Errorf("%s %s: %+v", c.path, c.expect, r)
		}
	}
	if r := probe(context.Background(), Service{Kind: "tcp", Target: listener.Addr().String(), Timeout: 1}); !r.Healthy {
		t.Fatal(r)
	}
}

func TestCommandTimeoutKillsProcessGroup(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := command(ctx, nil, "/bin/sh", "-c", "sleep 20 & wait")
	if err == nil || time.Since(start) > 3*time.Second {
		t.Fatalf("timeout failed: %v, elapsed %s", err, time.Since(start))
	}
}

func TestDNSUsesSelectedServerAndExpectedAnswer(t *testing.T) {
	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("sandbox cannot bind UDP; run in VM: %v", err)
	}
	defer server.Close()
	go func() {
		buffer := make([]byte, 1500)
		for {
			n, addr, err := server.ReadFrom(buffer)
			if err != nil {
				return
			}
			if n < 17 {
				continue
			}
			end := 12
			for end < n && buffer[end] > 0 {
				end += 1 + int(buffer[end])
			}
			end++
			if end+4 > n {
				continue
			}
			isA := buffer[end] == 0 && buffer[end+1] == 1
			end += 4
			response := make([]byte, 12)
			copy(response[:2], buffer[:2])
			response[2], response[3], response[5] = 0x81, 0x80, 1
			if isA {
				response[7] = 1
			}
			response = append(response, buffer[12:end]...)
			if isA {
				response = append(response, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 10)
			}
			server.WriteTo(response, addr)
		}
	}()
	s := Service{Kind: "dns", Target: server.LocalAddr().String() + "/watchdog.invalid", Expect: "192.0.2.10", Timeout: 2}
	if r := probe(context.Background(), s); !r.Healthy {
		t.Fatal(r.Message)
	}
	s.Expect = "192.0.2.11"
	if r := probe(context.Background(), s); r.Healthy {
		t.Fatal("wrong DNS answer accepted")
	}
}

func TestOperationalErrorIsLoggedWithoutRecovery(t *testing.T) {
	m, output, _, _, restarts := fixture(t)
	writePrivate(t, filepath.Join(m.Dir, "state.json"), "broken state")
	if err := m.tickReported(context.Background()); err == nil {
		t.Fatal("corrupt state accepted")
	}
	if count(t, output, "CHECK_ERROR") != 1 || *restarts != 0 {
		t.Fatal("missing operational error event")
	}
}

// Invoked only as the temporary VM service's executable, never as a host daemon.
func TestServiceHelper(t *testing.T) {
	addr := os.Getenv("HUNTER_WATCH_TEST_SERVER")
	if addr == "" {
		t.Skip("service subprocess only")
	}
	server := &http.Server{Addr: addr, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "watchdog VM fixture ready")
	})}
	if err := server.ListenAndServe(); err != nil {
		t.Fatal(err)
	}
}

func TestNativeSystemdRecoveryInDisposableVM(t *testing.T) {
	if os.Getenv("HUNTER_WATCH_TEST_VM") != "1" || os.Geteuid() != 0 {
		t.Skip("requires explicit HUNTER_WATCH_TEST_VM=1 in a disposable root VM")
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		t.Fatal("VM must be booted normally with systemd")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	listener.Close()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	unit := fmt.Sprintf("hunter-watch-test-%d.service", os.Getpid())
	unitPath := "/etc/systemd/system/" + unit
	if _, err := os.Lstat(unitPath); !os.IsNotExist(err) {
		t.Fatal("fixture unit already exists")
	}
	text := fmt.Sprintf("[Unit]\nDescription=Disposable Hunter watchdog acceptance fixture\n[Service]\nType=simple\nEnvironment=HUNTER_WATCH_TEST_SERVER=%s\nExecStart=%s -test.run=^TestServiceHelper$ -test.timeout=30m\n", addr, executable)
	writePrivate(t, unitPath, text)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	control := func(args ...string) error { _, err := command(ctx, nil, "systemctl", args...); return err }
	defer func() {
		control("stop", unit)
		os.Remove(unitPath)
		control("daemon-reload")
	}()
	if err := control("daemon-reload"); err != nil {
		t.Fatal(err)
	}
	if err := control("start", unit); err != nil {
		t.Fatal(err)
	}
	m, output, _, _, _ := fixture(t)
	m.Now = time.Now
	m.Services[0].Target = "http://" + addr + "/"
	m.Services[0].Expect = "200:watchdog VM fixture ready"
	m.Services[0].Unit = unit
	m.Services[0].Failures = 2
	m.Services[0].Timeout = 3
	m.Probe = probe
	m.Restart = func(ctx context.Context, s Service) error { return nativeService(ctx, s, "restart") }
	deadline := time.Now().Add(5 * time.Second)
	for !probe(ctx, m.Services[0]).Healthy {
		if time.Now().After(deadline) {
			t.Fatal("fixture HTTP service did not start")
		}
		time.Sleep(100 * time.Millisecond)
	}
	tick(t, m)
	if err := control("stop", unit); err != nil {
		t.Fatal(err)
	}
	tick(t, m)
	tick(t, m)
	if count(t, output, "DOWN") != 1 || count(t, output, "RECOVERY_ATTEMPT") != 0 {
		t.Fatal("monitoring did not detect stopped service without changing it")
	}
	if r := probe(ctx, m.Services[0]); r.Healthy {
		t.Fatal("monitor-only restarted stopped service")
	}
	writePrivate(t, filepath.Join(m.Dir, "recovery-owner"), "local\n")
	tick(t, m)
	if count(t, output, "RECOVERY_ATTEMPT") != 1 || count(t, output, "RECOVERED") != 1 {
		t.Fatalf("native recovery did not restore HTTP: %s", output.String())
	}
	if r := probe(ctx, m.Services[0]); !r.Healthy {
		t.Fatal(r.Message)
	}
}
