package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func putFixture(t *testing.T, root, path, body string) {
	t.Helper()
	target := filepath.Join(root, path)
	if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
}
func fixture(t *testing.T) (*scanner, string) {
	t.Helper()
	root := t.TempDir()
	putFixture(t, root, "etc/ld.so.preload", "# keep comment\n/opt/a.so:/opt/b.so /opt/approved.so # keep /opt/a.so in comment\n")
	for _, p := range []string{"opt/a.so", "opt/b.so", "opt/approved.so"} {
		putFixture(t, root, p, "fixture library "+p)
	}
	putFixture(t, root, "proc/modules", "normal 1 0 - Live 0\n")
	putFixture(t, root, "sys/module/normal/initstate", "live\n")
	putFixture(t, root, "sys/module/normal/taint", "OE\n")
	putFixture(t, root, "sys/module/hidden_one/initstate", "live\n")
	putFixture(t, root, "sys/module/hidden_two/initstate", "live\n")
	putFixture(t, root, "sys/module/builtin/parameters/fixture", "1\n")
	putFixture(t, root, "proc/sys/kernel/modules_disabled", "0\n")
	putFixture(t, root, "proc/sys/kernel/tainted", "12288\n")
	putFixture(t, root, "proc/42/maps", "1000-2000 r-xp 00000000 00:00 1 /opt/a.so\n2000-3000 r-xp 0 00:00 2 /opt/b.so\n3000-4000 r-xp 0 00:00 0 /memfd:injected (deleted)\n")
	putFixture(t, root, "proc/42/environ", "LD_PRELOAD=/opt/a.so\x00LD_AUDIT=/opt/b.so\x00LD_LIBRARY_PATH=/tmp/injected\x00TOKEN=DO_NOT_SAVE_THIS\x00")
	putFixture(t, root, "proc/42/fdinfo/7", "pos:\t0\nprog_id:\t123\n")
	putFixture(t, root, "proc/42/status", "Name:\tfixture\nTracerPid:\t71\n")
	putFixture(t, root, "etc/modprobe.d/hidden.conf", "install alias /sbin/insmod /opt/driver.ko\n")
	return &scanner{root: root}, root
}
func TestMultipleImplantsAndRedaction(t *testing.T) {
	s, _ := fixture(t)
	s.preload()
	s.kernel()
	s.processes()
	report := s.render(false)
	for _, value := range []string{"/opt/a.so", "/opt/b.so", "hidden_one", "hidden_two", "memfd:injected", "LD_LIBRARY_PATH=/tmp/injected", "BPF_FD", "prog_id:", "modprobe override", "SHA256=", "TracerPid=71"} {
		if !strings.Contains(report, value) {
			t.Errorf("missing %q", value)
		}
	}
	if strings.Contains(report, "DO_NOT_SAVE_THIS") {
		t.Fatal("unrelated environment leaked")
	}
	mismatches := 0
	for _, f := range s.findings {
		if strings.Contains(f.title, "absent from both") {
			mismatches++
			if strings.Contains(f.location, "normal") || strings.Contains(f.location, "builtin") {
				t.Fatal("legitimate module mismatch")
			}
		}
	}
	if mismatches != 2 {
		t.Fatalf("got %d mismatches", mismatches)
	}
	if !strings.Contains(report, "not a clean-kernel attestation") {
		t.Fatal("missing trust boundary")
	}
	if strings.Contains(report, "[HIGH] Kernel taint") {
		t.Fatal("taint alone is not a rootkit")
	}
}
func TestOfflineReadBoundary(t *testing.T) {
	s, root := fixture(t)
	outside := t.TempDir()
	putFixture(t, outside, "secret", "HOST_SECRET")
	if err := os.Symlink(outside, filepath.Join(root, "etc", "escaped")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.read("/etc/escaped/secret", 100); err == nil {
		t.Fatal("escaped root")
	}
	if err := os.Symlink(filepath.Join(outside, "secret"), filepath.Join(root, "etc", "profile")); err != nil {
		t.Fatal(err)
	}
	s.preload()
	if strings.Contains(s.render(false), "HOST_SECRET") {
		t.Fatal("secret escaped")
	}
}

func TestUserspaceFocusAndStartupSources(t *testing.T) {
	_, root := fixture(t)
	putFixture(t, root, "etc/passwd", "team:x:1000:1000::/srv/team:/bin/sh\n")
	putFixture(t, root, "srv/team/.bashrc", "export LD_PRELOAD=/opt/user.so\n")
	putFixture(t, root, "srv/team/.ssh/id_rsa", "PRIVATE_KEY_NEVER_READ")
	putFixture(t, root, "etc/default/shop", "LD_LIBRARY_PATH=/opt/private-libs\n")
	putFixture(t, root, "etc/systemd/system/shop.service", "[Service]\nEnvironmentFile=-\"/opt/shop/runtime.env\"\n")
	putFixture(t, root, "opt/shop/runtime.env", "LD_AUDIT=/opt/audit.so\n")
	s := collect(root, "/state", true)
	report := s.render(false)
	for _, value := range []string{"kernel module checks skipped", "/srv/team/.bashrc", "/opt/user.so", "/etc/default/shop", "/opt/private-libs", "/opt/shop/runtime.env", "LD_AUDIT=/opt/audit.so"} {
		if !strings.Contains(report, value) {
			t.Errorf("missing %q", value)
		}
	}
	for _, value := range []string{"hidden_one", "hidden_two", "BPF_FD", "MODULE_STARTUP", "MODULE_TAINT", "PRIVATE_KEY_NEVER_READ"} {
		if strings.Contains(report, value) {
			t.Errorf("unexpected %q", value)
		}
	}
}

func TestPostCleanupRecheckTracksProcessesAndReinfection(t *testing.T) {
	s, root := fixture(t)
	s.userspaceOnly = true
	s.preload()
	putFixture(t, root, "etc/environment", "LD_PRELOAD=/opt/a.so\n")
	if err := s.contain(filepath.Join(root, "state"), []string{"/opt/a.so", "/opt/b.so"}, false, true); err != nil {
		t.Fatal(err)
	}
	after := s.recheck("/state", []string{"/opt/a.so", "/opt/b.so"})
	report := after.render(false)
	if after.preloads["/opt/a.so"] || after.preloads["/opt/b.so"] {
		t.Fatal("selected entries remained")
	}
	for _, value := range []string{"POST-CLEANUP RECHECK: selected preload tokens still present=0", "Process maps a previously quarantined preload path", "Loader injection startup setting", "/etc/environment"} {
		if !strings.Contains(report, value) {
			t.Errorf("missing %q", value)
		}
	}
	putFixture(t, root, "etc/ld.so.preload", "/opt/a.so\n")
	reinfected := after.recheck("/state", []string{"/opt/a.so"})
	if !strings.Contains(reinfected.render(false), "Selected preload persistence remains or was recreated") {
		t.Fatal("recreated hook not detected")
	}
	os.Remove(filepath.Join(root, "etc/ld.so.preload"))
	os.Mkdir(filepath.Join(root, "etc/ld.so.preload"), 0700)
	unknown := after.recheck("/state", []string{"/opt/a.so"})
	if unknown.preloadKnown || !strings.Contains(unknown.render(false), "still present=UNKNOWN") {
		t.Fatal("unreadable hook incorrectly reported absent")
	}
}

func TestUserspaceModeRejectsModuleLockBeforeWriting(t *testing.T) {
	output := filepath.Join(t.TempDir(), "not-created")
	if rc := run([]string{"--userspace-only", "--disable-modules-until-reboot", "--output", output}); rc != 2 {
		t.Fatalf("rc=%d", rc)
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatal("wrote output before rejecting conflicting controls")
	}
}
func TestExactPreloadRemoval(t *testing.T) {
	before := []byte("# /bad.so is retained here\n/bad.so:/keep.so /bad.so.extra\t/second.so # /second.so comment\n")
	after, found := removeEntries(before, map[string]bool{"/bad.so": true, "/second.so": true})
	want := "# /bad.so is retained here\n:/keep.so /bad.so.extra\t # /second.so comment\n"
	if string(after) != want || !found["/bad.so"] || !found["/second.so"] {
		t.Fatalf("wrong removal: %q %v", after, found)
	}
}
func TestPreviewNeverChangesFiles(t *testing.T) {
	s, root := fixture(t)
	state := filepath.Join(root, "state")
	before, _ := os.ReadFile(filepath.Join(root, "etc/ld.so.preload"))
	if err := s.contain(state, []string{"/opt/a.so", "/opt/b.so"}, true, false); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(filepath.Join(root, "etc/ld.so.preload"))
	control, _ := os.ReadFile(filepath.Join(root, "proc/sys/kernel/modules_disabled"))
	if !bytes.Equal(before, after) || string(control) != "0\n" {
		t.Fatal("preview changed target")
	}
	if _, err := os.Stat(state); !os.IsNotExist(err) {
		t.Fatal("preview wrote state")
	}
}
func TestSelectedContainmentAndRecords(t *testing.T) {
	s, root := fixture(t)
	state := filepath.Join(root, "state")
	putFixture(t, root, "state/latest", "ORIGINAL_BASELINE\n")
	preload := filepath.Join(root, "etc/ld.so.preload")
	os.Chmod(preload, 0640)
	attrSupported := syscall.Setxattr(preload, "user.hunter-fixture", []byte("preserve"), 0) == nil
	before, _ := os.ReadFile(preload)
	if err := s.contain(state, []string{"/opt/a.so", "/opt/b.so"}, true, true); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(preload)
	if !strings.Contains(string(after), "/opt/approved.so") || !strings.Contains(string(after), "# keep /opt/a.so in comment") {
		t.Fatal("unselected content changed")
	}
	if active := strings.Join(tokens(after), " "); strings.Contains(active, "/opt/a.so") || strings.Contains(active, "/opt/b.so") {
		t.Fatal("selected token still active")
	}
	st, _ := os.Stat(preload)
	if st.Mode().Perm() != 0640 {
		t.Fatal("mode not preserved")
	}
	if attrSupported {
		value := make([]byte, 64)
		n, err := syscall.Getxattr(preload, "user.hunter-fixture", value)
		if err != nil || string(value[:n]) != "preserve" {
			t.Fatal("extended attribute not preserved")
		}
	}
	for _, p := range []string{"opt/a.so", "opt/b.so", "proc/42/maps"} {
		if _, err := os.Stat(filepath.Join(root, p)); err != nil {
			t.Fatal("deleted library/process")
		}
	}
	control, _ := os.ReadFile(filepath.Join(root, "proc/sys/kernel/modules_disabled"))
	if string(control) != "1\n" {
		t.Fatal("module control not written")
	}
	rescan := &scanner{root: root}
	rescan.preload()
	rescan.quarantineHistory("/state")
	rescan.processes()
	if !strings.Contains(rescan.render(false), "Process maps a previously quarantined preload path") {
		t.Fatal("lost existing injected-process evidence after removing the hook")
	}
	latest, _ := os.ReadFile(filepath.Join(state, "latest"))
	if string(latest) != "ORIGINAL_BASELINE\n" {
		t.Fatal("baseline changed")
	}
	runs, _ := filepath.Glob(filepath.Join(state, "rootkit", "*"))
	if len(runs) != 1 {
		t.Fatal("missing record")
	}
	saved, _ := os.ReadFile(filepath.Join(runs[0], "ld.so.preload.before"))
	if !bytes.Equal(saved, before) {
		t.Fatal("bad original backup")
	}
	for _, file := range []string{"COMPLETE", "before.txt", "preload.sha256", "preload.metadata.txt", "library-1.bin", "library-2.bin"} {
		st, err := os.Stat(filepath.Join(runs[0], file))
		if err != nil || st.Mode().Perm() != 0600 {
			t.Fatalf("private record missing %s: %v", file, err)
		}
	}
	if _, err := os.Stat(filepath.Join(state, ".setup-lock")); !os.IsNotExist(err) {
		t.Fatal("lock leaked")
	}
}

func TestAlreadyDisabledModuleControl(t *testing.T) {
	s, root := fixture(t)
	putFixture(t, root, "proc/sys/kernel/modules_disabled", "1\n")
	if err := s.contain(filepath.Join(root, "state"), nil, true, true); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(s.render(false), "already disabled; no control write") {
		t.Fatal("already-set control not handled")
	}
}
func TestContainmentRefusesUnsafeChanges(t *testing.T) {
	for _, mode := range []string{"absent", "symlink", "locked", "bad-token"} {
		t.Run(mode, func(t *testing.T) {
			s, root := fixture(t)
			state := filepath.Join(root, "state")
			selected := []string{"/opt/a.so"}
			original, _ := os.ReadFile(filepath.Join(root, "etc/ld.so.preload"))
			switch mode {
			case "absent":
				selected = []string{"/opt/absent.so"}
			case "bad-token":
				selected = []string{"/opt/a.so:/opt/b.so"}
			case "symlink":
				os.Remove(filepath.Join(root, "etc/ld.so.preload"))
				os.Symlink(filepath.Join(root, "opt/a.so"), filepath.Join(root, "etc/ld.so.preload"))
			case "locked":
				os.MkdirAll(filepath.Join(state, ".setup-lock"), 0700)
			}
			if err := s.contain(state, selected, false, true); err == nil {
				t.Fatal("accepted unsafe edit")
			}
			if mode != "symlink" {
				after, _ := os.ReadFile(filepath.Join(root, "etc/ld.so.preload"))
				if !bytes.Equal(original, after) {
					t.Fatal("changed file on refusal")
				}
			}
		})
	}
}
func TestOfflineApplyRejectedBeforeReport(t *testing.T) {
	_, root := fixture(t)
	output := filepath.Join(root, "not-created.txt")
	if rc := run([]string{"--root", root, "--output", output, "--apply", "--quarantine-preload", "/opt/a.so"}); rc != 2 {
		t.Fatalf("rc=%d", rc)
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatal("created output before rejecting")
	}
}
