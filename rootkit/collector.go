// Linux rootkit evidence and explicit containment. Standard library only;
// built with CGO_ENABLED=0 so collection never calls a target libc or utility.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const maxRead = 16 << 20
const maxLibrary = 64 << 20

type many []string

func (m *many) String() string     { return strings.Join(*m, ",") }
func (m *many) Set(v string) error { *m = append(*m, v); return nil }

type finding struct {
	rank                              int
	title, location, evidence, action string
}
type scanner struct {
	root               string
	findings           []finding
	evidence, coverage []string
	preloads           map[string]bool
	historical         map[string]bool
	userspaceOnly      bool
	configSeen         map[string]bool
	configDepth        int
	preloadKnown       bool
	denied             int
}

func (s *scanner) hit(rank int, title, loc, evidence, action string) {
	s.findings = append(s.findings, finding{rank, title, loc, evidence, action})
}
func clean(v string) string {
	return strings.Map(func(r rune) rune {
		if r < 32 && r != '\n' && r != '\t' || r == 127 {
			return '?'
		}
		return r
	}, v)
}
func (s *scanner) resolve(logical string) (string, error) {
	if !filepath.IsAbs(logical) {
		return "", fmt.Errorf("not an absolute path: %q", logical)
	}
	p := filepath.Join(s.root, filepath.Clean(logical))
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		return "", err
	}
	if s.root != "/" && r != s.root && !strings.HasPrefix(r, s.root+"/") {
		return "", fmt.Errorf("outside-root symlink refused: %q", logical)
	}
	return r, nil
}
func (s *scanner) read(logical string, limit int64) ([]byte, error) {
	p, err := s.resolve(logical)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("not a regular/proc file: %q", logical)
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err == nil && int64(len(b)) > limit {
		return nil, fmt.Errorf("read exceeds %d bytes: %q", limit, logical)
	}
	return b, err
}
func (s *scanner) dirs(logical string) ([]os.DirEntry, error) {
	p, err := s.resolve(logical)
	if err != nil {
		return nil, err
	}
	return os.ReadDir(p)
}
func (s *scanner) optional(logical string) []byte {
	b, err := s.read(logical, maxRead)
	if err != nil {
		if !os.IsNotExist(err) {
			s.coverage = append(s.coverage, fmt.Sprintf("UNAVAILABLE %s: %v", logical, err))
			s.denied++
		}
		return nil
	}
	return b
}
func tokens(b []byte) []string {
	var result []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.SplitN(line, "#", 2)[0]
		result = append(result, strings.FieldsFunc(line, func(r rune) bool { return strings.ContainsRune(": \t\r\v\f", r) })...)
	}
	return result
}
func (s *scanner) preload() {
	s.preloads = map[string]bool{}
	s.configSeen = map[string]bool{}
	b, err := s.read("/etc/ld.so.preload", maxRead)
	s.preloadKnown = err == nil || os.IsNotExist(err)
	if err != nil && !os.IsNotExist(err) {
		s.coverage = append(s.coverage, "PRELOAD UNAVAILABLE: "+err.Error())
		s.denied++
	}
	for _, entry := range tokens(b) {
		if s.preloads[entry] {
			continue
		}
		s.preloads[entry] = true
		proof := "Unresolved loader token (soname, relative path, or expansion); inspect loader configuration without executing it."
		if filepath.IsAbs(entry) && !strings.Contains(entry, "$") {
			data, err := s.read(entry, maxLibrary)
			if err != nil {
				proof = err.Error()
				s.denied++
			} else {
				h := sha256.Sum256(data)
				proof = fmt.Sprintf("SHA256=%x bytes=%d", h, len(data))
			}
		}
		s.hit(1, "System-wide preload library requires approval", "/etc/ld.so.preload -> "+entry, proof,
			"Verify each library against trusted matching packages. Preview removal of only confirmed entries; keep SSH sessions open. Existing infected processes retain their mappings.")
	}
	if len(b) > 0 {
		s.evidence = append(s.evidence, "--- /etc/ld.so.preload ---\n"+clean(string(b)))
	}
	s.coverage = append(s.coverage, fmt.Sprintf("PRELOAD: %d distinct entries; all inspected independently; no libraries executed", len(s.preloads)))
	for _, p := range []string{"/etc/ld.so.conf", "/etc/environment", "/etc/profile", "/etc/bash.bashrc", "/etc/rc.local", "/etc/modules"} {
		if s.userspaceOnly && p == "/etc/modules" {
			continue
		}
		s.config(p, "loader")
	}
	for _, p := range []string{"/etc/ld.so.conf.d", "/etc/environment.d", "/run/environment.d", "/usr/lib/environment.d", "/etc/profile.d", "/etc/default", "/etc/sysconfig", "/etc/systemd/system", "/run/systemd/system", "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly"} {
		s.configTree(p, "loader", 0)
	}
	s.config("/etc/security/pam_env.conf", "loader")
	s.userStartup()
	if !s.userspaceOnly {
		for _, p := range []string{"/etc/modules-load.d", "/run/modules-load.d", "/usr/lib/modules-load.d", "/lib/modules-load.d", "/etc/modprobe.d", "/run/modprobe.d", "/usr/lib/modprobe.d", "/lib/modprobe.d"} {
			s.configTree(p, "module", 0)
		}
	}
}

func (s *scanner) userStartup() {
	homes := map[string]bool{"/root": true}
	for _, line := range strings.Split(string(s.optional("/etc/passwd")), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) >= 7 && filepath.IsAbs(fields[5]) && fields[5] != "/" {
			homes[filepath.Clean(fields[5])] = true
		}
	}
	if entries, err := s.dirs("/home"); err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				homes[filepath.Join("/home", entry.Name())] = true
			}
		}
	}
	for home := range homes {
		for _, name := range []string{".profile", ".bash_profile", ".bash_login", ".bashrc", ".zshenv", ".zprofile", ".zshrc", ".pam_environment", ".ssh/environment", ".ssh/rc"} {
			s.config(filepath.Join(home, name), "loader")
		}
		for _, name := range []string{".config/environment.d", ".config/systemd/user"} {
			s.configTree(filepath.Join(home, name), "loader", 0)
		}
	}
	s.coverage = append(s.coverage, fmt.Sprintf("USER STARTUP: inspected %d passwd/common home paths for loader settings; key material not read", len(homes)))
}
func (s *scanner) configTree(p, kind string, depth int) {
	if depth > 8 {
		s.coverage = append(s.coverage, "Depth limit: "+p)
		return
	}
	entries, err := s.dirs(p)
	if err != nil {
		if !os.IsNotExist(err) {
			s.coverage = append(s.coverage, fmt.Sprintf("UNAVAILABLE %s: %v", p, err))
			s.denied++
		}
		return
	}
	for _, e := range entries {
		child := filepath.Join(p, e.Name())
		if e.IsDir() {
			s.configTree(child, kind, depth+1)
		} else {
			s.config(child, kind)
		}
	}
}
func (s *scanner) config(p, kind string) {
	if s.configSeen == nil {
		s.configSeen = map[string]bool{}
	}
	key := kind + "|" + p
	if s.configSeen[key] {
		return
	}
	s.configSeen[key] = true
	if s.configDepth >= 16 {
		s.coverage = append(s.coverage, "ENVIRONMENTFILE recursion limit: "+p)
		s.denied++
		return
	}
	s.configDepth++
	defer func() { s.configDepth-- }()
	b := s.optional(p)
	for i, line := range strings.Split(string(b), "\n") {
		active := strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if active == "" {
			continue
		}
		upper := strings.ToUpper(active)
		if strings.HasPrefix(active, "EnvironmentFile=") {
			value := strings.TrimSpace(strings.TrimPrefix(active, "EnvironmentFile="))
			value = strings.TrimPrefix(value, "-")
			if len(value) >= 2 && (value[0] == '\'' && value[len(value)-1] == '\'' || value[0] == '"' && value[len(value)-1] == '"') {
				value = value[1 : len(value)-1]
			}
			if filepath.IsAbs(value) && !strings.ContainsAny(value, "$%*?[]\\\x00\r\n") {
				s.config(value, "loader")
			} else if value != "" {
				s.coverage = append(s.coverage, "ENVIRONMENTFILE unresolved literal/expression: "+p+" -> "+value)
			}
		}
		if strings.Contains(upper, "LD_PRELOAD") || strings.Contains(upper, "LD_AUDIT") || strings.Contains(upper, "LD_LIBRARY_PATH") {
			s.hit(1, "Loader injection startup setting", fmt.Sprintf("%s:%d", p, i+1), active,
				"Review every referenced library and preserve the startup file. Remove only unapproved settings; a system preload edit does not clear service or shell environment injection.")
		}
		fields := strings.Fields(active)
		if kind == "module" || p == "/etc/modules" {
			s.evidence = append(s.evidence, fmt.Sprintf("MODULE_STARTUP %s:%d %s", p, i+1, active))
			if len(fields) > 1 && (fields[0] == "install" || fields[0] == "remove") || strings.Contains(active, "insmod ") {
				s.hit(1, "Module startup command or modprobe override", fmt.Sprintf("%s:%d", p, i+1), active,
					"Compare with distro packages and approved drivers; preserve unapproved load hooks. Do not unload modules over SSH without a recovery path.")
			}
		}
	}
}
func moduleNames(b []byte) map[string]bool {
	names := map[string]bool{}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) > 0 {
			names[f[0]] = true
		}
	}
	return names
}

func (s *scanner) quarantineHistory(state string) {
	s.historical = map[string]bool{}
	base := filepath.Join(state, "rootkit")
	entries, err := s.dirs(base)
	if err != nil {
		if !os.IsNotExist(err) {
			s.coverage = append(s.coverage, "QUARANTINE HISTORY UNAVAILABLE: "+err.Error())
			s.denied++
		}
		return
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		b, err := s.read(filepath.Join(base, entry.Name(), "selected-preloads.txt"), 1<<20)
		if err != nil {
			continue
		}
		for _, name := range strings.Split(string(b), "\n") {
			if filepath.IsAbs(name) && filepath.Clean(name) == name && !strings.ContainsAny(name, "\x00\r\t\v\f :#$") {
				s.historical[name] = true
			}
		}
	}
	s.coverage = append(s.coverage, fmt.Sprintf("QUARANTINE HISTORY: %d previously selected preload paths retained for process-map review; path reuse is not proof of malicious mapped bytes", len(s.historical)))
}
func (s *scanner) kernel() {
	for _, p := range []string{"/proc/sys/kernel/osrelease", "/proc/sys/kernel/tainted", "/proc/sys/kernel/modules_disabled", "/proc/sys/kernel/unprivileged_bpf_disabled", "/proc/sys/kernel/modprobe", "/sys/module/module/parameters/sig_enforce", "/sys/kernel/security/lockdown"} {
		if b := s.optional(p); b != nil {
			s.evidence = append(s.evidence, p+"="+strings.TrimSpace(string(b)))
		}
	}
	first, err := s.read("/proc/modules", maxRead)
	if err != nil {
		s.coverage = append(s.coverage, "MODULES UNAVAILABLE: "+err.Error())
		s.denied++
		return
	}
	s.evidence = append(s.evidence, "--- /proc/modules ---\n"+string(first))
	entries, err := s.dirs("/sys/module")
	if err != nil {
		s.coverage = append(s.coverage, "SYSFS MODULES UNAVAILABLE: "+err.Error())
		s.denied++
		return
	}
	second, err := s.read("/proc/modules", maxRead)
	if err != nil {
		s.denied++
		return
	}
	a, b := moduleNames(first), moduleNames(second)
	for _, entry := range entries {
		name := entry.Name()
		p := "/sys/module/" + name
		state, err := s.read(p+"/initstate", 4096)
		if err != nil {
			continue
		} // Built-ins generally have no initstate: exclude.
		if strings.TrimSpace(string(state)) != "live" {
			continue
		}
		if !a[name] && !b[name] {
			// Re-read initstate to reduce module unloading races.
			if state, err = s.read(p+"/initstate", 4096); err == nil && strings.TrimSpace(string(state)) == "live" {
				s.hit(0, "Loadable module absent from both proc snapshots", p, "sysfs initstate=live, absent from two /proc/modules reads; loading/unloading can race, so repeat from an independent view.",
					"Preserve both views off-host. Do not run rmmod, send rootkit trigger signals, reboot, or change boot settings through this tool. A kernel rootkit may falsify all views; plan a trusted rebuild.")
			}
		}
		if taint := s.optional(p + "/taint"); len(bytes.TrimSpace(taint)) > 0 {
			s.evidence = append(s.evidence, "MODULE_TAINT "+name+"="+strings.TrimSpace(string(taint)))
		}
	}
	s.coverage = append(s.coverage, fmt.Sprintf("MODULES: %d proc entries, %d sysfs entries; built-ins excluded from mismatch detection; taint is provenance data, not a rootkit verdict", len(b), len(entries)))
}
func (s *scanner) processes() {
	entries, err := s.dirs("/proc")
	if err != nil {
		s.coverage = append(s.coverage, "PROC UNAVAILABLE: "+err.Error())
		s.denied++
		return
	}
	count, denied, bpf := 0, 0, 0
	for _, entry := range entries {
		if _, err := strconv.ParseUint(entry.Name(), 10, 32); err != nil {
			continue
		}
		pid := entry.Name()
		p := "/proc/" + pid
		count++
		if status, statusErr := s.read(p+"/status", 1<<20); statusErr == nil {
			for _, line := range strings.Split(string(status), "\n") {
				fields := strings.Fields(line)
				if len(fields) == 2 && fields[0] == "TracerPid:" && fields[1] != "0" {
					s.hit(2, "Process is being traced", p+"/status", "TracerPid="+fields[1], "Confirm debugger or monitoring ownership. Ptrace injection can coexist with loader/kernel implants; do not kill or detach a tracer automatically.")
				}
			}
		}
		maps, err := s.read(p+"/maps", maxRead)
		if err == nil {
			seen := map[string]bool{}
			for _, line := range strings.Split(string(maps), "\n") {
				f := strings.Fields(line)
				if len(f) < 6 {
					continue
				}
				mapping := strings.Join(f[5:], " ")
				library := strings.TrimSuffix(mapping, " (deleted)")
				if seen[mapping] {
					continue
				}
				seen[mapping] = true
				match := s.preloads[library] || s.historical[library]
				unusual := strings.HasPrefix(library, "/tmp/") || strings.HasPrefix(library, "/var/tmp/") || strings.HasPrefix(library, "/dev/shm/") || strings.Contains(mapping, "(deleted)") || strings.Contains(mapping, "memfd:")
				if match || unusual && strings.Contains(f[1], "x") {
					title := "Temporary, deleted or memfd executable mapping"
					if match {
						title = "Process still maps a system preload library"
					}
					if s.historical[library] {
						title = "Process maps a previously quarantined preload path"
					}
					s.hit(1, title, p+"/maps", mapping,
						"Identify the service and verify the mapped file. Removing a loader hook leaves existing processes infected; replace/re-exec confirmed affected services individually after testing a second SSH login. Do not bulk-kill or restart sshd here.")
				}
			}
		} else if !os.IsNotExist(err) {
			denied++
		}
		environ, err := s.read(p+"/environ", 1<<20)
		if err == nil {
			for _, variable := range bytes.Split(environ, []byte{0}) {
				v := string(variable)
				for _, key := range []string{"LD_PRELOAD=", "LD_AUDIT=", "LD_LIBRARY_PATH="} {
					if strings.HasPrefix(v, key) && len(v) > len(key) {
						s.hit(1, "Process loader injection environment", p+"/environ", v,
							"Validate the libraries and the parent service's environment. Unset only unapproved injection at its source; preserve active SSH sessions.")
					}
				}
			}
		} else if !os.IsNotExist(err) {
			denied++
		}
		if s.userspaceOnly {
			continue
		}
		fds, err := s.dirs(p + "/fdinfo")
		if err != nil {
			continue
		}
		for _, fd := range fds {
			info, err := s.read(p+"/fdinfo/"+fd.Name(), 65536)
			if err != nil {
				continue
			}
			for _, line := range strings.Split(string(info), "\n") {
				for _, prefix := range []string{"prog_id:", "map_id:", "link_id:", "btf_id:"} {
					if strings.HasPrefix(line, prefix) {
						s.evidence = append(s.evidence, "BPF_FD "+p+"/fdinfo/"+fd.Name()+" "+line)
						bpf++
					}
				}
			}
		}
	}
	s.denied += denied
	s.coverage = append(s.coverage, fmt.Sprintf("PROCESSES: %d entries, %d maps/environment failures, %d BPF fd records; no unrelated environment values saved", count, denied, bpf))
	if !s.userspaceOnly {
		s.coverage = append(s.coverage, "BPF: fdinfo inventory only; no exhaustive program/attachment enumeration. Closed/pinned/hidden programs can be missed. Privileged BPF remains possible even when unprivileged BPF is disabled.")
	}
}

func collect(root, state string, userspaceOnly bool) *scanner {
	s := &scanner{root: root, userspaceOnly: userspaceOnly}
	s.preload()
	s.quarantineHistory(state)
	if !userspaceOnly {
		s.kernel()
	} else {
		s.coverage = append(s.coverage, "SCOPE: userspace loader cleanup; LKM/module controls and BPF handle enumeration skipped")
	}
	s.processes()
	if s.denied > 0 {
		s.hit(2, "Collection partially unavailable", "coverage", fmt.Sprintf("%d failed reads or unresolved libraries; see coverage", s.denied), "Review permissions, process races, namespaces and missing evidence. A hidden object or failed read is not a clean result.")
	}
	return s
}

func (s *scanner) recheck(state string, selected []string) *scanner {
	after := collect(s.root, state, s.userspaceOnly)
	for _, note := range s.coverage {
		if strings.HasPrefix(note, "PLAN:") || strings.HasPrefix(note, "APPLIED:") || strings.HasPrefix(note, "UNCHANGED:") || strings.HasPrefix(note, "Containment record:") {
			after.coverage = append(after.coverage, note)
		}
	}
	remaining := 0
	for _, entry := range selected {
		if after.preloads[entry] {
			remaining++
		}
	}
	presence := strconv.Itoa(remaining)
	if !after.preloadKnown {
		presence = "UNKNOWN"
		after.hit(0, "Preload cleanup verification unavailable", "/etc/ld.so.preload", "The preload file could not be read after cleanup; remaining selected entries cannot be counted.", "Keep current access and inspect the read failure using trusted tools. A successful edit does not establish that the loader configuration stayed clean.")
	}
	after.coverage = append(after.coverage, "POST-CLEANUP RECHECK: selected preload tokens still present="+presence+"; fresh process/startup observations follow. No processes were restarted.")
	if remaining > 0 {
		after.hit(0, "Selected preload persistence remains or was recreated", "/etc/ld.so.preload", fmt.Sprintf("%d selected tokens remain after the cleanup", remaining), "Preserve the new file and investigate the process or startup hook recreating it. Repeatedly deleting the file does not remove that persistence source.")
	}
	return after
}
func (s *scanner) render(color bool) string {
	sort.SliceStable(s.findings, func(i, j int) bool { return s.findings[i].rank < s.findings[j].rank })
	labels := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
	counts := make([]int, 5)
	for _, f := range s.findings {
		counts[f.rank]++
	}
	var out strings.Builder
	fmt.Fprintln(&out, "CCDC rootkit triage — collection completed; this is not a clean-kernel attestation")
	fmt.Fprintf(&out, "UTC: %s | Root: %s | Static collector: %s/%s\n", time.Now().UTC().Format(time.RFC3339), s.root, runtime.GOOS, runtime.GOARCH)
	if s.userspaceOnly {
		fmt.Fprintln(&out, "Scope: userspace loader/process checks; kernel module checks skipped")
	}
	for i, l := range labels {
		fmt.Fprintf(&out, "%s=%d ", l, counts[i])
	}
	fmt.Fprint(&out, "\n\n")
	for _, f := range s.findings {
		heading := fmt.Sprintf("[%s] %s", labels[f.rank], f.title)
		if color {
			heading = []string{"\x1b[1;91m", "\x1b[1;31m", "\x1b[1;33m", "\x1b[36m", "\x1b[34m"}[f.rank] + heading + "\x1b[0m"
		}
		fmt.Fprintf(&out, "%s\n  Location: %s\n  Evidence: %s\n  Action: %s\n\n", heading, clean(f.location), clean(f.evidence), clean(f.action))
	}
	fmt.Fprintln(&out, "CHECK COVERAGE")
	for _, line := range s.coverage {
		fmt.Fprintln(&out, clean(line))
	}
	fmt.Fprintln(&out, "TRUST: a static binary bypasses libc loader interposition, but trusts the running kernel. SSH/sudo/staging can already be compromised. No result proves an LKM, eBPF, ptrace, boot or replaced-binary rootkit absent.")
	fmt.Fprintln(&out, "DETAILED EVIDENCE")
	for _, line := range s.evidence {
		fmt.Fprintln(&out, clean(line))
	}
	return out.String()
}

// removeEntries preserves comments, whitespace and every unselected token.
func removeEntries(input []byte, selected map[string]bool) ([]byte, map[string]bool) {
	found := map[string]bool{}
	var out bytes.Buffer
	for i := 0; i < len(input); {
		if input[i] == '#' {
			end := bytes.IndexByte(input[i:], '\n')
			if end < 0 {
				out.Write(input[i:])
				break
			}
			end += i
			out.Write(input[i : end+1])
			i = end + 1
			continue
		}
		if strings.ContainsRune(" \t\r\n\v\f:", rune(input[i])) {
			out.WriteByte(input[i])
			i++
			continue
		}
		end := i
		for end < len(input) && !strings.ContainsRune(" \t\r\n\v\f:#", rune(input[end])) {
			end++
		}
		token := string(input[i:end])
		if selected[token] {
			found[token] = true
		} else {
			out.Write(input[i:end])
		}
		i = end
	}
	return out.Bytes(), found
}
func safeDirs(p string) error {
	p = filepath.Clean(p)
	if !filepath.IsAbs(p) {
		return errors.New("directory must be absolute")
	}
	current := "/"
	for _, part := range strings.Split(strings.TrimPrefix(p, "/"), "/") {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		st, err := os.Lstat(current)
		if os.IsNotExist(err) {
			if err = os.Mkdir(current, 0700); err != nil {
				return err
			}
			continue
		}
		if err != nil {
			return err
		}
		if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("unsafe directory: %s", current)
		}
	}
	return nil
}
func exclusive(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}

// Preserve access-control metadata before an atomic replacement. Content-bound
// IMA/EVM signatures cannot be reused for changed bytes, so refuse that case.
func copyAttrs(source, destination string) error {
	n, err := syscall.Listxattr(source, nil)
	if errors.Is(err, syscall.ENOTSUP) {
		return nil
	}
	if err != nil {
		return err
	}
	if n == 0 {
		return nil
	}
	if n > 1<<20 {
		return errors.New("extended attribute list exceeds limit")
	}
	list := make([]byte, n)
	n, err = syscall.Listxattr(source, list)
	if err != nil {
		return err
	}
	for _, attr := range bytes.Split(list[:n], []byte{0}) {
		if len(attr) == 0 {
			continue
		}
		name := string(attr)
		if name == "security.ima" || name == "security.evm" {
			return errors.New("preload has content-bound IMA/EVM metadata; targeted policy-aware recovery is required")
		}
		size, err := syscall.Getxattr(source, name, nil)
		if err != nil {
			return err
		}
		if size > 1<<20 {
			return errors.New("extended attribute exceeds limit")
		}
		value := make([]byte, size)
		size, err = syscall.Getxattr(source, name, value)
		if err != nil {
			return err
		}
		if err = syscall.Setxattr(destination, name, value[:size], 0); err != nil {
			return fmt.Errorf("preserve attribute %s: %w", name, err)
		}
	}
	return nil
}
func (s *scanner) contain(state string, selected []string, seal bool, apply bool) error {
	selectSet := map[string]bool{}
	for _, entry := range selected {
		if !filepath.IsAbs(entry) || filepath.Clean(entry) != entry || strings.ContainsAny(entry, "\x00\r\n\t\v\f :#$") {
			return fmt.Errorf("select an exact absolute preload path without delimiters or loader expansions: %q", entry)
		}
		selectSet[entry] = true
	}
	var before, after []byte
	var original os.FileInfo
	preload := filepath.Join(s.root, "etc/ld.so.preload")
	if len(selectSet) > 0 {
		var err error
		original, err = os.Lstat(preload)
		if err != nil {
			return err
		}
		if !original.Mode().IsRegular() || original.Mode()&os.ModeSymlink != 0 {
			return errors.New("preload must be a regular file, not a symlink")
		}
		before, err = s.read("/etc/ld.so.preload", maxRead)
		if err != nil {
			return err
		}
		var found map[string]bool
		after, found = removeEntries(before, selectSet)
		for entry := range selectSet {
			if !found[entry] {
				return fmt.Errorf("selected entry is absent; no changes: %s", entry)
			}
		}
	}
	sealAlready := false
	if seal {
		b, err := s.read("/proc/sys/kernel/modules_disabled", 4096)
		if err != nil {
			return err
		}
		if v := strings.TrimSpace(string(b)); v != "0" && v != "1" {
			return fmt.Errorf("unexpected modules_disabled value %q", v)
		}
		sealAlready = strings.TrimSpace(string(b)) == "1"
	}
	for _, entry := range selected {
		s.coverage = append(s.coverage, "PLAN: remove only preload token "+entry+"; retain library and all running processes")
	}
	if seal {
		s.coverage = append(s.coverage, "PLAN: modules_disabled=1; blocks BOTH loading and unloading until reboot; does not remove existing rootkits; no persistent sysctl file")
	}
	if !apply {
		s.coverage = append(s.coverage, "PREVIEW ONLY: no containment changes; use --apply during an authorized hardening phase")
		return nil
	}
	if err := safeDirs(state); err != nil {
		return err
	}
	st, err := os.Lstat(state)
	if err != nil {
		return err
	}
	if st.Mode().Perm()&0077 != 0 {
		return errors.New("state directory must be owner-only")
	}
	if uid, ok := st.Sys().(*syscall.Stat_t); ok && int(uid.Uid) != os.Geteuid() {
		return errors.New("state directory belongs to another user")
	}
	lock := filepath.Join(state, ".setup-lock")
	if err = os.Mkdir(lock, 0700); err != nil {
		return fmt.Errorf("setup/hardening lock: %w", err)
	}
	defer os.Remove(lock)
	base := filepath.Join(state, "rootkit")
	if err = safeDirs(base); err != nil {
		return err
	}
	record, err := os.MkdirTemp(base, time.Now().UTC().Format("20060102T150405Z")+"-")
	if err != nil {
		return err
	}
	s.coverage = append(s.coverage, "Containment record: "+record)
	if err = exclusive(filepath.Join(record, "INCOMPLETE"), nil); err != nil {
		return err
	}
	if err = exclusive(filepath.Join(record, "before.txt"), []byte(s.render(false))); err != nil {
		return err
	}
	if len(selectSet) > 0 {
		if err = exclusive(filepath.Join(record, "selected-preloads.txt"), []byte(strings.Join(selected, "\n")+"\n")); err != nil {
			return err
		}
		if err = exclusive(filepath.Join(record, "ld.so.preload.before"), before); err != nil {
			return err
		}
		h := sha256.Sum256(before)
		if err = exclusive(filepath.Join(record, "preload.sha256"), []byte(hex.EncodeToString(h[:])+"\n")); err != nil {
			return err
		}
		metadata := fmt.Sprintf("mode=%04o\n", original.Mode().Perm())
		if ids, ok := original.Sys().(*syscall.Stat_t); ok {
			metadata += fmt.Sprintf("uid=%d\ngid=%d\n", ids.Uid, ids.Gid)
		}
		if err = exclusive(filepath.Join(record, "preload.metadata.txt"), []byte(metadata)); err != nil {
			return err
		}
		for i, entry := range selected {
			library, readErr := s.read(entry, maxLibrary)
			if readErr != nil {
				s.coverage = append(s.coverage, "Library backup unavailable: "+entry+": "+readErr.Error())
				continue
			}
			name := fmt.Sprintf("library-%d.bin", i+1)
			h = sha256.Sum256(library)
			if err = exclusive(filepath.Join(record, name), library); err != nil {
				return err
			}
			if err = exclusive(filepath.Join(record, name+".txt"), []byte(fmt.Sprintf("source=%q\nSHA256=%x\n", entry, h))); err != nil {
				return err
			}
		}
		// Fail closed on a changed file; never overwrite a later admin's edit.
		current, err := s.read("/etc/ld.so.preload", maxRead)
		if err != nil {
			return err
		}
		latest, err := os.Lstat(preload)
		if err != nil {
			return err
		}
		if !os.SameFile(original, latest) || !bytes.Equal(current, before) {
			return errors.New("preload changed during preservation; no edit made")
		}
		if err = safeDirs(filepath.Dir(preload)); err != nil {
			return err
		}
		staged, err := os.CreateTemp(filepath.Dir(preload), ".hunter-preload-")
		if err != nil {
			return err
		}
		name := staged.Name()
		defer os.Remove(name)
		if _, err = staged.Write(after); err != nil {
			staged.Close()
			return err
		}
		if uid, ok := original.Sys().(*syscall.Stat_t); ok {
			if err = staged.Chown(int(uid.Uid), int(uid.Gid)); err != nil {
				staged.Close()
				return err
			}
		}
		if err = staged.Chmod(original.Mode().Perm()); err != nil {
			staged.Close()
			return err
		}
		if err = copyAttrs(preload, name); err != nil {
			staged.Close()
			return err
		}
		if err = staged.Sync(); err != nil {
			staged.Close()
			return err
		}
		if err = staged.Close(); err != nil {
			return err
		}
		if err = os.Rename(name, preload); err != nil {
			return err
		}
		s.coverage = append(s.coverage, "APPLIED: selected preload tokens removed; all libraries, other tokens, comments and running processes retained")
	}
	if seal && sealAlready {
		s.coverage = append(s.coverage, "UNCHANGED: module loading/unloading was already disabled; no control write")
	}
	if seal && !sealAlready {
		control := filepath.Join(s.root, "proc/sys/kernel/modules_disabled")
		f, err := os.OpenFile(control, os.O_WRONLY, 0)
		if err != nil {
			return err
		}
		_, err = f.Write([]byte("1\n"))
		closeErr := f.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		b, err := s.read("/proc/sys/kernel/modules_disabled", 4096)
		if err != nil {
			return err
		}
		if strings.TrimSpace(string(b)) != "1" {
			return errors.New("modules_disabled readback did not confirm 1")
		}
		s.coverage = append(s.coverage, "APPLIED: module loading AND unloading disabled until reboot; existing loaded code remains")
	}
	if err = exclusive(filepath.Join(record, "COMPLETE"), nil); err != nil {
		return err
	}
	return os.Remove(filepath.Join(record, "INCOMPLETE"))
}

func run(args []string) int {
	flags := flag.NewFlagSet("hunter-rootkit", flag.ContinueOnError)
	root := flags.String("root", "/", "Mounted/snapshot root; always read-only, containment forbidden")
	output := flags.String("output", "", "Private report path; exclusive create (default ./ccdc-rootkit-TIME-PID.txt)")
	state := flags.String("state-dir", "/.x86", "Root-owned private state store for explicit containment records")
	color := flags.String("color", "auto", "auto, always or never; saved report is plain")
	apply := flags.Bool("apply", false, "Apply explicitly selected containment operations; never restart services or unload modules")
	userspaceOnly := flags.Bool("userspace-only", false, "Focus on preload libraries, process mappings and loader startup settings; skip LKM/BPF inventory and forbid module locking")
	seal := flags.Bool("disable-modules-until-reboot", false, "Preview one-way kernel.modules_disabled=1: blocks loading AND unloading until reboot")
	var quarantine many
	flags.Var(&quarantine, "quarantine-preload", "Preview removing this exact /etc/ld.so.preload token; repeat for multiple libraries; requires --apply to edit")
	flags.Usage = func() {
		fmt.Fprint(flags.Output(), "Static Linux rootkit triage. Default: READ ONLY, no repairs.\nUse a trusted jump box to build; no target Go/Python or external commands.\n\n")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "Unexpected positional arguments")
		return 2
	}
	if *color != "auto" && *color != "always" && *color != "never" {
		fmt.Fprintln(os.Stderr, "Invalid --color")
		return 2
	}
	if *userspaceOnly && *seal {
		fmt.Fprintln(os.Stderr, "--userspace-only cannot change kernel module controls")
		return 2
	}
	resolved, err := filepath.EvalSymlinks(*root)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if resolved != "/" && (*apply || *seal || len(quarantine) > 0) {
		fmt.Fprintln(os.Stderr, "Containment is forbidden with an offline --root")
		return 2
	}
	if !filepath.IsAbs(*state) || filepath.Clean(*state) != *state || *state == "/" || strings.HasPrefix(*state, "/etc/") || *state == "/etc" {
		fmt.Fprintln(os.Stderr, "Use a canonical absolute --state-dir outside /etc")
		return 2
	}
	if *apply && (!*seal && len(quarantine) == 0 || os.Geteuid() != 0) {
		fmt.Fprintln(os.Stderr, "--apply needs root and explicitly selected containment operations")
		return 2
	}
	if *output == "" {
		*output = fmt.Sprintf("ccdc-rootkit-%s-%d.txt", time.Now().UTC().Format("20060102T150405Z"), os.Getpid())
	}
	report, err := os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer report.Close()
	if _, err = fmt.Fprintln(report, "CCDC rootkit report started; collection is incomplete unless a completion summary follows."); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err = report.Sync(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	s := collect(resolved, *state, *userspaceOnly)
	rc := 0
	if *seal || len(quarantine) > 0 {
		// Preserve the collected report before touching any loader/kernel setting.
		if _, err = fmt.Fprintln(report, "PRE-CONTAINMENT COLLECTION\n"+s.render(false)); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if err = report.Sync(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if err = s.contain(*state, quarantine, *seal, *apply); err != nil {
			s.hit(0, "Containment incomplete", *state, err.Error(), "Keep current access. Review retained records before retrying; earlier selected operations may have succeeded. No automatic rollback of module locking is possible.")
			rc = 1
		} else if *apply {
			s = s.recheck(*state, quarantine)
			if len(quarantine) > 0 && !s.preloadKnown {
				rc = 1
			}
			for _, entry := range quarantine {
				if s.preloads[entry] {
					rc = 1
				}
			}
		}
	}
	text := s.render(false)
	if *seal || len(quarantine) > 0 {
		text = "FINAL RESULT (preview unless --apply was requested; successful changes include a fresh read-only recheck)\n" + text
	}
	if _, err = io.WriteString(report, text); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err = report.Sync(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	useColor := *color == "always"
	if *color == "auto" {
		st, _ := os.Stdout.Stat()
		useColor = st != nil && st.Mode()&os.ModeCharDevice != 0 && os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb"
	}
	console := s.render(useColor)
	if index := strings.Index(console, "DETAILED EVIDENCE\n"); index >= 0 {
		console = console[:index]
	}
	for _, note := range s.coverage {
		if strings.HasPrefix(note, "APPLIED:") || strings.HasPrefix(note, "UNCHANGED:") || strings.HasPrefix(note, "POST-CLEANUP RECHECK:") {
			fmt.Println(clean(note))
		}
	}
	fmt.Print(console)
	fmt.Printf("Report: %s\n", *output)
	return rc
}
func main() { os.Exit(run(os.Args[1:])) }
