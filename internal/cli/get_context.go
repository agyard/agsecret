package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/term"
)

const capturedOutputRefusal = `refused to print a password directly to captured stdout. Use it indirectly via "$(agsecret get <ref>)", a pipe, "agsecret send tmux:<pane> <ref>", or "agsecret exec", or pass --dangerously-skip-check. Run "agsecret help" for details.`

// trustedTerminal lets get serve a person at a terminal and lets a shell pass
// the value to another process through a pipe or command substitution. A
// direct capture by an agent (for example, a bytes pipe owned by the caller)
// is rejected. This is a context check, not a security boundary: callers that
// can inspect the process or rewrite the value can still defeat it.
func trustedTerminal(out io.Writer) error {
	terminal := isTerminalWriter(out)
	if runtime.GOOS == "linux" {
		// Pipes belong to the nearest shell, whether interactive, scripted or
		// running -c. Terminal output still refuses any command-shell ancestor.
		pid, err := shellAncestor(os.Getppid(), terminal, os.ReadFile)
		if err == nil && (terminal && pid == 0 || !terminal && pid != 0 && isIndirectOutput(out, pid)) {
			return nil
		}
	} else if terminal {
		return nil
	}
	return &exitError{code: 2, err: errors.New(capturedOutputRefusal)}
}

func isTerminalWriter(w io.Writer) bool {
	f, ok := w.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

func isIndirectOutput(out io.Writer, shellPID int) bool {
	f, ok := out.(*os.File)
	if !ok {
		return false
	}
	current, err := f.Stat()
	// A file redirect is ambiguous: it might be a deliberate capture by the
	// caller, so only a pipe is treated as an indirect shell workflow.
	if err != nil || current.Mode()&os.ModeNamedPipe == 0 {
		return false
	}
	for _, fd := range []int{1, 2} {
		ancestor, err := os.Stat(fmt.Sprintf("/proc/%d/fd/%d", shellPID, fd))
		if err != nil || os.SameFile(current, ancestor) {
			return false
		}
	}
	return true
}

// parseParentPID parses Linux /proc/<pid>/stat. The comm field may contain
// spaces and parentheses, so the final ')' is the only reliable delimiter.
func parseParentPID(stat string) (int, error) {
	end := strings.LastIndexByte(stat, ')')
	if end < 0 {
		return 0, errors.New("invalid process stat")
	}
	fields := strings.Fields(stat[end+1:])
	if len(fields) < 2 {
		return 0, errors.New("invalid process stat")
	}
	pid, err := strconv.Atoi(fields[1])
	if err != nil || pid < 0 {
		return 0, errors.New("invalid process parent PID")
	}
	return pid, nil
}

// shellAncestor finds the nearest shell, or only shells running -c when
// commandOnly is true. Skipping an inner shell would compare the wrong pipes.
func shellAncestor(pid int, commandOnly bool, readFile func(string) ([]byte, error)) (int, error) {
	seen := make(map[int]bool)
	for pid > 0 {
		if seen[pid] || len(seen) >= 4096 {
			return 0, errors.New("cyclic process ancestry")
		}
		seen[pid] = true
		cmdline, err := readFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		if err != nil {
			return 0, err
		}
		args := strings.Split(string(cmdline), "\x00")
		if len(shellArgs(args)) > 0 && (!commandOnly || isShellCommand(args)) {
			return pid, nil
		}
		if pid == 1 {
			return 0, nil
		}
		stat, err := readFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err != nil {
			return 0, err
		}
		pid, err = parseParentPID(string(stat))
		if err != nil {
			return 0, err
		}
	}
	return 0, nil
}

func shellArgs(args []string) []string {
	if len(args) == 0 {
		return nil
	}
	name := strings.TrimPrefix(strings.ToLower(filepathBase(args[0])), "-")
	if name == "busybox" && len(args) > 1 {
		args = args[1:]
		name = strings.ToLower(filepathBase(args[0]))
	}
	switch name {
	case "sh", "bash", "dash", "ash", "zsh", "ksh", "mksh", "fish":
		return args
	default:
		return nil
	}
}

func isShellCommand(args []string) bool {
	args = shellArgs(args)
	for i := 1; i < len(args); i++ {
		arg := args[i]
		if arg == "--command" || strings.HasPrefix(arg, "--command=") {
			return true
		}
		if arg == "-o" || arg == "+o" || arg == "-O" || arg == "+O" || arg == "--rcfile" || arg == "--init-file" {
			i++
			continue
		}
		if arg == "--" || !strings.HasPrefix(arg, "-") || arg == "-" {
			return false
		}
		if !strings.HasPrefix(arg, "--") && strings.ContainsRune(arg[1:], 'c') {
			return true
		}
	}
	return false
}

func filepathBase(s string) string {
	if i := strings.LastIndexAny(s, "/\\"); i >= 0 {
		return s[i+1:]
	}
	return s
}
