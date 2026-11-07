//go:build linux || freebsd || openbsd || netbsd || dragonfly

package keyring

import (
	"bufio"
	"bytes"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

const (
	testCollection = dbus.ObjectPath("/org/freedesktop/secrets/collection/test")
	testItem       = dbus.ObjectPath("/org/freedesktop/secrets/collection/test/item")
	testSession    = dbus.ObjectPath("/org/freedesktop/secrets/session/test")
)

type fakeService struct {
	mu                        sync.Mutex
	account                   string
	value                     []byte
	locked, duplicate, prompt bool
	delay                     time.Duration
	searches                  int
}

func (f *fakeService) SearchItems(attrs map[string]string) ([]dbus.ObjectPath, []dbus.ObjectPath, *dbus.Error) {
	f.mu.Lock()
	f.searches++
	matched, locked, duplicate, delay := attrs["service"] == "agsecret" && len(attrs) == 2 && attrs["vault"] == f.account && len(f.value) > 0, f.locked, f.duplicate, f.delay
	f.mu.Unlock()
	time.Sleep(delay)
	if !matched {
		return []dbus.ObjectPath{}, []dbus.ObjectPath{}, nil
	}
	if locked {
		return []dbus.ObjectPath{}, []dbus.ObjectPath{testItem}, nil
	}
	if duplicate {
		return []dbus.ObjectPath{testItem, testItem}, []dbus.ObjectPath{}, nil
	}
	return []dbus.ObjectPath{testItem}, []dbus.ObjectPath{}, nil
}

func (*fakeService) OpenSession(string, dbus.Variant) (dbus.Variant, dbus.ObjectPath, *dbus.Error) {
	return dbus.MakeVariant(""), testSession, nil
}

func (*fakeService) ReadAlias(string) (dbus.ObjectPath, *dbus.Error) { return testCollection, nil }
func (*fakeService) Close() *dbus.Error                              { return nil }

func (f *fakeService) Get(string, string) (dbus.Variant, *dbus.Error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return dbus.MakeVariant(f.locked), nil
}

func (f *fakeService) CreateItem(properties map[string]dbus.Variant, value secret, replace bool) (dbus.ObjectPath, dbus.ObjectPath, *dbus.Error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.prompt {
		return "/", "/prompt", nil
	}
	f.account = properties[itemIF+".Attributes"].Value().(map[string]string)["vault"]
	f.value = bytes.Clone(value.Value)
	return testItem, "/", nil
}

func (f *fakeService) GetSecret(session dbus.ObjectPath) (secret, *dbus.Error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return secret{Session: session, Parameters: []byte{}, Value: bytes.Clone(f.value), ContentType: "application/octet-stream"}, nil
}

func (f *fakeService) SetSecret(value secret) *dbus.Error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.value = bytes.Clone(value.Value)
	return nil
}

func privateService(t *testing.T) (secretService, *fakeService, *dbus.Conn) {
	t.Helper()
	program, err := exec.LookPath("dbus-daemon")
	if err != nil {
		t.Skip("private Secret Service acceptance requires dbus-daemon")
	}
	process := exec.Command(program, "--session", "--nofork", "--nopidfile", "--print-address=1")
	output, err := process.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = process.Process.Kill(); _ = process.Wait() })
	scanner := bufio.NewScanner(output)
	if !scanner.Scan() {
		t.Fatal("private bus did not start")
	}
	address := scanner.Text()
	conn, err := dbus.Connect(address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	fake := &fakeService{}
	for _, target := range []struct {
		path  dbus.ObjectPath
		iface string
	}{
		{servicePath, serviceIF}, {testCollection, collectionIF}, {testCollection, "org.freedesktop.DBus.Properties"},
		{testItem, itemIF}, {testSession, "org.freedesktop.Secret.Session"},
	} {
		if err := conn.Export(fake, target.path, target.iface); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := conn.RequestName(destination, dbus.NameFlagDoNotQueue); err != nil {
		t.Fatal(err)
	}
	return secretService{address: address, timeout: time.Second}, fake, conn
}

func TestSecretServicePrivateRoundTripAndReplacement(t *testing.T) {
	backend, _, _ := privateService(t)
	for _, value := range [][]byte{[]byte("synthetic-unlock-secret"), []byte("replacement-unlock-secret")} {
		if err := backend.Set("synthetic-vault-id", value); err != nil {
			t.Fatal(err)
		}
		got, err := backend.Get("synthetic-vault-id")
		if err != nil || !bytes.Equal(got, value) {
			t.Fatal("private Secret Service round trip failed")
		}
		clear(got)
	}
	if _, err := backend.Get("other-vault-id"); err == nil {
		t.Fatal("unrelated vault entry returned")
	}
}

func TestSecretServiceLockedDuplicatePromptMissingAndTimeout(t *testing.T) {
	for _, mode := range []string{"locked", "duplicate", "prompt", "missing", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			backend, fake, conn := privateService(t)
			fake.mu.Lock()
			if mode != "prompt" {
				fake.account, fake.value = "vault", []byte("synthetic-unlock-secret")
			}
			switch mode {
			case "locked":
				fake.locked = true
			case "duplicate":
				fake.duplicate = true
			case "prompt":
				fake.prompt = true
			case "timeout":
				fake.delay = 80 * time.Millisecond
				backend.timeout = 20 * time.Millisecond
			}
			fake.mu.Unlock()
			if mode == "missing" {
				_, _ = conn.ReleaseName(destination)
			}
			if mode == "prompt" {
				if err := backend.Set("vault", []byte("synthetic-unlock-secret")); err == nil {
					t.Fatal("interactive prompt accepted")
				}
			} else if _, err := backend.Get("vault"); err == nil {
				t.Fatal("unavailable keyring accepted")
			}
		})
	}
}
