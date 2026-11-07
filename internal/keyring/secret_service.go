//go:build linux || freebsd || openbsd || netbsd || dragonfly

package keyring

import (
	"context"
	"time"

	"github.com/godbus/dbus/v5"
)

const (
	destination  = "org.freedesktop.secrets"
	servicePath  = dbus.ObjectPath("/org/freedesktop/secrets")
	serviceIF    = "org.freedesktop.Secret.Service"
	itemIF       = "org.freedesktop.Secret.Item"
	collectionIF = "org.freedesktop.Secret.Collection"
)

type secretService struct {
	// address is only supplied by tests using a private bus.
	address string
	timeout time.Duration
}

type secret struct {
	Session     dbus.ObjectPath
	Parameters  []byte
	Value       []byte
	ContentType string
}

// New uses an already-running Secret Service. Missing/locked services and
// requests taking more than two seconds are unavailable, allowing file fallback.
func New() Backend { return secretService{timeout: 2 * time.Second} }

func (b secretService) connect(ctx context.Context) (*dbus.Conn, error) {
	var conn *dbus.Conn
	var err error
	if b.address != "" {
		conn, err = dbus.Dial(b.address, dbus.WithContext(ctx))
	} else {
		conn, err = dbus.SessionBusPrivateNoAutoStartup(dbus.WithContext(ctx))
	}
	if err != nil {
		return nil, ErrUnavailable
	}
	// WithContext cancels calls, but the authentication handshake also needs
	// its transport closed when the operation's deadline expires.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	if err = conn.Auth(nil); err == nil {
		err = conn.Hello()
	}
	stop()
	if err != nil {
		_ = conn.Close()
		return nil, ErrUnavailable
	}
	var owner bool
	err = conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.NameHasOwner", 0, destination).Store(&owner)
	if err != nil || !owner {
		_ = conn.Close()
		return nil, ErrUnavailable
	}
	return conn, nil
}

func attributes(account string) map[string]string {
	return map[string]string{"service": "agsecret", "vault": account}
}

func find(ctx context.Context, conn *dbus.Conn, account string) (dbus.ObjectPath, error) {
	var unlocked, locked []dbus.ObjectPath
	err := conn.Object(destination, servicePath).CallWithContext(ctx, serviceIF+".SearchItems", 0,
		attributes(account)).Store(&unlocked, &locked)
	if err != nil || len(locked) != 0 || len(unlocked) > 1 {
		return "", ErrUnavailable
	}
	if len(unlocked) == 1 {
		return unlocked[0], nil
	}
	return "/", nil
}

func openSession(ctx context.Context, conn *dbus.Conn) (dbus.ObjectPath, error) {
	var output dbus.Variant
	var path dbus.ObjectPath
	err := conn.Object(destination, servicePath).CallWithContext(ctx, serviceIF+".OpenSession", 0,
		"plain", dbus.MakeVariant("")).Store(&output, &path)
	if err != nil || path == "/" || !path.IsValid() {
		return "", ErrUnavailable
	}
	return path, nil
}

func (b secretService) Get(account string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), b.timeout)
	defer cancel()
	conn, err := b.connect(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	item, err := find(ctx, conn, account)
	if err != nil || item == "/" {
		return nil, ErrUnavailable
	}
	session, err := openSession(ctx, conn)
	if err != nil {
		return nil, err
	}
	defer conn.Object(destination, session).CallWithContext(ctx, "org.freedesktop.Secret.Session.Close", 0)
	var value secret
	err = conn.Object(destination, item).CallWithContext(ctx, itemIF+".GetSecret", 0, session).Store(&value)
	if err != nil || value.Session != session || len(value.Parameters) != 0 || len(value.Value) == 0 || len(value.Value) > 1<<20 {
		clear(value.Value)
		return nil, ErrUnavailable
	}
	return value.Value, nil
}

func (b secretService) Set(account string, passphrase []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), b.timeout)
	defer cancel()
	conn, err := b.connect(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	item, err := find(ctx, conn, account)
	if err != nil {
		return err
	}
	session, err := openSession(ctx, conn)
	if err != nil {
		return err
	}
	defer conn.Object(destination, session).CallWithContext(ctx, "org.freedesktop.Secret.Session.Close", 0)
	value := secret{Session: session, Parameters: []byte{}, Value: passphrase, ContentType: "application/octet-stream"}
	if item != "/" {
		if err := conn.Object(destination, item).CallWithContext(ctx, itemIF+".SetSecret", 0, value).Err; err != nil {
			return ErrUnavailable
		}
		return nil
	}
	var collection dbus.ObjectPath
	err = conn.Object(destination, servicePath).CallWithContext(ctx, serviceIF+".ReadAlias", 0, "default").Store(&collection)
	if err != nil || collection == "/" || !collection.IsValid() {
		return ErrUnavailable
	}
	var locked dbus.Variant
	err = conn.Object(destination, collection).CallWithContext(ctx, "org.freedesktop.DBus.Properties.Get", 0,
		collectionIF, "Locked").Store(&locked)
	if err != nil || locked.Value() != false {
		return ErrUnavailable
	}
	properties := map[string]dbus.Variant{
		itemIF + ".Label":      dbus.MakeVariant("AG-Secret vault unlock"),
		itemIF + ".Attributes": dbus.MakeVariant(attributes(account)),
	}
	var created, prompt dbus.ObjectPath
	err = conn.Object(destination, collection).CallWithContext(ctx, collectionIF+".CreateItem", 0,
		properties, value, true).Store(&created, &prompt)
	if err != nil || prompt != "/" || created == "/" || !created.IsValid() {
		return ErrUnavailable
	}
	return nil
}
