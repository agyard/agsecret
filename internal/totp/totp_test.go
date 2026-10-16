package totp

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"
)

func TestRFC6238Vectors(t *testing.T) {
	seeds := map[string]string{
		"SHA1":   "12345678901234567890",
		"SHA256": "12345678901234567890123456789012",
		"SHA512": "1234567890123456789012345678901234567890123456789012345678901234",
	}
	vectors := []struct {
		at                   int64
		sha1, sha256, sha512 string
	}{
		{59, "94287082", "46119246", "90693936"},
		{1111111109, "07081804", "68084774", "25091201"},
		{1111111111, "14050471", "67062674", "99943326"},
		{1234567890, "89005924", "91819424", "93441116"},
		{2000000000, "69279037", "90698825", "38618901"},
		{20000000000, "65353130", "77737706", "47863826"},
	}
	for _, v := range vectors {
		for algorithm, want := range map[string]string{"SHA1": v.sha1, "SHA256": v.sha256, "SHA512": v.sha512} {
			uri := "otpauth://totp/test?secret=" + base32.StdEncoding.EncodeToString([]byte(seeds[algorithm])) + "&algorithm=" + algorithm + "&digits=8&period=30"
			got, err := Generate(uri, time.Unix(v.at, 0))
			if err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Errorf("%s at %d = %s, want %s", algorithm, v.at, got, want)
			}
		}
	}
}

func TestRawSeedNormalizationAndDefaultCode(t *testing.T) {
	seed := strings.ToLower(base32.StdEncoding.EncodeToString([]byte("12345678901234567890")))
	seed = seed[:4] + " - \t" + seed[4:] + "==="
	got, err := Generate(seed, time.Unix(59, 0))
	if err != nil || got != "287082" {
		t.Fatalf("got %q, %v", got, err)
	}
	got, err = Generate("otpauth://totp/test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&period=60", time.Unix(119, 0))
	if err != nil || got != "287082" {
		t.Fatalf("custom period got %q, %v", got, err)
	}
}

func TestRejectInvalidSeedsAndURIParameters(t *testing.T) {
	for _, seed := range []string{
		"", "- ", "A", "not!base32", "GEZD=GNBV", "otpauth://hotp/test?secret=MY",
		"otpauth://totp/test", "otpauth://totp/test?secret=MY&secret=MY",
		"otpauth://totp/test?secret=MY&digits=7", "otpauth://totp/test?secret=MY&period=0",
		"otpauth://totp/test?secret=MY&period=-1", "otpauth://totp/test?secret=MY&algorithm=MD5",
		"otpauth://totp/test?secret=MY&algorithm=SHA1&algorithm=SHA256",
		"otpauth://totp/test?secret=MY&digits=6&digits=8",
		"otpauth://totp/test?secret=MY&period=30&period=0",
	} {
		if c, err := Parse(seed); err == nil {
			c.Clear()
			t.Errorf("accepted invalid seed %q", seed)
		}
	}
}
