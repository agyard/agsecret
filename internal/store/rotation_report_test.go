package store

import (
	"errors"
	"slices"
	"sync"
	"testing"
	"time"
)

func TestPutReturnsNewIdentityAndPreservesUnchangedIncident(t *testing.T) {
	s := newTestStore(t)
	first, err := s.Put(Record{Name: "api", Secret: []byte("first-value"), AllowGet: true, AllowExec: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReportLeak(first.Record.ID, Leak{Reason: "exposed"}); err != nil {
		t.Fatal(err)
	}
	same, err := s.Put(Record{Name: first.Record.ID, Secret: []byte("first-value"), AllowGet: false}, map[string]bool{"allow-get": true})
	if err != nil {
		t.Fatal(err)
	}
	if same.Record.ID != first.Record.ID || len(same.Record.Leaks) != 1 || same.Record.AllowGet || !same.Record.AllowExec {
		t.Fatal("same value lost identity, history or policy")
	}
	rotated, err := s.Put(Record{Name: same.Record.ID, Secret: []byte("replacement-value")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !ValidID(rotated.Record.ID) || rotated.Record.ID == same.Record.ID || len(rotated.Record.Leaks) != 0 || len(rotated.Record.Secret) != 0 {
		t.Fatal("rotation result must contain the committed new ID without plaintext or old incidents")
	}
	if rotated.Record.AllowGet || !rotated.Record.AllowExec {
		t.Fatal("rotation changed omitted policies")
	}
	if _, err := s.GetByNameOrID(same.Record.ID, true); !errors.Is(err, ErrNotFound) {
		t.Fatal("old ID still resolves", err)
	}
	if _, err := s.ReportLeak(same.Record.ID, Leak{Reason: "late old incident"}); !errors.Is(err, ErrNotFound) {
		t.Fatal("stale report applied to replacement", err)
	}
	current, err := s.GetByNameOrID("api", false)
	if err != nil || current.ID != rotated.Record.ID || len(current.Leaks) != 0 {
		t.Fatal("stale report changed current credential", err)
	}
}

func TestReportIDAndNameCoverEveryMatchingPass(t *testing.T) {
	s := newTestStore(t)
	seed := []byte("JBSWY3DPEHPK3PXP")
	past := time.Now().Add(-time.Hour)
	a, err := s.Put(Record{Name: "primary", Type: "pass", Secret: seed, AllowGet: true, AllowExec: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.Put(Record{Name: "retired", Type: "pass", Secret: seed, ExpiresAt: &past}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(b.DuplicateIDs, []string{a.Record.ID}) {
		t.Fatal("duplicate put missing committed matching ID", b.DuplicateIDs)
	}
	for _, r := range []Record{{Name: "otp", Type: "totp", Secret: seed}, {Name: "other", Type: "pass", Secret: []byte("unrelated")}} {
		if _, err := s.Put(r, nil); err != nil {
			t.Fatal(err)
		}
	}
	leak := Leak{Reason: "exposure", Context: "same bytes", Attachments: []string{"shot.png"}}
	for i, ref := range []string{a.Record.ID, "retired"} {
		records, err := s.ReportLeak(ref, leak)
		if err != nil || len(records) != 2 {
			t.Fatal("report did not cover both passwords", err)
		}
		for _, r := range records {
			if len(r.Leaks) != i+1 || len(r.Secret) != 0 {
				t.Fatal("history or report response changed")
			}
			if r.ID == a.Record.ID && (!r.AllowGet || !r.AllowExec) {
				t.Fatal("report disabled policy")
			}
			if r.ID == b.Record.ID && (r.AllowGet || r.AllowExec) {
				t.Fatal("report enabled policy")
			}
		}
	}
	records, err := s.ReportSecret(seed, leak)
	if err != nil || len(records) != 2 {
		t.Fatal("stdin equivalent did not cover both pass records", err)
	}
	for _, ref := range []string{"otp", "other"} {
		r, err := s.GetByNameOrID(ref, false)
		if err != nil || len(r.Leaks) != 0 {
			t.Fatal("unrelated/TOTP history changed", err)
		}
	}
	if _, err := s.ReportLeak("otp", leak); err == nil {
		t.Fatal("TOTP report accepted")
	}
	if _, err := s.Put(Record{Name: a.Record.ID, Secret: []byte("rotated")}, nil); err != nil {
		t.Fatal(err)
	}
	r, err := s.GetByNameOrID(b.Record.ID, false)
	if err != nil || len(r.Leaks) != 3 {
		t.Fatal("rotating one password cleared another's history", err)
	}
}

func TestConcurrentDuplicatePutsObserveEachOther(t *testing.T) {
	first := newTestStore(t)
	second, err := Open(first.Path, []byte("test passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	start := make(chan struct{})
	results := make(chan PutResult, 2)
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for i, s := range []*Store{first, second} {
		wg.Add(1)
		go func(i int, s *Store) {
			defer wg.Done()
			<-start
			r, err := s.Put(Record{Name: []string{"first", "second"}[i], Secret: []byte("shared-value")}, nil)
			results <- r
			errs <- err
		}(i, s)
	}
	close(start)
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	observed := 0
	for r := range results {
		observed += len(r.DuplicateIDs)
	}
	if observed != 1 {
		t.Fatal("concurrent puts missed or duplicated warning", observed)
	}
}
