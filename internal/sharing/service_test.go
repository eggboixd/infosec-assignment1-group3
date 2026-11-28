package sharing

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/eggboixd/infosec-assignment1-group3/internal/auth"
)

var t0 = time.Date(2026, 11, 28, 10, 0, 0, 0, time.UTC)

type env struct {
	svc   *Service
	store *memStore
	keys  *fakeKeys
	g     *fakeGranter
	users fakeUsers
	now   time.Time
}

func newEnv(t *testing.T, extraUsers ...string) *env {
	t.Helper()
	users := fakeUsers{}
	for _, n := range append([]string{"vinno", "rayen", "kenzie"}, extraUsers...) {
		users[n] = &auth.User{ID: bson.NewObjectID(), Username: n}
	}
	e := &env{store: newMemStore(), keys: &fakeKeys{errs: map[bson.ObjectID]error{}}, g: &fakeGranter{}, users: users, now: t0}
	e.svc = NewService(e.store, users, e.keys, e.g)
	e.svc.SetClock(func() time.Time { return e.now })
	return e
}

func (e *env) u(name string) *auth.User { return e.users[name] }

func (e *env) advance(d time.Duration) { e.now = e.now.Add(d) }

// send sends from -> to and fails the test on error.
func (e *env) send(t *testing.T, from, to string) *Request {
	t.Helper()
	r, err := e.svc.Send(context.Background(), e.u(from), to, "")
	if err != nil {
		t.Fatalf("Send %s -> %s: %v", from, to, err)
	}
	return r
}

func TestSend(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name    string
		setup   func(t *testing.T, e *env) // runs before the send under test
		to      string
		reason  string
		wantErr error
		check   func(t *testing.T, e *env, r *Request)
	}{
		{name: "ok", to: "rayen", reason: "  for the committee review ", check: func(t *testing.T, e *env, r *Request) {
			got := e.store.get(r.ID)
			if got.Status != StatusPending || !got.ExpiresAt.Equal(t0.Add(168*time.Hour)) {
				t.Fatalf("stored %+v", got)
			}
			if got.Reason != "for the committee review" || got.OwnerName != "rayen" || got.RequesterName != "vinno" {
				t.Fatalf("stored %+v", got)
			}
			if got.OwnerID != e.u("rayen").ID || got.RequesterID != e.u("vinno").ID || !got.CreatedAt.Equal(t0) {
				t.Fatalf("stored %+v", got)
			}
		}},
		{name: "username is normalised", to: "  Rayen ", check: func(t *testing.T, e *env, r *Request) {
			if r.OwnerName != "rayen" || r.OwnerID != e.u("rayen").ID {
				t.Fatalf("got %+v", r)
			}
		}},
		{name: "self", to: "vinno", wantErr: ErrSelfRequest},
		{name: "self in another case", to: " VINNO", wantErr: ErrSelfRequest},
		{name: "unknown user", to: "nobody", wantErr: ErrUserNotFound},
		{name: "empty username", to: "  ", wantErr: ErrUserNotFound},
		{name: "reason 201 runes", to: "rayen", reason: strings.Repeat("é", 201), wantErr: ErrReasonTooLong},
		{name: "reason 200 runes", to: "rayen", reason: strings.Repeat("é", 200)},
		{name: "duplicate pending", to: "rayen", wantErr: ErrAlreadyOpen,
			setup: func(t *testing.T, e *env) { e.send(t, "vinno", "rayen") }},
		{name: "after rejected", to: "rayen", setup: func(t *testing.T, e *env) {
			r := e.send(t, "vinno", "rayen")
			e.store.set(r.ID, func(r *Request) { r.Status = StatusRejected })
		}},
		{name: "after cancelled", to: "rayen", setup: func(t *testing.T, e *env) {
			r := e.send(t, "vinno", "rayen")
			e.store.set(r.ID, func(r *Request) { r.Status = StatusCancelled })
		}},
		{name: "after pending lapsed", to: "rayen", setup: func(t *testing.T, e *env) {
			e.send(t, "vinno", "rayen")
			e.advance(PendingLifetime)
		}},
		{name: "after approved expired", to: "rayen", setup: func(t *testing.T, e *env) {
			r := e.send(t, "vinno", "rayen")
			e.store.set(r.ID, func(r *Request) { r.Status = StatusApproved; r.ExpiresAt = t0.Add(time.Hour) })
			e.advance(2 * time.Hour)
		}, check: func(t *testing.T, e *env, _ *Request) {
			reqs, _ := e.store.List(context.Background(), actorRequester, e.u("vinno").ID, ListLimit)
			old := reqs[len(reqs)-1]
			if old.Status != StatusExpired || old.EndedAt == nil || !old.EndedAt.Equal(t0.Add(time.Hour)) {
				t.Fatalf("old request %+v, want stored expired with EndedAt=ExpiresAt", old)
			}
			if n := e.g.destroyCount(old.ID); n != 1 {
				t.Fatalf("Destroy called %d times for the expired approval, want 1", n)
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t)
			if tt.setup != nil {
				tt.setup(t, e)
			}
			r, err := e.svc.Send(ctx, e.u("vinno"), tt.to, tt.reason)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("err = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Send: %v", err)
			}
			if tt.check != nil {
				tt.check(t, e, r)
			}
		})
	}
}

func TestSendPendingCap(t *testing.T) {
	var names []string
	for i := range MaxPendingOutgoing + 1 {
		names = append(names, fmt.Sprintf("user%02d", i))
	}
	e := newEnv(t, names...)
	for i, n := range names[:MaxPendingOutgoing] {
		if i > 0 && i%sendLimit == 0 {
			e.advance(sendWindow)
		}
		e.send(t, "vinno", n)
	}
	e.advance(sendWindow)
	_, err := e.svc.Send(context.Background(), e.u("vinno"), names[MaxPendingOutgoing], "")
	if !errors.Is(err, ErrTooManyPending) {
		t.Fatalf("21st pending: err = %v, want ErrTooManyPending", err)
	}
}

func TestSendRateLimit(t *testing.T) {
	var names []string
	for i := range sendLimit + 1 {
		names = append(names, fmt.Sprintf("user%02d", i))
	}
	e := newEnv(t, names...)
	for _, n := range names[:sendLimit] {
		e.send(t, "vinno", n)
	}
	_, err := e.svc.Send(context.Background(), e.u("vinno"), names[sendLimit], "")
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("11th send: err = %v, want ErrRateLimited", err)
	}
	e.advance(sendWindow)
	e.send(t, "vinno", names[sendLimit])
}

func TestInboxAndSent(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	fromVinno := e.send(t, "vinno", "rayen")
	e.advance(time.Minute)
	fromKenzie := e.send(t, "kenzie", "rayen")
	e.advance(time.Minute)
	toKenzie := e.send(t, "vinno", "kenzie")
	e.keys.errs[e.u("kenzie").ID] = errFake

	inbox, err := e.svc.Inbox(ctx, e.u("rayen").ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(inbox) != 2 || inbox[0].ID != fromKenzie.ID || inbox[1].ID != fromVinno.ID {
		t.Fatalf("rayen's inbox = %+v, want kenzie's then vinno's", inbox)
	}
	if inbox[1].Fingerprint != fingerprintOf(e.u("vinno").ID) || inbox[1].KeyProblem {
		t.Fatalf("vinno's row: fingerprint %q, KeyProblem %v", inbox[1].Fingerprint, inbox[1].KeyProblem)
	}
	if inbox[0].Fingerprint != "" || !inbox[0].KeyProblem {
		t.Fatalf("kenzie's row: fingerprint %q, KeyProblem %v; want empty and true", inbox[0].Fingerprint, inbox[0].KeyProblem)
	}

	sent, err := e.svc.Sent(ctx, e.u("vinno").ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(sent) != 2 || sent[0].ID != toKenzie.ID || sent[1].ID != fromVinno.ID {
		t.Fatalf("vinno's sent = %+v", sent)
	}

	// An approval that expired is shown and then stored as expired, and its
	// share material is destroyed.
	e.store.set(fromVinno.ID, func(r *Request) { r.Status = StatusApproved; r.ExpiresAt = e.now.Add(time.Hour) })
	e.advance(time.Hour)
	inbox, err = e.svc.Inbox(ctx, e.u("rayen").ID)
	if err != nil {
		t.Fatal(err)
	}
	if inbox[1].Status != StatusExpired {
		t.Fatalf("effective status = %q, want expired", inbox[1].Status)
	}
	if got := e.store.get(fromVinno.ID).Status; got != StatusExpired {
		t.Fatalf("stored status = %q, want expired", got)
	}
	if n := e.g.destroyCount(fromVinno.ID); n != 1 {
		t.Fatalf("Destroy called %d times, want 1", n)
	}
}
