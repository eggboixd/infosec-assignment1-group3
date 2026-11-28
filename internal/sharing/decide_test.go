package sharing

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// pendingFromVinno returns an env with one pending request vinno -> rayen.
func pendingFromVinno(t *testing.T) (*env, *Request) {
	t.Helper()
	e := newEnv(t)
	return e, e.send(t, "vinno", "rayen")
}

func TestApprove(t *testing.T) {
	ctx := context.Background()

	t.Run("ok", func(t *testing.T) {
		e, r := pendingFromVinno(t)
		e.advance(time.Hour)
		got, err := e.svc.Approve(ctx, e.u("rayen").ID, r.ID, "1d")
		if err != nil {
			t.Fatal(err)
		}
		want := e.now.Add(24 * time.Hour)
		st := e.store.get(r.ID)
		if st.Status != StatusApproved || !st.ExpiresAt.Equal(want) || st.DecidedAt == nil || !st.DecidedAt.Equal(e.now) {
			t.Fatalf("stored %+v", st)
		}
		if got.Status != StatusApproved || !got.ExpiresAt.Equal(want) {
			t.Fatalf("returned %+v", got)
		}
		wantGrant := Grant{RequestID: r.ID, OwnerID: e.u("rayen").ID, RequesterID: e.u("vinno").ID, ExpiresAt: want}
		if len(e.g.grants) != 1 || e.g.grants[0] != wantGrant {
			t.Fatalf("grants = %+v, want [%+v]", e.g.grants, wantGrant)
		}
		if len(e.g.destroyed) != 0 {
			t.Fatalf("destroyed = %v, want none", e.g.destroyed)
		}
	})

	t.Run("default duration is 7 days", func(t *testing.T) {
		e, r := pendingFromVinno(t)
		got, err := e.svc.Approve(ctx, e.u("rayen").ID, r.ID, "")
		if err != nil || !got.ExpiresAt.Equal(e.now.Add(7*24*time.Hour)) {
			t.Fatalf("got %+v, %v", got, err)
		}
	})

	failures := []struct {
		name    string
		prepare func(e *env, r *Request) (actor, id bson.ObjectID, dur string)
		wantErr error
	}{
		{"bad duration", func(e *env, r *Request) (bson.ObjectID, bson.ObjectID, string) {
			return e.u("rayen").ID, r.ID, "2d"
		}, ErrBadDuration},
		{"requester key problem", func(e *env, r *Request) (bson.ObjectID, bson.ObjectID, string) {
			e.keys.errs[e.u("vinno").ID] = errFake
			return e.u("rayen").ID, r.ID, "7d"
		}, ErrRequesterKeys},
		{"requester tries", func(e *env, r *Request) (bson.ObjectID, bson.ObjectID, string) {
			return e.u("vinno").ID, r.ID, "7d"
		}, ErrNotFound},
		{"stranger tries", func(e *env, r *Request) (bson.ObjectID, bson.ObjectID, string) {
			return e.u("kenzie").ID, r.ID, "7d"
		}, ErrNotFound},
		{"unknown request", func(e *env, _ *Request) (bson.ObjectID, bson.ObjectID, string) {
			return e.u("rayen").ID, bson.NewObjectID(), "7d"
		}, ErrNotFound},
		{"already rejected", func(e *env, r *Request) (bson.ObjectID, bson.ObjectID, string) {
			e.store.set(r.ID, func(r *Request) { r.Status = StatusRejected })
			return e.u("rayen").ID, r.ID, "7d"
		}, ErrNotPending},
		{"lapsed", func(e *env, r *Request) (bson.ObjectID, bson.ObjectID, string) {
			e.advance(PendingLifetime)
			return e.u("rayen").ID, r.ID, "7d"
		}, ErrExpired},
	}
	for _, tt := range failures {
		t.Run(tt.name, func(t *testing.T) {
			e, r := pendingFromVinno(t)
			actor, id, dur := tt.prepare(e, r)
			if _, err := e.svc.Approve(ctx, actor, id, dur); !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if len(e.g.grants) != 0 {
				t.Fatalf("Grant called %d times, want 0", len(e.g.grants))
			}
		})
	}

	t.Run("grant fails", func(t *testing.T) {
		e, r := pendingFromVinno(t)
		e.g.grantErr = errFake
		if _, err := e.svc.Approve(ctx, e.u("rayen").ID, r.ID, "7d"); !errors.Is(err, ErrGrant) {
			t.Fatalf("err = %v, want ErrGrant", err)
		}
		if st := e.store.get(r.ID).Status; st != StatusPending {
			t.Fatalf("status = %q, want pending", st)
		}
	})
}

func TestApproveExpiredBetweenLoadAndClick(t *testing.T) {
	e, r := pendingFromVinno(t)
	// The request lapses while Grant runs (RSA and re-wrapping take time).
	e.g.onGrant = func() { e.now = r.ExpiresAt }
	if _, err := e.svc.Approve(context.Background(), e.u("rayen").ID, r.ID, "7d"); !errors.Is(err, ErrExpired) {
		t.Fatalf("err = %v, want ErrExpired", err)
	}
	if n := e.g.destroyCount(r.ID); n != 1 {
		t.Fatalf("Destroy called %d times, want 1", n)
	}
	if st := e.store.get(r.ID).Status; st == StatusApproved {
		t.Fatal("stored status is approved")
	}
}

func TestApproveLostRaceToApproveKeepsMaterial(t *testing.T) {
	e, r := pendingFromVinno(t)
	e.store.beforeTransition = func(transition) {
		e.store.set(r.ID, func(r *Request) { r.Status = StatusApproved })
	}
	if _, err := e.svc.Approve(context.Background(), e.u("rayen").ID, r.ID, "7d"); !errors.Is(err, ErrNotPending) {
		t.Fatalf("err = %v, want ErrNotPending", err)
	}
	if n := e.g.destroyCount(r.ID); n != 0 {
		t.Fatalf("Destroy called %d times, want 0: the winner's material must stay", n)
	}
}

func TestApproveLostRaceToCancel(t *testing.T) {
	e, r := pendingFromVinno(t)
	e.store.beforeTransition = func(transition) {
		e.store.set(r.ID, func(r *Request) { r.Status = StatusCancelled })
	}
	if _, err := e.svc.Approve(context.Background(), e.u("rayen").ID, r.ID, "7d"); !errors.Is(err, ErrNotPending) {
		t.Fatalf("err = %v, want ErrNotPending", err)
	}
	if n := e.g.destroyCount(r.ID); n != 1 {
		t.Fatalf("Destroy called %d times, want 1", n)
	}
}

// decideCase is shared by TestReject and TestCancel.
type decideCase struct {
	name    string
	actor   string // user who acts
	prepare func(e *env, r *Request)
	wantErr error
}

func runDecide(t *testing.T, act func(e *env, actorID, id bson.ObjectID) error, okActor string, want Status, cases []decideCase) {
	t.Helper()
	for _, tt := range append([]decideCase{{name: "ok", actor: okActor}}, cases...) {
		t.Run(tt.name, func(t *testing.T) {
			e, r := pendingFromVinno(t)
			if tt.prepare != nil {
				tt.prepare(e, r)
			}
			err := act(e, e.u(tt.actor).ID, r.ID)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("err = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if st := e.store.get(r.ID).Status; st != want {
				t.Fatalf("status = %q, want %q", st, want)
			}
		})
	}
}

func TestReject(t *testing.T) {
	act := func(e *env, actorID, id bson.ObjectID) error { return e.svc.Reject(context.Background(), actorID, id) }
	runDecide(t, act, "rayen", StatusRejected, []decideCase{
		{name: "requester tries", actor: "vinno", wantErr: ErrNotFound},
		{name: "approved", actor: "rayen", wantErr: ErrNotPending,
			prepare: func(e *env, r *Request) { e.store.set(r.ID, func(r *Request) { r.Status = StatusApproved }) }},
		{name: "lapsed", actor: "rayen", wantErr: ErrExpired, prepare: func(e *env, _ *Request) { e.advance(PendingLifetime) }},
	})
}

func TestCancel(t *testing.T) {
	act := func(e *env, actorID, id bson.ObjectID) error { return e.svc.Cancel(context.Background(), actorID, id) }
	runDecide(t, act, "vinno", StatusCancelled, []decideCase{
		{name: "owner tries", actor: "rayen", wantErr: ErrNotFound},
		{name: "approved", actor: "vinno", wantErr: ErrNotPending,
			prepare: func(e *env, r *Request) { e.store.set(r.ID, func(r *Request) { r.Status = StatusApproved }) }},
		{name: "lapsed", actor: "vinno", wantErr: ErrExpired, prepare: func(e *env, _ *Request) { e.advance(PendingLifetime) }},
	})
}

// approved returns an env with vinno -> rayen approved for 7 days.
func approved(t *testing.T) (*env, *Request) {
	t.Helper()
	e, r := pendingFromVinno(t)
	got, err := e.svc.Approve(context.Background(), e.u("rayen").ID, r.ID, "7d")
	if err != nil {
		t.Fatal(err)
	}
	return e, got
}

func TestRevoke(t *testing.T) {
	ctx := context.Background()
	t.Run("ok", func(t *testing.T) {
		e, r := approved(t)
		if err := e.svc.Revoke(ctx, e.u("rayen").ID, r.ID); err != nil {
			t.Fatal(err)
		}
		st := e.store.get(r.ID)
		if st.Status != StatusRevoked || st.EndedAt == nil {
			t.Fatalf("stored %+v", st)
		}
		if n := e.g.destroyCount(r.ID); n != 1 {
			t.Fatalf("Destroy called %d times, want 1", n)
		}
	})
	t.Run("destroy fails, still revoked", func(t *testing.T) {
		e, r := approved(t)
		e.g.destroyErr = errFake
		if err := e.svc.Revoke(ctx, e.u("rayen").ID, r.ID); err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		if st := e.store.get(r.ID).Status; st != StatusRevoked {
			t.Fatalf("status = %q", st)
		}
	})
	t.Run("pending", func(t *testing.T) {
		e, r := pendingFromVinno(t)
		if err := e.svc.Revoke(ctx, e.u("rayen").ID, r.ID); !errors.Is(err, ErrNotApproved) {
			t.Fatalf("err = %v, want ErrNotApproved", err)
		}
	})
	t.Run("requester tries", func(t *testing.T) {
		e, r := approved(t)
		if err := e.svc.Revoke(ctx, e.u("vinno").ID, r.ID); !errors.Is(err, ErrNotFound) {
			t.Fatalf("err = %v, want ErrNotFound", err)
		}
	})
	t.Run("already expired", func(t *testing.T) {
		e, r := approved(t)
		e.now = r.ExpiresAt
		if err := e.svc.Revoke(ctx, e.u("rayen").ID, r.ID); !errors.Is(err, ErrExpired) {
			t.Fatalf("err = %v, want ErrExpired", err)
		}
	})
}

func TestActive(t *testing.T) {
	ctx := context.Background()
	t.Run("approved", func(t *testing.T) {
		e, r := approved(t)
		got, err := e.svc.Active(ctx, r.ID, e.u("vinno").ID)
		if err != nil || got.ID != r.ID {
			t.Fatalf("got %+v, %v", got, err)
		}
	})
	t.Run("at exactly expiry", func(t *testing.T) {
		e, r := approved(t)
		e.now = r.ExpiresAt
		if _, err := e.svc.Active(ctx, r.ID, e.u("vinno").ID); !errors.Is(err, ErrExpired) {
			t.Fatalf("err = %v, want ErrExpired", err)
		}
	})
	t.Run("owner's ID as requester", func(t *testing.T) {
		e, r := approved(t)
		if _, err := e.svc.Active(ctx, r.ID, e.u("rayen").ID); !errors.Is(err, ErrNotFound) {
			t.Fatalf("err = %v, want ErrNotFound", err)
		}
	})
	for _, s := range []Status{StatusPending, StatusRejected, StatusRevoked, StatusCancelled} {
		t.Run(string(s), func(t *testing.T) {
			e, r := pendingFromVinno(t)
			e.store.set(r.ID, func(r *Request) { r.Status = s })
			if _, err := e.svc.Active(ctx, r.ID, e.u("vinno").ID); !errors.Is(err, ErrNotApproved) {
				t.Fatalf("err = %v, want ErrNotApproved", err)
			}
		})
	}
}

// Final review I1: a write that MongoDB applied but reported as failed (a
// timeout) must not destroy the material of a now-approved request.
func TestApproveTransitionErrorAfterApplyKeepsMaterial(t *testing.T) {
	e, r := pendingFromVinno(t)
	e.store.transitionErr = func(transition) (bool, error) { return true, errFake }
	if _, err := e.svc.Approve(context.Background(), e.u("rayen").ID, r.ID, "7d"); err == nil {
		t.Fatal("Approve succeeded, want an error")
	}
	if st := e.store.get(r.ID).Status; st != StatusApproved {
		t.Fatalf("stored status = %q, want approved (the write was applied)", st)
	}
	if n := e.g.destroyCount(r.ID); n != 0 {
		t.Fatalf("Destroy called %d times, want 0", n)
	}
}

// A write that failed without applying leaves a pending request: its stray
// material may be destroyed.
func TestApproveTransitionErrorNotAppliedDestroys(t *testing.T) {
	e, r := pendingFromVinno(t)
	e.store.transitionErr = func(transition) (bool, error) { return false, errFake }
	if _, err := e.svc.Approve(context.Background(), e.u("rayen").ID, r.ID, "7d"); err == nil {
		t.Fatal("Approve succeeded, want an error")
	}
	if st := e.store.get(r.ID).Status; st != StatusPending {
		t.Fatalf("stored status = %q, want pending", st)
	}
	if n := e.g.destroyCount(r.ID); n != 1 {
		t.Fatalf("Destroy called %d times, want 1", n)
	}
}

// Final review I1, scenario B: a double click whose loser can't re-read the
// request must not destroy the winner's material.
func TestApproveLostRaceReReadFailsKeepsMaterial(t *testing.T) {
	e, r := pendingFromVinno(t)
	e.store.beforeTransition = func(transition) {
		e.store.set(r.ID, func(r *Request) { r.Status = StatusApproved })
		e.store.findErr = func() error { return errFake }
	}
	if _, err := e.svc.Approve(context.Background(), e.u("rayen").ID, r.ID, "7d"); err == nil {
		t.Fatal("Approve succeeded, want an error")
	}
	if n := e.g.destroyCount(r.ID); n != 0 {
		t.Fatalf("Destroy called %d times, want 0", n)
	}
}

// Final review M1: a cancelled request context (the user navigated away)
// must not stop the share material being deleted after a revoke.
func TestRevokeDestroysWithCancelledRequestContext(t *testing.T) {
	e, r := approved(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := e.svc.Revoke(ctx, e.u("rayen").ID, r.ID); err != nil {
		t.Fatal(err)
	}
	if len(e.g.destroyCtxErrs) != 1 || e.g.destroyCtxErrs[0] != nil {
		t.Fatalf("Destroy ctx errors = %v, want one call with a live context", e.g.destroyCtxErrs)
	}
}
