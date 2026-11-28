package sharing

import (
	"context"
	"log/slog"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// StubGranter makes no share key. It lets the request lifecycle run and be
// demoed before feature/share-keys is merged.
//
// TODO(feature/share-keys): replace with the real Granter in cmd/server/main.go.
type StubGranter struct{}

// Grant only logs.
func (StubGranter) Grant(_ context.Context, g Grant) error {
	slog.Warn("sharing: share-keys not wired yet", "request_id", g.RequestID.Hex())
	return nil
}

// Destroy only logs.
func (StubGranter) Destroy(_ context.Context, requestID bson.ObjectID) error {
	slog.Warn("sharing: share-keys not wired yet", "request_id", requestID.Hex())
	return nil
}
