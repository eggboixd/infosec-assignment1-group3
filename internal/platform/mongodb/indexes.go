package mongodb

import (
	"context"
	"fmt"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// Collection names. main.go passes each feature store its collection, so
// feature packages never import this package.
const (
	UsersCollection         = "users"
	ProfilesCollection      = "profiles"
	FilesCollection         = "files"
	BenchmarksCollection    = "benchmarks"
	SessionsCollection      = "sessions"
	ApplicationsCollection  = "applications"
	KeypairsCollection      = "keypairs"
	ShareRequestsCollection = "share_requests"
	ShareKeysCollection     = "share_keys"
)

// indexes lists the indexes each collection needs. CreateMany is idempotent
// for identical definitions, so this runs safely on every startup.
func indexes() map[string][]mongo.IndexModel {
	return map[string][]mongo.IndexModel{
		UsersCollection: {
			{Keys: bson.D{{Key: "username", Value: 1}}, Options: options.Index().SetName("username_unique").SetUnique(true)},
		},
		ProfilesCollection: {
			{Keys: bson.D{{Key: "user_id", Value: 1}}, Options: options.Index().SetName("user_id_unique").SetUnique(true)},
			// Sparse so profiles saved before a NIK is set do not collide.
			{Keys: bson.D{{Key: "nik_index", Value: 1}}, Options: options.Index().SetName("nik_index_unique").SetUnique(true).SetSparse(true)},
		},
		FilesCollection: {
			{Keys: bson.D{{Key: "owner_id", Value: 1}, {Key: "created_at", Value: -1}}, Options: options.Index().SetName("owner_created")},
		},
		BenchmarksCollection: {
			{Keys: bson.D{{Key: "created_at", Value: -1}}, Options: options.Index().SetName("created")},
			{Keys: bson.D{{Key: "algorithm", Value: 1}, {Key: "operation", Value: 1}}, Options: options.Index().SetName("alg_op")},
		},
		ApplicationsCollection: {
			// One application per student and scholarship, via the blind index (D38).
			{Keys: bson.D{{Key: "index", Value: 1}}, Options: options.Index().SetName("index_unique").SetUnique(true)},
			{Keys: bson.D{{Key: "user_id", Value: 1}}, Options: options.Index().SetName("user_id")},
		},
		KeypairsCollection: {
			// One key-pair document per user. The unique index also makes
			// concurrent EnsureKeys calls keep exactly one set (D43).
			{Keys: bson.D{{Key: "user_id", Value: 1}}, Options: options.Index().SetName("user_id_unique").SetUnique(true)},
		},
		ShareRequestsCollection: {
			// At most one pending or approved request per (requester, owner)
			// (docs/decisions.md D56). Expired rows still stored as approved
			// are marked expired before a new request is inserted.
			{Keys: bson.D{{Key: "requester_id", Value: 1}, {Key: "owner_id", Value: 1}}, Options: options.Index().SetName("open_pair_unique").SetUnique(true).
				SetPartialFilterExpression(bson.D{{Key: "status", Value: bson.D{{Key: "$in", Value: bson.A{"pending", "approved"}}}}})},
			{Keys: bson.D{{Key: "owner_id", Value: 1}, {Key: "created_at", Value: -1}}, Options: options.Index().SetName("owner_created")},
			{Keys: bson.D{{Key: "requester_id", Value: 1}, {Key: "created_at", Value: -1}}, Options: options.Index().SetName("requester_created")},
		},
		// One set of share material per request. The unique index makes
		// Grant create-if-absent when two approves race (docs/sharekeys.md).
		ShareKeysCollection: {
			{Keys: bson.D{{Key: "request_id", Value: 1}}, Options: options.Index().SetName("request_id_unique").SetUnique(true)},
		},
		// auth.SessionStore writes "expires_at" as a date, so this TTL index
		// removes expired sessions.
		SessionsCollection: {
			{Keys: bson.D{{Key: "expires_at", Value: 1}}, Options: options.Index().SetName("expires_ttl").SetExpireAfterSeconds(0)},
		},
	}
}

// EnsureIndexes creates every index the application relies on.
func EnsureIndexes(ctx context.Context, db *mongo.Database) error {
	for coll, models := range indexes() {
		if _, err := db.Collection(coll).Indexes().CreateMany(ctx, models); err != nil {
			return fmt.Errorf("mongodb: create indexes on %s: %w", coll, err)
		}
	}
	return nil
}
