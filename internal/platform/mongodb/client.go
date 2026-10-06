// Package mongodb connects to MongoDB and prepares the database schema.
package mongodb

import (
	"context"
	"fmt"

	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
)

// Client wraps a connected MongoDB client and the application database.
type Client struct {
	client *mongo.Client
	db     *mongo.Database
}

// Connect opens a client for uri, verifies it with a ping, and selects
// database. The URI may contain credentials, so it is never logged or
// included in errors.
func Connect(ctx context.Context, uri, database string) (*Client, error) {
	client, err := mongo.Connect(options.Client().ApplyURI(uri))
	if err != nil {
		return nil, fmt.Errorf("mongodb: connect: %w", err)
	}
	if err := client.Ping(ctx, readpref.Primary()); err != nil {
		_ = client.Disconnect(context.Background())
		return nil, fmt.Errorf("mongodb: ping: %w", err)
	}
	return &Client{client: client, db: client.Database(database)}, nil
}

// Database returns the application database.
func (c *Client) Database() *mongo.Database {
	return c.db
}

// Ping checks that the primary is reachable. It satisfies the health check.
func (c *Client) Ping(ctx context.Context) error {
	return c.client.Ping(ctx, readpref.Primary())
}

// Close disconnects, waiting for in-use connections until ctx is done.
func (c *Client) Close(ctx context.Context) error {
	return c.client.Disconnect(ctx)
}
