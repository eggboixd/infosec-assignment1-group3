// Package minio provides the MinIO-backed object store used for encrypted
// file variants. Only ciphertext is ever written here.
package minio

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// partSize bounds memory per upload when the object size is unknown.
// Without it, minio-go sizes parts for a 5 TiB object (about 512 MiB each).
const partSize = 16 << 20

// Store is a bucket in MinIO. It satisfies files.ObjectStore.
type Store struct {
	client    *minio.Client
	transport *http.Transport
	bucket    string
}

// Config holds the connection settings for New.
type Config struct {
	Endpoint  string
	AccessKey string
	SecretKey string
	UseSSL    bool
	Bucket    string
}

// New creates a client. It does not contact the server; call EnsureBucket.
func New(cfg Config) (*Store, error) {
	tr, err := minio.DefaultTransport(cfg.UseSSL)
	if err != nil {
		return nil, fmt.Errorf("minio: transport: %w", err)
	}
	client, err := minio.New(cfg.Endpoint, &minio.Options{
		Creds:     credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""),
		Secure:    cfg.UseSSL,
		Transport: tr,
	})
	if err != nil {
		return nil, fmt.Errorf("minio: new client: %w", err)
	}
	return &Store{client: client, transport: tr, bucket: cfg.Bucket}, nil
}

// EnsureBucket creates the bucket if it does not exist. In Docker Compose
// the minio-init service creates it first; this covers local runs.
func (s *Store) EnsureBucket(ctx context.Context) error {
	exists, err := s.client.BucketExists(ctx, s.bucket)
	if err != nil {
		return fmt.Errorf("minio: check bucket: %w", err)
	}
	if exists {
		return nil
	}
	if err := s.client.MakeBucket(ctx, s.bucket, minio.MakeBucketOptions{}); err != nil {
		return fmt.Errorf("minio: create bucket: %w", err)
	}
	return nil
}

// Ping checks that the server is reachable and the bucket exists.
func (s *Store) Ping(ctx context.Context) error {
	exists, err := s.client.BucketExists(ctx, s.bucket)
	if err != nil {
		return fmt.Errorf("minio: ping: %w", err)
	}
	if !exists {
		return errors.New("minio: bucket does not exist")
	}
	return nil
}

// Put streams r into key. Pass size -1 when the length is unknown.
func (s *Store) Put(ctx context.Context, key string, r io.Reader, size int64, contentType string) error {
	_, err := s.client.PutObject(ctx, s.bucket, key, r, size, minio.PutObjectOptions{
		ContentType: contentType,
		PartSize:    partSize,
	})
	if err != nil {
		return fmt.Errorf("minio: put %s: %w", key, err)
	}
	return nil
}

// Get opens key for reading. The returned object supports Seek, so callers
// can verify the MAC in one pass, seek to the start, and decrypt in a
// second pass. The caller must Close it.
func (s *Store) Get(ctx context.Context, key string) (io.ReadSeekCloser, error) {
	obj, err := s.client.GetObject(ctx, s.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("minio: get %s: %w", key, err)
	}
	// GetObject is lazy; Stat surfaces a missing object now, not on Read.
	if _, err := obj.Stat(); err != nil {
		_ = obj.Close()
		return nil, fmt.Errorf("minio: stat %s: %w", key, err)
	}
	return obj, nil
}

// Delete removes key. Deleting a missing key is not an error.
func (s *Store) Delete(ctx context.Context, key string) error {
	if err := s.client.RemoveObject(ctx, s.bucket, key, minio.RemoveObjectOptions{}); err != nil {
		return fmt.Errorf("minio: delete %s: %w", key, err)
	}
	return nil
}

// Close releases idle HTTP connections. minio-go keeps no other state.
func (s *Store) Close() {
	s.transport.CloseIdleConnections()
}
