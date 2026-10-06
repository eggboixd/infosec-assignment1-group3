// Command server runs the encrypted file-storage web application.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/eggboixd/infosec-assignment1-group3/internal/auth"
	"github.com/eggboixd/infosec-assignment1-group3/internal/benchmark"
	"github.com/eggboixd/infosec-assignment1-group3/internal/config"
	"github.com/eggboixd/infosec-assignment1-group3/internal/crypto"
	"github.com/eggboixd/infosec-assignment1-group3/internal/files"
	"github.com/eggboixd/infosec-assignment1-group3/internal/platform/minio"
	"github.com/eggboixd/infosec-assignment1-group3/internal/platform/mongodb"
	"github.com/eggboixd/infosec-assignment1-group3/internal/profile"
	"github.com/eggboixd/infosec-assignment1-group3/internal/web"
)

// startupTimeout bounds connecting to and preparing MongoDB and MinIO.
const startupTimeout = 30 * time.Second

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	if err := run(); err != nil {
		slog.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	// Cancelled on SIGINT or SIGTERM.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	startCtx, cancel := context.WithTimeout(ctx, startupTimeout)
	defer cancel()

	mongo, err := mongodb.Connect(startCtx, cfg.MongoURI, cfg.MongoDatabase)
	if err != nil {
		return err
	}
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		defer cancel()
		if err := mongo.Close(closeCtx); err != nil {
			slog.Error("close mongodb", "error", err)
		}
	}()
	if err := mongodb.EnsureIndexes(startCtx, mongo.Database()); err != nil {
		return err
	}

	objects, err := minio.New(minio.Config{
		Endpoint:  cfg.MinIOEndpoint,
		AccessKey: cfg.MinIOAccessKey,
		SecretKey: cfg.MinIOSecretKey,
		UseSSL:    cfg.MinIOUseSSL,
		Bucket:    cfg.MinIOBucket,
	})
	if err != nil {
		return err
	}
	defer objects.Close()
	if err := objects.EnsureBucket(startCtx); err != nil {
		return err
	}

	// TODO(feature/crypto-core): replace PassthroughEncryptor with the real
	// Encryptor built from cfg.MasterKey.
	var enc crypto.Encryptor = crypto.PassthroughEncryptor{}

	// TODO(feature/private-data): derive with
	// crypto.DeriveKey(cfg.MasterKey, "nik-blind-index") once implemented.
	var nikBlindKey []byte

	db := mongo.Database()
	benchStore := benchmark.NewStore(db.Collection(mongodb.BenchmarksCollection))

	authSvc := auth.NewService(auth.NewStore(db.Collection(mongodb.UsersCollection)))
	profileSvc := profile.NewService(profile.NewStore(db.Collection(mongodb.ProfilesCollection)), enc, nikBlindKey)
	filesSvc := files.NewService(files.NewStore(db.Collection(mongodb.FilesCollection)), objects, enc, benchStore)

	engine, err := web.NewEngine(web.Options{
		Mode:         cfg.GinMode,
		MaxBodyBytes: cfg.MaxBodyBytes,
		HealthChecks: []web.HealthCheck{
			{Name: "mongodb", Pinger: mongo},
			{Name: "minio", Pinger: objects},
		},
		Features: []web.RouteRegistrar{
			auth.NewHandler(authSvc),
			profile.NewHandler(profileSvc),
			files.NewHandler(filesSvc),
			benchmark.NewHandler(benchStore),
		},
	})
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           engine,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		// No ReadTimeout or WriteTimeout: large video uploads and downloads
		// are streamed and can legitimately take minutes.
	}

	serveErr := make(chan error, 1)
	go func() {
		slog.Info("server listening", "addr", cfg.HTTPAddr)
		serveErr <- srv.ListenAndServe()
	}()

	select {
	case err := <-serveErr:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case <-ctx.Done():
	}

	slog.Info("shutting down", "timeout", cfg.ShutdownTimeout.String())
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancelShutdown()
	// Shutdown stops accepting connections and waits for in-flight requests.
	// The deferred calls above then close the MinIO and MongoDB clients.
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return err
	}
	slog.Info("server stopped cleanly")
	return nil
}
