package db

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog/log"
	libsql "github.com/tursodatabase/go-libsql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// openTurso opens a Turso database connection based on the configured mode.
// It supports three modes:
// - local: Just a local database file (embedded)
// - embedded-replica: Local SQLite file that syncs with Turso Cloud
// - remote: Direct connection to Turso Cloud
func openTurso(cfg types.DatabaseConfig, dbLogger logger.Interface) (*gorm.DB, error) {
	mode := cfg.Turso.Mode
	if mode == "" {
		mode = "local"
	}

	switch mode {
	case "local":
		return openTursoLocal(cfg, dbLogger)
	case "embedded-replica":
		return openTursoEmbeddedReplica(cfg, dbLogger)
	case "remote":
		return openTursoRemote(cfg, dbLogger)
	default:
		return nil, fmt.Errorf("invalid turso mode %q, must be 'local', 'embedded-replica', or 'remote'", mode)
	}
}

// openTursoLocal opens a local-only Turso database (just a local file, no sync).
func openTursoLocal(cfg types.DatabaseConfig, dbLogger logger.Interface) (*gorm.DB, error) {
	if cfg.Turso.Path == "" {
		return nil, fmt.Errorf("turso.path must be set when using 'local' mode")
	}

	dir := filepath.Dir(cfg.Turso.Path)
	err := util.EnsureDir(dir)
	if err != nil {
		return nil, fmt.Errorf("creating directory for turso local database: %w", err)
	}

	log.Info().
		Str("database", types.DatabaseTurso).
		Str("mode", "local").
		Str("path", cfg.Turso.Path).
		Msg("Opening Turso database in local mode")

	// Local mode uses standard SQLite connection
	// Note: We're using the glebarez/sqlite driver which is compatible
	connectionURL := cfg.Turso.Path

	// Add SQLite pragmas for WAL mode if enabled
	if cfg.Turso.WriteAheadLog {
		connectionURL += "?_journal_mode=WAL"
		if cfg.Turso.WALAutoCheckPoint > 0 {
			connectionURL += fmt.Sprintf("&_wal_autocheckpoint=%d", cfg.Turso.WALAutoCheckPoint)
		}
	}

	db, err := gorm.Open(
		sqlite.Open(connectionURL),
		&gorm.Config{
			PrepareStmt: cfg.Gorm.PrepareStmt,
			Logger:      dbLogger,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("opening turso local database: %w", err)
	}

	// Configure connection pool (same as SQLite)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxIdleConns(1)
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetConnMaxIdleTime(time.Hour)

	return db, nil
}

// openTursoEmbeddedReplica opens a Turso embedded replica (local file + cloud sync).
// This requires the go-libsql package which uses CGO.
func openTursoEmbeddedReplica(cfg types.DatabaseConfig, dbLogger logger.Interface) (*gorm.DB, error) {
	if cfg.Turso.Path == "" {
		return nil, fmt.Errorf("turso.path must be set when using 'embedded-replica' mode")
	}
	if cfg.Turso.URL == "" {
		return nil, fmt.Errorf("turso.url must be set when using 'embedded-replica' mode")
	}
	if cfg.Turso.AuthToken == "" {
		return nil, fmt.Errorf("turso.auth_token must be set when using 'embedded-replica' mode")
	}

	dir := filepath.Dir(cfg.Turso.Path)
	err := util.EnsureDir(dir)
	if err != nil {
		return nil, fmt.Errorf("creating directory for turso embedded replica: %w", err)
	}

	syncInterval := cfg.Turso.SyncInterval
	if syncInterval == 0 {
		syncInterval = 5 * time.Minute
	}

	log.Info().
		Str("database", types.DatabaseTurso).
		Str("mode", "embedded-replica").
		Str("path", cfg.Turso.Path).
		Str("url", cfg.Turso.URL).
		Dur("sync_interval", syncInterval).
		Msg("Opening Turso database in embedded-replica mode")

	// Open embedded replica using go-libsql
	// This creates a local SQLite file that syncs with Turso Cloud
	connector, err := libsql.NewEmbeddedReplicaConnector(
		cfg.Turso.Path,
		cfg.Turso.URL,
		libsql.WithAuthToken(cfg.Turso.AuthToken),
		libsql.WithSyncInterval(syncInterval),
	)
	if err != nil {
		return nil, fmt.Errorf("creating turso embedded replica connector: %w", err)
	}

	// Open database connection
	sqlDB := sql.OpenDB(connector)

	// Configure connection pool (same as SQLite - single connection)
	sqlDB.SetMaxIdleConns(1)
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetConnMaxIdleTime(time.Hour)

	// Test connection
	if err := sqlDB.Ping(); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("pinging turso embedded replica: %w", err)
	}

	// Create GORM instance using the SQLite dialector
	// Turso is SQLite-compatible so we use the SQLite dialector
	db, err := gorm.Open(
		createTursoDialector(sqlDB),
		&gorm.Config{
			PrepareStmt: cfg.Gorm.PrepareStmt,
			Logger:      dbLogger,
		},
	)
	if err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("creating gorm instance for turso embedded replica: %w", err)
	}

	log.Info().
		Str("database", types.DatabaseTurso).
		Str("mode", "embedded-replica").
		Msg("Successfully opened Turso database in embedded-replica mode")

	return db, nil
}

// openTursoRemote opens a remote-only Turso database connection.
// Note: For production use, we recommend using embedded-replica mode instead,
// which provides local caching with cloud sync for better performance.
func openTursoRemote(cfg types.DatabaseConfig, dbLogger logger.Interface) (*gorm.DB, error) {
	if cfg.Turso.URL == "" {
		return nil, fmt.Errorf("turso.url must be set when using 'remote' mode")
	}
	if cfg.Turso.AuthToken == "" {
		return nil, fmt.Errorf("turso.auth_token must be set when using 'remote' mode")
	}

	log.Info().
		Str("database", types.DatabaseTurso).
		Str("mode", "remote").
		Str("url", cfg.Turso.URL).
		Msg("Opening Turso database in remote mode - using embedded-replica with temp sync")

	// For remote mode, we use embedded-replica with a temporary local file
	// This provides the benefits of local caching while primarily using the remote database
	// The sync happens frequently to minimize divergence from cloud state
	tempPath := filepath.Join(filepath.Dir(cfg.Turso.Path), ".turso-remote-cache.db")
	if cfg.Turso.Path == "" {
		tempPath = "/tmp/headscale-turso-remote.db"
	}

	connector, err := libsql.NewEmbeddedReplicaConnector(
		tempPath,
		cfg.Turso.URL,
		libsql.WithAuthToken(cfg.Turso.AuthToken),
		libsql.WithSyncInterval(30*time.Second), // Sync every 30 seconds for remote mode
	)
	if err != nil {
		return nil, fmt.Errorf("creating turso remote connector: %w", err)
	}

	// Open database connection
	sqlDB := sql.OpenDB(connector)

	// Configure connection pool for remote connections
	// Remote mode can handle more concurrent connections than local
	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetMaxOpenConns(25)
	sqlDB.SetConnMaxIdleTime(5 * time.Minute)

	// Test connection
	if err := sqlDB.Ping(); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("pinging turso remote database: %w", err)
	}

	// Create GORM instance using the SQLite dialector
	// Turso is SQLite-compatible so we use the SQLite dialector
	db, err := gorm.Open(
		createTursoDialector(sqlDB),
		&gorm.Config{
			PrepareStmt: cfg.Gorm.PrepareStmt,
			Logger:      dbLogger,
		},
	)
	if err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("creating gorm instance for turso remote: %w", err)
	}

	log.Info().
		Str("database", types.DatabaseTurso).
		Str("mode", "remote").
		Str("cache_path", tempPath).
		Msg("Successfully opened Turso database in remote mode with local cache")

	return db, nil
}

// createTursoDialector creates a GORM dialector for Turso database connections.
// This is a helper function for when we implement the full Turso driver support.
func createTursoDialector(sqlDB *sql.DB) gorm.Dialector {
	// For now, we use the SQLite dialector as Turso is SQLite-compatible
	return sqlite.Dialector{Conn: sqlDB}
}
