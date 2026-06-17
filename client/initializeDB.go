package client

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver, no CGO needed
)

// InitializeLocalDB opens or creates the local SQLite database and makes sure
// the required table exists. The connection limits fit a local single-user
// database.
//
//	db, err := InitializeLocalDB("/home/alice/.guardedim/client.db")
//	if err != nil { return err }
//	defer db.Close()
func InitializeLocalDB(path string) (*sql.DB, error) {
	if path == "" {
		return nil, fmt.Errorf("sqlite path is required")
	}
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, fmt.Errorf("create sqlite directory: %w", err)
		}
	}

	// busy_timeout helps when the file is on network filesystems.
	dsn := fmt.Sprintf("file:%s?_busy_timeout=5000&_journal_mode=WAL", path)

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	// Limit the single-process connection pool: SQLite is not a server.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxIdleTime(5 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	const ddl = `
CREATE TABLE IF NOT EXISTS server_info_table (
  server_id           INTEGER       PRIMARY KEY AUTOINCREMENT,
  server_name         TEXT          COLLATE NOCASE,         -- STRING(64)
  server_pubip        BLOB          NOT NULL,               -- BYTES
  server_port         INTEGER       NOT NULL CHECK (server_port BETWEEN 0 AND 65535),
  server_privip       BLOB          NOT NULL UNIQUE,
  server_pubkey       BLOB          NOT NULL UNIQUE,
  server_presharedkey BLOB          NOT NULL
);`
	if _, err = db.ExecContext(ctx, ddl); err != nil {
		db.Close()
		return nil, fmt.Errorf("create table: %w", err)
	}

	return db, nil
}
