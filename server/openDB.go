package server

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"path/filepath"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func OpenDB(addr string, port uint16, dbUsername string, dbName string, certDir string) (*sql.DB, error) {
	return OpenDBWithURL(CraftDBAccessURL(addr, port, dbUsername, dbName, certDir))
}

func CraftDBAccessURL(addr string, port uint16, dbUsername string, dbName string, certDir string) string {
	if dbName == "" {
		dbName = "defaultdb"
	}
	values := url.Values{}
	values.Set("sslmode", "verify-full")
	values.Set("sslrootcert", filepath.Join(certDir, "ca.crt"))
	values.Set("sslcert", filepath.Join(certDir, fmt.Sprintf("client.%s.crt", dbUsername)))
	values.Set("sslkey", filepath.Join(certDir, fmt.Sprintf("client.%s.key", dbUsername)))
	return fmt.Sprintf("postgresql://%s@%s:%d/%s?%s",
		url.User(dbUsername).String(),
		addr,
		port,
		url.PathEscape(dbName),
		values.Encode(),
	)
}

func OpenDBWithURL(db_access_url string) (*sql.DB, error) {
	db, err := sql.Open("pgx", db_access_url)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(50)
	db.SetMaxIdleConns(25)
	db.SetConnMaxIdleTime(5 * time.Minute)
	db.SetConnMaxLifetime(30 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping db: %w", err)
	}
	return db, nil
}
