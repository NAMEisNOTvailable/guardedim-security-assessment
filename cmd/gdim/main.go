package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"guardedim/server"
	"os"
	"os/exec"
	"strconv"
)

const configFile = "guarded_im_config.json"

// typedConfig holds the config values used by the CLI.
type typedConfig struct {
	OperationMode string `json:"operation_mode"`
	SelfIP        string `json:"self_server_wireguard_ip"`
	PrivateKey    string `json:"self_server_wireguard_private_key"`
	ListenPort    int    `json:"self_server_wireguard_listen_port"`
	MTU           int    `json:"self_server_wireguard_mtu"`
	PublicIP      string `json:"self_server_public_ip"`
	ClientIP      string `json:"self_client_wireguard_ip"`
	ClientKey     string `json:"self_client_wireguard_private_key"`
	ClientMTU     int    `json:"self_client_wireguard_mtu"`
	LocalDB       string `json:"self_client_localdb"`

	DBHost    string `json:"database_host"`
	DBPort    uint16 `json:"database_port"`
	DBCertDir string `json:"database_cert_directory"`
	DBName    string `json:"database_dbname"`
	DBUser    string `json:"database_username"`
}

var cfg typedConfig

func loadConfig() error {
	data, err := os.ReadFile(configFile)
	if err != nil {
		return errors.New("config not found")
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}
	return nil
}

func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func main() {
	if err := loadConfig(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if len(os.Args) < 2 {
		fmt.Println("usage: gdim <command> [flags]")
		os.Exit(1)
	}

	switch cfg.OperationMode {
	case "server":
		db, err := server.OpenDB(cfg.DBHost, cfg.DBPort, cfg.DBUser, cfg.DBName, cfg.DBCertDir)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Could not connect to the database.")
			os.Exit(1)
		}

		switch os.Args[1] {
		case "adduser":
			addUserCmd(db, os.Args[2:])
		case "addserver":
			addServerCmd(db, os.Args[2:])
		case "startserver":
			if err := runCommand("systemctl", "set-environment",
				"GDIM_DAEMON_OPMODE="+"server",
				"GDIM_WG_PRIVKEY="+cfg.PrivateKey,
				"GDIM_DB_ACCESS_URL="+server.CraftDBAccessURL(cfg.DBHost, cfg.DBPort, cfg.DBUser, cfg.DBName, cfg.DBCertDir),
				"GDIM_CERT_DIR="+cfg.DBCertDir,
				"GDIM_WG_PRIVIP="+cfg.SelfIP,
				"GDIM_WG_PORT="+strconv.Itoa(cfg.ListenPort),
				"GDIM_WG_MTU="+strconv.Itoa(cfg.MTU)); err != nil {
				fmt.Fprintf(os.Stderr, "Could not pass settings to gdimd: %v\n", err)
				os.Exit(1)
			}
			startServerCmd(os.Args[2:])
		case "serverstatus":
			if err := runCommand("systemctl", "status", "gdimd"); err != nil {
				os.Exit(1)
			}
		case "stopserver":
			if err := runCommand("systemctl", "stop", "gdimd"); err != nil {
				fmt.Fprintf(os.Stderr, "Could not stop gdimd: %v\n", err)
				os.Exit(1)
			}
		case "updateconn":
			if err := server.UpdateConnection(db); err != nil {
				fmt.Fprintf(os.Stderr, "Could not update WireGuard peers: %v\n", err)
				os.Exit(1)
			}
		default:
			fmt.Fprintln(os.Stderr, "Unknown server command.")
			os.Exit(1)
		}
	case "client":
		switch os.Args[1] {
		case "startclient":
			if cfg.ClientMTU == 0 {
				cfg.ClientMTU = cfg.MTU
			}
			if err := runCommand("systemctl", "set-environment",
				"GDIM_DAEMON_OPMODE="+"client",
				"GDIM_WG_PRIVKEY="+cfg.ClientKey,
				"GDIM_WG_PRIVIP="+cfg.ClientIP,
				"GDIM_WG_MTU="+strconv.Itoa(cfg.ClientMTU),
				"GDIM_CLIENT_LOCALDB_FILEPATH="+cfg.LocalDB); err != nil {
				fmt.Fprintf(os.Stderr, "Could not pass settings to gdimd: %v\n", err)
				os.Exit(1)
			}
			startClientCmd(os.Args[2:])
		default:
			fmt.Fprintln(os.Stderr, "Unknown client command.")
			os.Exit(1)
		}

	default:
		fmt.Fprintln(os.Stderr, "Unsupported operation mode.")
		os.Exit(1)
	}

}
