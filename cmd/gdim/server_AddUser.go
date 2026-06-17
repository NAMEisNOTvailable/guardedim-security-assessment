package main

import (
	"database/sql"
	"flag"
	"fmt"
	"guardedim/server"
	"net"
)

func addUserCmd(db *sql.DB, args []string) {
	fs := flag.NewFlagSet("adduser", flag.ExitOnError)
	username := fs.String("username", "", "username (required)")
	display_name := fs.String("display-name", "", "display name (optional)")
	latest_ip := fs.String("latest-ip", "", "user wireguard ip address (required)")
	pubkey := fs.String("public-key", "", "wireguard public key (required)")
	fs.Parse(args)

	if *username == "" || *latest_ip == "" || *pubkey == "" {
		fs.Usage()
		return
	}
	if net.ParseIP(*latest_ip) == nil {
		fmt.Println("latest-ip must be a valid IP address")
		return
	}
	if *display_name == "" {
		*display_name = *username
	}

	if _, err := server.AddUser(db, *username, *display_name, *pubkey, *latest_ip); err == nil {
		fmt.Println("User added.")
	} else {
		fmt.Printf("Could not add user: %v\n", err)
	}
}
