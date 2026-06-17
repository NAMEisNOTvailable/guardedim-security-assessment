package main

import (
	"flag"
	"fmt"
	_ "guardedim/server"
	"os"
	"os/exec"
	"text/template"
)

// startClientCmd installs gdimd.service if needed, then restarts it.
// Called like: gdim startclient
func startClientCmd(args []string) {
	fs := flag.NewFlagSet("startclient", flag.ExitOnError)
	servicePath := fs.String("unit-path", "/etc/systemd/system/gdimd.service",
		"location for generated systemd unit")
	binaryPath := fs.String("bin", "/usr/local/bin/gdimd", "path to daemon binary")
	fs.Parse(args)

	// 1) If the unit file doesn't exist, create it from template
	if _, err := os.Stat(*servicePath); os.IsNotExist(err) {
		if err := writeUnitFileClient(*servicePath, *binaryPath); err != nil {
			fmt.Printf("Could not write unit file: %v\n", err)
			return
		}
		// Reload systemd to pick up the new unit.
		exec.Command("systemctl", "daemon-reload").Run()
		exec.Command("systemctl", "enable", "gdimd").Run()
		fmt.Println("Installed gdimd.service.")
	}
	if err := exec.Command("systemctl", "restart", "gdimd").Run(); err != nil {
		fmt.Printf("Could not start gdimd: %v\n", err)
		return
	}
	fmt.Println("gdimd started.")
}

// writeUnitFileClient writes a minimal systemd unit.
func writeUnitFileClient(path, bin string) error {
	const tmpl = `[Unit]
Description=GuardedIM Daemon
After=network-online.target

[Service]
ExecStart={{ .Bin }}
Restart=on-failure
Type=simple

[Install]
WantedBy=multi-user.target
`
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	return template.Must(template.New("unit").Parse(tmpl)).Execute(f, struct{ Bin string }{bin})
}
