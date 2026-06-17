package server

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"syscall"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// createWG0 creates a userspace WireGuard interface.
// It generates a new private key when none is provided.
func createWG0(wg_privkey string, server_port string) (*device.Device, error) {

	var key wgtypes.Key
	var err error

	port, err := strconv.Atoi(server_port)
	if port < 0 || port > 65535 || err != nil {
		return nil, errors.New("port out of range")
	}

	if len(wg_privkey) != 0 {
		key, err = wgtypes.ParseKey(wg_privkey)
		if err != nil {
			return nil, err
		}
	} else {
		key, err = wgtypes.GeneratePrivateKey()
		if err != nil {
			return nil, err
		}
	}

	wg_privkey = hex.EncodeToString(key[:])

	tun_dev, err := tun.CreateTUN("wg0", 1500)
	if err != nil {
		return nil, err
	}

	bind := conn.NewDefaultBind()
	logger := device.NewLogger(device.LogLevelVerbose, "wg0: ")

	wg_dev := device.NewDevice(tun_dev, bind, logger)
	go wg_dev.RoutineTUNEventReader()

	wg_config := fmt.Sprintf("private_key=%s\nlisten_port=%s", wg_privkey, server_port)

	return wg_dev, wg_dev.IpcSet(wg_config)
}

// setupWG0Linux sets the interface IP, route, and MTU on Linux.
// Use MTU 0 to keep the default value.
func setupWG0Linux(server_privip string, MTU int) error {

	privip := net.ParseIP(server_privip)
	var ip_net *net.IPNet
	if privip == nil {
		return errors.New("invalid IP address")
	}
	if v4 := privip.To4(); v4 != nil {
		if v4[3] != 1 {
			return errors.New("IPv4 server_privip must end with .1")
		}
		ip_net = &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)}
	} else {
		ip16 := privip.To16()
		if binary.BigEndian.Uint16(ip16[14:]) != 1 {
			return errors.New("IPv6 server_privip must end with :1")
		}
		ip_net = &net.IPNet{IP: ip16, Mask: net.CIDRMask(128, 128)}
	}

	if MTU == 0 {
		MTU = 1500
	}

	if MTU > 1700 || MTU < 800 {
		return errors.New("MTU must be between 800 and 1700")
	}

	link, err := netlink.LinkByName("wg0")
	if err != nil {
		return err
	}

	if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: ip_net}); err != nil {
		return err
	}

	if err = netlink.LinkSetUp(link); err != nil {
		return err
	}

	if err = netlink.LinkSetMTU(link, MTU); err != nil {
		return err
	}

	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       &net.IPNet{IP: net.IPv4(10, 0, 0, 0), Mask: net.CIDRMask(8, 32)},
	}
	if err := netlink.RouteAdd(route); err != nil && !errors.Is(err, syscall.EEXIST) {
		return err
	}
	return nil

}

// InitializeInterface starts the WireGuard interface and loads peer settings.
func InitializeInterface(server_privip string, server_privkey string, server_port string, MTU int, db_access_url string) (*device.Device, error) {
	var wg_dev *device.Device
	var err error
	wg_dev, err = createWG0(server_privkey, server_port)
	if err != nil {
		return nil, err
	}
	err = setupWG0Linux(server_privip, MTU)
	if err != nil {
		return nil, err
	}
	db, err := OpenDBWithURL(db_access_url)
	if err != nil {
		fmt.Println("Could not connect to the database.")
		return nil, err
	}
	err = UpdateConnection(db)
	if err != nil {
		fmt.Println("Could not load WireGuard peers.")
		return nil, err
	}
	return wg_dev, nil
}
