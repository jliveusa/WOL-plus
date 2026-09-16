package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/google/gopacket/pcap"
)

const (
	ethernetHeaderLength = 14
	wolEthertype         = 0x0842
	wolPayloadLength     = 102
	shutdownPayloadSize  = wolPayloadLength + 6
	captureReadTimeout   = 500 * time.Millisecond
)

var wolSyncBytes = bytes.Repeat([]byte{0xff}, 6)

// startPacketCapture accepts only WOL Ethernet frames whose Magic Packet and
// trailing six-byte discriminator both match this Client's configuration.
func startPacketCapture(ctx context.Context, cfg listenerConfig) {
	defer listenerWg.Done()

	// A finite timeout makes cancellation observable even when the network is idle.
	handle, err := pcap.OpenLive(cfg.Interface, 1600, true, captureReadTimeout)
	if err != nil {
		log.Printf("Failed to open capture device %s: %v", cfg.Interface, err)
		return
	}
	defer handle.Close()

	if err := handle.SetBPFFilter("ether proto 0x0842"); err != nil {
		log.Printf("Failed to apply WOL capture filter on %s: %v", cfg.Interface, err)
		return
	}

	for {
		select {
		case <-ctx.Done():
			log.Println("Stop Ethernet capture goroutine")
			return
		default:
		}

		frame, _, err := handle.ReadPacketData()
		if err == pcap.NextErrorTimeoutExpired {
			continue
		}
		if err != nil {
			if ctx.Err() != nil {
				log.Println("Stop Ethernet capture goroutine")
				return
			}
			log.Printf("Ethernet capture failed on %s: %v", cfg.Interface, err)
			return
		}
		if isShutdownFrame(frame, cfg) {
			log.Println("Received matching WOL Ethernet frame, initiating shutdown")
			initiateShutdown()
		}
	}
}

func isShutdownFrame(frame []byte, cfg listenerConfig) bool {
	if len(frame) < ethernetHeaderLength+shutdownPayloadSize {
		return false
	}
	if frame[12] != byte(wolEthertype>>8) || frame[13] != byte(wolEthertype&0xff) {
		return false
	}

	targetMAC, err := decodeConfiguredMAC(cfg.MacAddress)
	if err != nil {
		return false
	}
	extraData, err := decodeConfiguredMAC(cfg.ExtraData)
	if err != nil {
		return false
	}

	payload := frame[ethernetHeaderLength:]
	if !bytes.Equal(payload[:6], wolSyncBytes) {
		return false
	}
	for offset := 6; offset < wolPayloadLength; offset += len(targetMAC) {
		if !bytes.Equal(payload[offset:offset+len(targetMAC)], targetMAC) {
			return false
		}
	}

	return bytes.Equal(payload[wolPayloadLength:shutdownPayloadSize], extraData)
}

func decodeConfiguredMAC(value string) ([]byte, error) {
	decoded, err := hex.DecodeString(strings.ReplaceAll(value, ":", ""))
	if err != nil || len(decoded) != 6 {
		return nil, fmt.Errorf("invalid six-byte value")
	}
	return decoded, nil
}

// NetworkDeviceInfo describes one libpcap capture device together with any
// OS-level network interface information that could be correlated with it
// (friendly name, hardware address, addresses, and link status). It is the
// payload returned by the /api/interfaces endpoint so the Web UI can let the
// user pick a specific NIC on machines with more than one adapter.
type NetworkDeviceInfo struct {
	// Device is the libpcap capture-device name. This is the value stored
	// in Config.Interface and passed to pcap.OpenLive.
	Device string `json:"device"`
	// Name is the OS-level interface name (e.g. "eth0", "以太网 3"), when it
	// could be determined. Empty if no OS interface could be correlated.
	Name string `json:"name"`
	// Description is the libpcap-reported description of the device (on
	// Windows via Npcap this is typically the adapter's vendor/model name).
	Description string `json:"description"`
	// MacAddress is the interface's hardware address, lower-case
	// colon-separated, when it could be determined.
	MacAddress string `json:"mac_address"`
	// Addresses lists the IP addresses (v4 and v6) bound to this device.
	Addresses []string `json:"addresses"`
	// IsUp reports whether the OS interface is currently up. False when no
	// OS interface could be correlated.
	IsUp bool `json:"is_up"`
	// IsCurrent reports whether this device is the one currently configured
	// in Config.Interface, so the Web UI can preselect it.
	IsCurrent bool `json:"is_current"`
}

func isLoopbackAddress(addr string) bool {
	ip := net.ParseIP(addr)
	return ip != nil && ip.IsLoopback()
}

// listNetworkDevices enumerates every libpcap capture device and, wherever
// possible, correlates it with an OS-level network interface (matching by
// shared IP address, and, as a fallback that works on Linux/macOS where the
// capture-device name equals the OS interface name, by name). Pure loopback
// devices are omitted since they can never receive a WOL Ethernet frame.
func listNetworkDevices() ([]NetworkDeviceInfo, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("could not list capture devices: %w", err)
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("could not list network interfaces: %w", err)
	}

	ipToIface := make(map[string]net.Interface)
	for _, iface := range interfaces {
		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			if ipNet, ok := address.(*net.IPNet); ok {
				ipToIface[ipNet.IP.String()] = iface
			}
		}
	}

	currentInterface := currentListenerConfig().Interface

	result := make([]NetworkDeviceInfo, 0, len(devices))
	for _, device := range devices {
		info := NetworkDeviceInfo{
			Device:      device.Name,
			Description: device.Description,
			IsCurrent:   device.Name == currentInterface,
		}

		var matched *net.Interface
		for _, deviceAddress := range device.Addresses {
			if deviceAddress.IP == nil {
				continue
			}
			ip := deviceAddress.IP.String()
			info.Addresses = append(info.Addresses, ip)
			if matched == nil {
				if iface, ok := ipToIface[ip]; ok {
					ifaceCopy := iface
					matched = &ifaceCopy
				}
			}
		}
		if matched == nil {
			// Works on Linux/macOS, where the capture-device name is the OS
			// interface name. Fails harmlessly (and is ignored) on Windows.
			if iface, err := net.InterfaceByName(device.Name); err == nil {
				matched = iface
			}
		}

		// Skip devices that only ever expose loopback addresses; they can
		// never carry a WOL frame from another host.
		if matched != nil && matched.Flags&net.FlagLoopback != 0 {
			continue
		}
		if len(info.Addresses) > 0 {
			allLoopback := true
			for _, addr := range info.Addresses {
				if !isLoopbackAddress(addr) {
					allLoopback = false
					break
				}
			}
			if allLoopback {
				continue
			}
		}

		if matched != nil {
			info.Name = matched.Name
			info.IsUp = matched.Flags&net.FlagUp != 0
			if len(matched.HardwareAddr) == 6 {
				info.MacAddress = strings.ToLower(matched.HardwareAddr.String())
			}
		}

		result = append(result, info)
	}

	return result, nil
}

// getNetworkDevice returns the capture-device name rather than the operating
// system interface name, which is required by libpcap on Windows. It picks
// the first up, non-loopback interface with a usable IPv4 address and a
// resolvable hardware address, used only to seed a brand-new config file;
// once the config exists, the interface can be changed via the Web UI's
// interface picker (backed by listNetworkDevices).
func getNetworkDevice() (string, string, error) {
	devices, err := listNetworkDevices()
	if err != nil {
		return "", "", err
	}

	for _, device := range devices {
		if !device.IsUp || device.MacAddress == "" {
			continue
		}
		hasUsableIPv4 := false
		for _, addr := range device.Addresses {
			ip := net.ParseIP(addr)
			if ip != nil && ip.To4() != nil && !ip.IsLoopback() {
				hasUsableIPv4 = true
				break
			}
		}
		if !hasUsableIPv4 {
			continue
		}
		log.Printf("Selected capture device: %s - MAC: %s - IPv4: %v", device.Device, device.MacAddress, device.Addresses)
		return device.Device, device.MacAddress, nil
	}

	return "", "", fmt.Errorf("could not select an active capture device")
}
