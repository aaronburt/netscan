package winapi

import (
	"encoding/binary"
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	IfTypePPP         = 23
	IfTypePropVirtual = 53
	IfTypeTunnel      = 131
)

var (
	procSendARP = iphlpapi.NewProc("SendARP")
)

func DiscoverNetworkInfo() (NetworkInfo, error) {
	var size uint32 = 15000
	var info NetworkInfo

	flags := uint32(windows.GAA_FLAG_INCLUDE_GATEWAYS)
	family := uint32(windows.AF_INET)

	for {
		buffer := make([]byte, size)
		adapterAddresses := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0]))

		err := windows.GetAdaptersAddresses(family, flags, 0, adapterAddresses, &size)
		if err == nil {
			curr := adapterAddresses
			for curr != nil {
				if curr.OperStatus == windows.IfOperStatusUp && curr.FirstGatewayAddress != nil {
					gwSockAddr := curr.FirstGatewayAddress.Address.Sockaddr
					if gwSockAddr != nil {
						rawSock := (*windows.RawSockaddrInet)(unsafe.Pointer(gwSockAddr))
						if rawSock.Family == windows.AF_INET {
							sa4 := (*windows.RawSockaddrInet4)(unsafe.Pointer(gwSockAddr))
							gwIP := net.IPv4(sa4.Addr[0], sa4.Addr[1], sa4.Addr[2], sa4.Addr[3])
							if !gwIP.IsUnspecified() && !gwIP.Equal(net.IPv4zero) {
								info.GatewayIP = gwIP
								info.InterfaceIndex = curr.IfIndex
								info.InterfaceName = windows.UTF16PtrToString(curr.FriendlyName)

								if curr.IfType == IfTypePPP || curr.IfType == IfTypePropVirtual || curr.IfType == IfTypeTunnel {
									info.IsVPN = true
								}

								if curr.FirstUnicastAddress != nil && curr.FirstUnicastAddress.Address.Sockaddr != nil {
									saUni := (*windows.RawSockaddrInet4)(unsafe.Pointer(curr.FirstUnicastAddress.Address.Sockaddr))
									info.LocalIP = net.IPv4(saUni.Addr[0], saUni.Addr[1], saUni.Addr[2], saUni.Addr[3])
								}

								dnsCurr := curr.FirstDnsServerAddress
								for dnsCurr != nil {
									if dnsCurr.Address.Sockaddr != nil {
										saDNS := (*windows.RawSockaddrInet4)(unsafe.Pointer(dnsCurr.Address.Sockaddr))
										dnsIP := net.IPv4(saDNS.Addr[0], saDNS.Addr[1], saDNS.Addr[2], saDNS.Addr[3])
										if !dnsIP.IsUnspecified() {
											info.SystemResolvers = append(info.SystemResolvers, dnsIP.String())
										}
									}
									dnsCurr = dnsCurr.Next
								}

								macStr := ResolveMAC(info.GatewayIP)
								if macStr != "" {
									info.GatewayMAC = macStr
								} else if curr.PhysicalAddressLength > 0 {
									var macParts []string
									for i := uint32(0); i < curr.PhysicalAddressLength; i++ {
										macParts = append(macParts, fmt.Sprintf("%02X", curr.PhysicalAddress[i]))
									}
									info.GatewayMAC = fmt.Sprintf("%s", macParts)
								}

								return info, nil
							}
						}
					}
				}
				curr = curr.Next
			}
			return info, nil
		}

		if err == windows.ERROR_BUFFER_OVERFLOW {
			continue
		}
		return info, err
	}
}

func ResolveMAC(ip net.IP) string {
	ip4 := ip.To4()
	if ip4 == nil {
		return ""
	}
	destIP := binary.LittleEndian.Uint32(ip4)
	mac := make([]byte, 6)
	macLen := uint32(len(mac))

	r, _, _ := procSendARP.Call(
		uintptr(destIP),
		0,
		uintptr(unsafe.Pointer(&mac[0])),
		uintptr(unsafe.Pointer(&macLen)),
	)
	if r == 0 && macLen >= 6 {
		return fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
	}
	return ""
}
