package platform

import "net"

type EchoResult struct {
	OK           bool
	Reached      bool
	Status       uint32
	ReplyIP      net.IP
	DurationUS   int64
	RoundTripMS  uint32
	TTLExpired   bool
	ErrorMessage string
}

type NetworkInfo struct {
	GatewayIP       net.IP
	GatewayMAC      string
	LocalIP         net.IP
	InterfaceIndex  uint32
	InterfaceName   string
	IsVPN           bool
	SystemResolvers []string
}
