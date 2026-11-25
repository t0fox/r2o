// Read-only IPv4 field measurements for Linux routers. Build with CGO_ENABLED=0.
package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var native = binary.NativeEndian

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("expected capture or route")
	}
	if len(args) == 6 && (args[0] == "capture" || args[0] == "capture-pppoe") {
		dev, err := net.InterfaceByName(args[1])
		if err != nil {
			return err
		}
		dst := net.ParseIP(args[2]).To4()
		port, e1 := strconv.ParseUint(args[3], 10, 16)
		secs, e2 := strconv.Atoi(args[4])
		service, e3 := strconv.ParseUint(args[5], 10, 16)
		if dst == nil || e1 != nil || e2 != nil || secs < 1 || secs > 120 || e3 != nil || service == 0 {
			return fmt.Errorf("capture IFACE SERVER_IPV4 CLIENT_PORT_OR_0 SECONDS SERVER_PORT")
		}
		ipOffset := 0
		if args[0] == "capture-pppoe" {
			ipOffset = 8
		}
		return capture(dev, dst, uint16(port), secs, uint16(service), ipOffset)
	}
	if len(args) == 6 && args[0] == "route" {
		dst := net.ParseIP(args[1]).To4()
		src := net.ParseIP(args[2]).To4()
		var index uint32
		if args[3] != "-" {
			dev, err := net.InterfaceByName(args[3])
			if err != nil {
				return err
			}
			index = uint32(dev.Index)
		}
		mark, e1 := strconv.ParseUint(args[4], 0, 32)
		tos, e2 := strconv.ParseUint(args[5], 0, 8)
		if dst == nil || (src == nil && args[2] != "-") || e1 != nil || e2 != nil {
			return fmt.Errorf("route DST SRC_OR_- IIF_OR_- MARK TOS")
		}
		return route(dst, src, index, uint32(mark), byte(tos))
	}
	return fmt.Errorf("capture IFACE SERVER_IPV4 CLIENT_PORT_OR_0 SECONDS SERVER_PORT | route DST SRC_OR_- IIF_OR_- MARK TOS")
}

func capture(dev *net.Interface, server net.IP, port uint16, secs int, service uint16, ipOffset int) error {
	// SOCK_DGRAM presents network-layer bytes on Ethernet and PPP alike.
	// ETH_P_ALL includes outgoing packets. A socket bound to ETH_P_IP alone can miss them.
	eth := []byte{0, 3}
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	if err = syscall.AttachLsf(fd, headerFilter(server, port, service, uint32(ipOffset))); err != nil {
		return err
	}
	if err = syscall.Bind(fd, &syscall.SockaddrLinklayer{Protocol: native.Uint16(eth), Ifindex: dev.Index}); err != nil {
		return err
	}
	if err = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Usec: 200000}); err != nil {
		return err
	}
	frame := make([]byte, 160)
	end := time.Now().Add(time.Duration(secs) * time.Second)
	fmt.Printf("ready iface=%s server=%s clientport=%d\n", dev.Name, server, port)
	for time.Now().Before(end) {
		n, sa, err := syscall.Recvfrom(fd, frame, 0)
		if err == syscall.EAGAIN || err == syscall.EINTR {
			continue
		}
		if err != nil {
			return err
		}
		n -= ipOffset
		buf := frame[ipOffset:]
		if n < 40 || buf[0]>>4 != 4 || buf[9] != 6 || binary.BigEndian.Uint16(buf[6:8])&0x1fff != 0 {
			continue
		}
		iplen := int(buf[0]&15) * 4
		if iplen < 20 || iplen+20 > n {
			continue
		}
		tcp := buf[iplen:n]
		sp, dp := binary.BigEndian.Uint16(tcp), binary.BigEndian.Uint16(tcp[2:])
		src, dst := net.IP(buf[12:16]), net.IP(buf[16:20])
		to := dst.Equal(server) && dp == service && (port == 0 || sp == port)
		from := src.Equal(server) && sp == service && (port == 0 || dp == port)
		if !to && !from {
			continue
		}
		headers := iplen + int(tcp[12]>>4)*4
		data := int(binary.BigEndian.Uint16(buf[2:4])) - headers
		if headers < iplen+20 || data < 0 {
			continue
		}
		dir := "in"
		if sa.(*syscall.SockaddrLinklayer).Pkttype == 4 {
			dir = "out"
		}
		fmt.Printf("%s %s %s %s:%d>%s:%d flags=%02x seq=%d ack=%d data=%d ttl=%d tos=%d\n",
			time.Now().UTC().Format(time.RFC3339Nano), dev.Name, dir, src, sp, dst, dp, tcp[13],
			binary.BigEndian.Uint32(tcp[4:]), binary.BigEndian.Uint32(tcp[8:]), data, buf[8], buf[1])
	}
	return nil
}

// The kernel delivers only the IP and TCP headers for the selected endpoints.
func headerFilter(server net.IP, client, service uint16, ipOffset uint32) []syscall.SockFilter {
	var code []syscall.SockFilter
	stmt := func(op uint16, k uint32) { code = append(code, syscall.SockFilter{Code: op, K: k}) }
	const (
		loadByte    = 0x30
		loadHalf    = 0x28
		loadWord    = 0x20
		loadTcpHalf = 0x48
		equal       = 0x15
		ret         = 0x06
	)
	require := func(k uint32) { code = append(code, syscall.SockFilter{Code: equal, K: k, Jt: 1}); stmt(ret, 0) }
	if ipOffset != 0 {
		stmt(loadHalf, 0)
		require(0x1100) // PPPoE session header.
		stmt(loadHalf, 6)
		require(0x0021) // PPP IPv4.
	}
	stmt(loadByte, ipOffset)
	stmt(0x54, 0xf0)
	require(0x40)
	stmt(loadByte, ipOffset+9)
	require(6)
	stmt(loadHalf, ipOffset+6)
	stmt(0x54, 0x1fff)
	require(0)
	stmt(0xb1, ipOffset) // X = IPv4 header length.
	branch := func(remoteOffset, localOffset uint32) {
		stmt(loadTcpHalf, ipOffset+remoteOffset)
		require(uint32(service))
		if client != 0 {
			stmt(loadTcpHalf, ipOffset+localOffset)
			require(uint32(client))
		}
		stmt(0x50, ipOffset+12)
		stmt(0x54, 0xf0)
		stmt(0x74, 2)
		stmt(0x0c, 0)
		if ipOffset != 0 {
			stmt(0x04, ipOffset)
		}
		stmt(0x16, 0)
	}
	serverIP := binary.BigEndian.Uint32(server)
	stmt(loadWord, ipOffset+16)
	jump := len(code)
	code = append(code, syscall.SockFilter{Code: equal, K: serverIP})
	branch(2, 0)
	code[jump].Jf = uint8(len(code) - jump - 1)
	stmt(loadWord, ipOffset+12)
	require(serverIP)
	branch(0, 2)
	return code
}

func route(dst, src net.IP, iif, mark uint32, tos byte) error {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	if err = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Sec: 2}); err != nil {
		return err
	}
	msg := make([]byte, 28)
	native.PutUint16(msg[4:], syscall.RTM_GETROUTE)
	native.PutUint16(msg[6:], syscall.NLM_F_REQUEST)
	native.PutUint32(msg[8:], 1)
	msg[16] = syscall.AF_INET
	msg[17] = 32
	msg[19] = tos
	add := func(kind uint16, val []byte) {
		a := make([]byte, 8)
		native.PutUint16(a, 8)
		native.PutUint16(a[2:], kind)
		copy(a[4:], val)
		msg = append(msg, a...)
	}
	u32 := func(v uint32) []byte { b := make([]byte, 4); native.PutUint32(b, v); return b }
	add(1, dst)
	if src != nil {
		msg[18] = 32
		add(2, src)
	}
	if iif != 0 {
		add(3, u32(iif))
	}
	if mark != 0 {
		add(16, u32(mark))
	}
	native.PutUint32(msg, uint32(len(msg)))
	if err = syscall.Sendto(fd, msg, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return err
	}
	buf := make([]byte, 8192)
	n, _, err := syscall.Recvfrom(fd, buf, 0)
	if err != nil {
		return err
	}
	messages, err := syscall.ParseNetlinkMessage(buf[:n])
	if err != nil {
		return err
	}
	for _, m := range messages {
		if m.Header.Seq != 1 {
			continue
		}
		if m.Header.Type == syscall.NLMSG_ERROR && len(m.Data) >= 4 {
			return fmt.Errorf("RTM_GETROUTE dst=%s src=%v iif=%d mark=%d errno=%d", dst, src, iif, mark, -int32(native.Uint32(m.Data)))
		}
		if m.Header.Type != syscall.RTM_NEWROUTE || len(m.Data) < 12 {
			continue
		}
		attrs, err := syscall.ParseNetlinkRouteAttr(&m)
		if err != nil {
			return err
		}
		var fields []string
		for _, a := range attrs {
			k := a.Attr.Type
			if len(a.Value) == 4 && (k == 1 || k == 2 || k == 5 || k == 7) {
				fields = append(fields, fmt.Sprintf("attr%d=%s", k, net.IP(a.Value)))
			} else if len(a.Value) == 4 && (k == 3 || k == 4 || k == 15 || k == 16) {
				fields = append(fields, fmt.Sprintf("attr%d=%d", k, native.Uint32(a.Value)))
			} else {
				fields = append(fields, fmt.Sprintf("attr%d[%d]", k, len(a.Value)))
			}
		}
		fmt.Printf("dst=%s src=%v iif=%d mark=%d tos=%d type=%d %s\n", dst, src, iif, mark, tos, m.Data[7], strings.Join(fields, " "))
		return nil
	}
	return fmt.Errorf("no matching route response")
}
