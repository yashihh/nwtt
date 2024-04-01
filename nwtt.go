package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

type PortIdentity struct {
	ClockIdentity uint64
	PortNumber    uint16
}

const (
	SYNC                  = 0x0
	DELAY_REQ             = 0x1
	PDELAY_REQ            = 0x2
	PDELAY_RESP           = 0x3
	FOLLOW_UP             = 0x8
	DELAY_RESP            = 0x9
	PDELAY_RESP_FOLLOW_UP = 0xA
	ANNOUNCE              = 0xB
	SIGNALING             = 0xC
	MANAGEMENT            = 0xD
)

type PTPHeader struct {
	SdoIDAndMsgType     uint8 // first 4 bits are SdoId, next 4 bits are msgtype
	Version             uint8 // first 4 bits are minorVersionPTP, next 4 bits are versionPTP
	MessageLength       uint16
	DomainNumber        uint8
	MinorSdoID          uint8
	FlagField           uint16
	CorrectionField     int64 // IntFloat is a float64 stored in int64
	MessageTypeSpecific uint32
	ClockIdentity       uint64
	SourcePortID        uint16
	SequenceID          uint16
	ControlField        uint8 // the use of this field is obsolete according to IEEE, unless it's ipv4
	LogMessageInterval  int8  // specified as a power of two in seconds. The default is 0 (1 second)
}

type TimeStamp struct {
	Reserved    uint16
	Seconds     uint32
	Nanoseconds uint32
}

type ClockQuality struct {
	ClockClass              uint8
	ClockAccuracy           uint8
	OffsetScaledLogVariance uint16
}

type TimeSource uint8

const (
	AtomicClock        TimeSource = 0x10
	GNSS               TimeSource = 0x20
	TerrestrialRadio   TimeSource = 0x30
	SerialTimeCode     TimeSource = 0x39
	PTP                TimeSource = 0x40
	NTP                TimeSource = 0x50
	HandSet            TimeSource = 0x60
	Other              TimeSource = 0x90
	InternalOscillator TimeSource = 0xa0
)

type Announce struct {
	header                  PTPHeader
	OriginTimestamp         TimeStamp
	CurrentUTCOffset        int16
	Reserved                uint8
	GrandmasterPriority1    uint8
	GrandmasterClockQuality ClockQuality
	GrandmasterPriority2    uint8
	GrandmasterIdentity     uint64
	StepsRemoved            uint16
	TimeSource              TimeSource
}
type Sync struct {
	header          PTPHeader
	OriginTimestamp TimeStamp
}

type FollowUp struct {
	header                 PTPHeader
	presiseOriginTimestamp TimeStamp
}

type DelayRESP struct {
	header                 PTPHeader
	receiveTimestamp       TimeStamp
	requestingPortIdentity PortIdentity
}

type UDPHeader struct {
	Src      uint16
	Dst      uint16
	Len      uint16
	Checksum uint16
}

func (hdr *UDPHeader) Bytes() []byte {
	var b []byte
	b = append(b, byte(hdr.Src>>8), byte(hdr.Src))
	b = append(b, byte(hdr.Dst>>8), byte(hdr.Dst))
	b = append(b, byte(hdr.Len>>8), byte(hdr.Len))
	b = append(b, byte(hdr.Checksum>>8), byte(hdr.Checksum))
	// b = append(b, hdr.Data...)
	return b
}

// TODO: add software and hardware option
// SUPPORT two-step
var (
	locker      sync.Mutex
	iphdrID     int
	seqAnnounce uint16
	seq         uint16
)

func ProcessANNOUNCE(fd int, srcAddr *net.IPAddr, dstAddr *syscall.SockaddrInet4, wg *sync.WaitGroup) {

	var data bytes.Buffer
	for {
		announceMsg := Announce{
			header: PTPHeader{
				SdoIDAndMsgType:     0x0 | ANNOUNCE,
				Version:             0x12,
				MessageLength:       64,
				DomainNumber:        0,
				MinorSdoID:          0,
				FlagField:           0x0000,
				CorrectionField:     0x0,
				MessageTypeSpecific: 0,
				ClockIdentity:       0x080027fffe700d27,
				SourcePortID:        1,
				SequenceID:          seqAnnounce,
				ControlField:        0,
				LogMessageInterval:  1,
			},
			CurrentUTCOffset:     37,
			GrandmasterPriority1: 128,
			GrandmasterClockQuality: ClockQuality{
				ClockClass:              248,
				ClockAccuracy:           0xfe, // Accuracy Unknown
				OffsetScaledLogVariance: 65535,
			},
			GrandmasterPriority2: 128,
			GrandmasterIdentity:  0x080027fffe700d27,
			StepsRemoved:         0,
			TimeSource:           InternalOscillator,
		}
		if err := binary.Write(&data, binary.BigEndian, &announceMsg); err != nil {
			return
		}

		if _, err := SendPTPmessage(ANNOUNCE, fd, data.Bytes(), srcAddr, dstAddr); err != nil {
			return
		}

		data.Reset()

		// interval time of PTP Msg transmit
		intervalsec := 1 << announceMsg.header.LogMessageInterval
		time.Sleep(time.Duration(intervalsec) * time.Second)
		seqAnnounce++
		defer wg.Done()
	}
}

func ProcessSYNC(fd int, srcAddr *net.IPAddr, dstAddr *syscall.SockaddrInet4, wg *sync.WaitGroup) {
	var data bytes.Buffer
	for {
		syncMsg := Sync{
			header: PTPHeader{
				SdoIDAndMsgType:     0x0 | SYNC,
				Version:             0x12,
				MessageLength:       44,
				DomainNumber:        0,
				MinorSdoID:          0,
				FlagField:           0x0200,
				CorrectionField:     0x0,
				MessageTypeSpecific: 0,
				ClockIdentity:       0x080027fffe700d27,
				SourcePortID:        1,
				SequenceID:          seq,
				ControlField:        0,
				LogMessageInterval:  0,
			},
			// OriginTimestamp: syncTimeStamp,
		}

		if err := binary.Write(&data, binary.BigEndian, &syncMsg); err != nil {
			fmt.Println("SYNC Error Writing Binary:", err)
			return
		}
		tx_time, err := SendPTPmessage(SYNC, fd, data.Bytes(), srcAddr, dstAddr)
		if err != nil {
			fmt.Println("SYNC Error Send PTP MSG:", err)
			return
		}
		data.Reset()

		/* Send the follow up message right away */
		followUpMsg := FollowUp{
			header: PTPHeader{
				SdoIDAndMsgType:     0x0 | FOLLOW_UP,
				Version:             0x12,
				MessageLength:       44,
				DomainNumber:        0,
				MinorSdoID:          0,
				FlagField:           0x0200,
				CorrectionField:     0,
				MessageTypeSpecific: 0,
				ClockIdentity:       0x080027fffe700d27,
				SourcePortID:        1,
				SequenceID:          seq,
				ControlField:        2,
				LogMessageInterval:  0,
			},
			presiseOriginTimestamp: TimeStamp{
				Seconds:     uint32(tx_time.UnixNano() / 1e9),
				Nanoseconds: uint32(tx_time.UnixNano() % 1e9),
			},
		}

		if err := binary.Write(&data, binary.BigEndian, &followUpMsg); err != nil {
			fmt.Println("FOLLOW_UP Error Writing Binary:", err)
			return
		}

		if _, err := SendPTPmessage(FOLLOW_UP, fd, data.Bytes(), srcAddr, dstAddr); err != nil {
			fmt.Println("FOLLOW_UP Error Send PTP MSG:", err)
			return
		}
		data.Reset()

		intervalsec := 1 << syncMsg.header.LogMessageInterval
		time.Sleep(time.Duration(intervalsec) * time.Second)
		seq++
	}

}

func getREQPortID(data []byte) PortIdentity {
	return PortIdentity{
		ClockIdentity: binary.BigEndian.Uint64(data[48:56]),
		PortNumber:    binary.BigEndian.Uint16(data[56:58]),
	}
}

func getREQSeqID(data []byte) uint16 {
	return binary.BigEndian.Uint16(data[58:60])
}

func ProcessRESP(fd int, srcAddr *net.IPAddr, dstAddr *syscall.SockaddrInet4, wg *sync.WaitGroup, rxTs time.Time, req []byte) {
	var data bytes.Buffer
	delayRespMsg := DelayRESP{
		header: PTPHeader{
			SdoIDAndMsgType:     0x0 | DELAY_RESP,
			Version:             0x12,
			MessageLength:       54,
			DomainNumber:        0,
			MinorSdoID:          0,
			FlagField:           0x0000,
			CorrectionField:     0,
			MessageTypeSpecific: 0,
			ClockIdentity:       0x080027fffe700d27,
			SourcePortID:        1,
			SequenceID:          getREQSeqID(req),
			ControlField:        3,
			LogMessageInterval:  0,
		},
		receiveTimestamp: TimeStamp{
			Seconds:     uint32(rxTs.UnixNano() / 1e9),
			Nanoseconds: uint32(rxTs.UnixNano() % 1e9),
		},
		requestingPortIdentity: getREQPortID(req),
	}
	if err := binary.Write(&data, binary.BigEndian, &delayRespMsg); err != nil {
		fmt.Println("DELAY_RESP Error Writing Binary:", err)
		return
	}

	if _, err := SendPTPmessage(DELAY_RESP, fd, data.Bytes(), srcAddr, dstAddr); err != nil {
		fmt.Println("DELAY_RESP Error Send PTP MSG:", err)
		return
	}

	data.Reset()

	intervalsec := 1 << delayRespMsg.header.LogMessageInterval
	time.Sleep(time.Duration(intervalsec) * time.Second)
}

func SendPTPmessage(msgtype int, fd int, data []byte, srcAddr *net.IPAddr, dstAddr *syscall.SockaddrInet4) (time.Time, error) {

	// fmt.Println("MSG PREPARE! %d", msgtype)

	// build UDP header
	udphdr := UDPHeader{
		Len: uint16(len(data)) + 8,
	}
	switch msgtype {
	case ANNOUNCE, SYNC, DELAY_RESP:
		udphdr.Src = 320
		udphdr.Dst = 320

	case FOLLOW_UP:
		udphdr.Src = 319
		udphdr.Dst = 319
	}
	udp := udphdr.Bytes()

	// build IP Header
	ipHeader := &ipv4.Header{
		Version:  4,
		Len:      20,
		TotalLen: len(data) + len(udp) + 20, // ptphdr | udphdr | iphdr
		ID:       iphdrID,
		TTL:      0,
		Protocol: syscall.IPPROTO_UDP,
		Src:      net.ParseIP("172.168.56.3").To4(),
		Dst:      net.ParseIP("224.0.1.129").To4(),
		Flags:    ipv4.DontFragment,
	}
	ip, _ := ipHeader.Marshal()
	pkt := append(ip, udp...)
	pkt = append(pkt, data...)

	if err := syscall.Sendmsg(fd, pkt, nil, dstAddr, 0); err != nil {
		return time.Time{}, err
	}

	oob := make([]byte, 1024) // a buffer for Out-Of-Band data where the kernel will write the timestamp
	// MSG_ERRQUEUE indicates that we want to receive a message from the socket's error queue
	_, oobn, _, _, err := syscall.Recvmsg(fd, pkt, oob, syscall.MSG_ERRQUEUE)

	if err != nil {
		return time.Time{}, err
	}
	sentAt, err := getTimestamp(oob, oobn)
	if err != nil {
		return time.Time{}, err
	}
	// now := time.Now().UnixNano()
	// offset := float64(sentAt.UnixNano()-now) / 1e9
	// fmt.Printf("tx: [%d] system: [%d]  offset: [%f] \n", sentAt.UnixNano(), now, offset)
	pkt = nil
	locker.Lock()
	iphdrID++
	locker.Unlock()

	return sentAt, nil
}

func getTimestamp(oob []byte, oobn int) (time.Time, error) {
	cms, err := syscall.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return time.Time{}, err
	}
	for _, cm := range cms {
		if cm.Header.Level == syscall.SOL_SOCKET || cm.Header.Type == syscall.SO_TIMESTAMPING {
			var t unix.ScmTimestamping
			if err := binary.Read(bytes.NewBuffer(cm.Data), binary.LittleEndian, &t); err != nil {
				return time.Time{}, err
			}
			return time.Unix(t.Ts[0].Unix()), nil
		}
		if cm.Header.Level == syscall.SOL_SOCKET && cm.Header.Type == syscall.SCM_TIMESTAMPNS {
			var t unix.Timespec
			if err := binary.Read(bytes.NewBuffer(cm.Data), binary.LittleEndian, &t); err != nil {
				return time.Time{}, err
			}
			return time.Unix(t.Unix()), nil
		}
	}

	return time.Time{}, fmt.Errorf("no timestamp found")
}

func pktdump(data []byte) {
	var result strings.Builder
	for i, b := range data {
		result.WriteString(fmt.Sprintf("%02X ", b))
		if (i+1)%8 == 0 {
			result.WriteString("  ")
		}
		if (i+1)%16 == 0 {
			result.WriteString("\n")
		}
	}
	fmt.Printf("Packet hex dump:\n" + result.String() + "\n")
}

func main() {

	upfAddr, err := net.ResolveIPAddr("ip4", "10.10.10.1")
	if err != nil {
		fmt.Println("Error resolving UPF address:", err)
		return
	}

	ueAddr, err := net.ResolveIPAddr("ip4", "10.60.0.1")
	if err != nil {
		fmt.Println("Error resolving UE address:", err)
		return
	}

	dstaddr := syscall.SockaddrInet4{
		Port: 0,
		Addr: [4]byte{
			ueAddr.IP.To4()[0],
			ueAddr.IP.To4()[1],
			ueAddr.IP.To4()[2],
			ueAddr.IP.To4()[3],
		},
	}

	// forward PTP message to the N3/N9 interfaces
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		fmt.Print("Error creating Socket: ", err.Error())
		return
	}
	defer syscall.Close(fd)

	err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	if err != nil {
		fmt.Println("Error opening IP_HDRINCL" + err.Error())
		return
	}
	flags := unix.SOF_TIMESTAMPING_SOFTWARE | unix.SOF_TIMESTAMPING_RX_SOFTWARE | unix.SOF_TIMESTAMPING_TX_SOFTWARE |
		unix.SOF_TIMESTAMPING_OPT_CMSG | unix.SOF_TIMESTAMPING_OPT_TSONLY

	err = syscall.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TIMESTAMPING, flags)
	if err != nil {
		fmt.Println("Error opening SO_TIMESTAMPING" + err.Error())
		return
	}

	multicastAddr := "224.0.1.129"
	conn, err := net.ListenIP("ip4:udp", &net.IPAddr{IP: net.ParseIP(multicastAddr)})

	if err != nil {
		fmt.Println("無法連接多播組:", err)
		return
	}

	defer conn.Close()

	var wg sync.WaitGroup
	wg.Add(3)

	go func() {
		defer wg.Done()

		buf := make([]byte, 1024)
		oob := make([]byte, 1024) // a buffer for Out-Of-Band data where the kernel will write the timestamp
		file, err := conn.File()
		if err != nil {
			fmt.Println("Can't read packet:", err)
			return
		}
		recvFd := file.Fd()
		err = syscall.SetsockoptInt(int(recvFd), unix.SOL_SOCKET, unix.SO_TIMESTAMPING, flags)
		if err != nil {
			fmt.Println("Error opening SO_TIMESTAMPING" + err.Error())
			return
		}
		for {
			// n, oobn, _, _, err := conn.ReadMsgIP(buf, oob)
			n, oobn, _, _, err := syscall.Recvmsg(int(recvFd), buf, oob, 0)

			if err != nil {
				fmt.Println("Can't read packet:", err)
				return
			}
			recvAt, err := getTimestamp(oob, oobn)
			if err != nil {
				fmt.Println("Can't get Timestamp:", err)
			}
			// fmt.Println(recvAt)

			ProcessRESP(fd, upfAddr, &dstaddr, &wg, recvAt, buf[:n])
		}
	}()

	go ProcessANNOUNCE(fd, upfAddr, &dstaddr, &wg)
	time.Sleep(1 * time.Second)
	go ProcessSYNC(fd, upfAddr, &dstaddr, &wg)
	wg.Wait()
}

// ref: https://pkg.go.dev/github.com/facebookincubator/ptp/protocol
