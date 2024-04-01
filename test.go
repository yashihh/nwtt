package main

import (
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func main() {
	// 選擇網卡和過濾條件
	iface := "enp0s9" // 更換為你的網卡名稱
	filter := "udp"   // 更換為你要過濾的封包類型

	// 開啟網卡
	handle, err := pcap.OpenLive(iface, 1600, true, -1)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// 設置過濾器
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}

	// 開始捕獲封包
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		fmt.Println("recv")

		// 提取 TIMESPEC 資訊
		timestamp := packet.Metadata().Timestamp

		// 打印 TIMESPEC 資訊
		fmt.Println("TIMESPEC:", timestamp.UnixNano())
	}
}
