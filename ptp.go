package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
)

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
	multicastAddr := "224.0.1.129:319"
	conn, err := net.ListenPacket("udp", multicastAddr)

	if err != nil {
		fmt.Println("無法連接多播組:", err)
		return
	}

	defer conn.Close()
	go func() {
		buf := make([]byte, 1024)

		for {
			// 讀取封包
			n, _, err := conn.ReadFrom(buf)
			if err != nil {
				fmt.Println("無法讀取封包:", err)
				return
			}

			// 將封包內容轉換為字串
			pktdump(buf[:n])

		}
	}()
	cmd := exec.Command("sudo", "ptp4l", "-i", "enp0s9", "-SmE4", "-s", "-l 7")

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// 執行命令並檢查錯誤
	if err := cmd.Run(); err != nil {
		panic(err)
	}
}
