package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/Alkorin/nflog"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	TCP = 6
	UDP = 17
)

func main() {
	urlFlag := flag.String("url", "", "Slack webhook URL")
	groupsFlag := flag.String("groups", "", "NFLog groups to watch, 0-65535, comma separated, max 32")
	flag.Parse()

	if urlFlag == nil || *urlFlag == "" {
		log.Fatalln("-url flag is mandatory")
	}
	if _, err := url.Parse(*urlFlag); err != nil {
		log.Fatalln("Invalid URL:", err)
	}

	groups := []uint16{}
	groupsStrings := strings.Split(*groupsFlag, ",")
	for _, groupString := range groupsStrings {
		if group64, err := strconv.ParseUint(groupString, 10, 16); err == nil {
			if group64 > 65535 {
				log.Fatalln("Invalid group argument:", group64)
			}
			group := uint16(group64)
			groups = append(groups, group)
		} else {
			log.Fatalln("Invalid group argument:", err.Error())
		}
	}

	conf := nflog.NewConfig()
	conf.Groups = groups
	conf.CopyRange = 512
	conf.Return.Errors = false

	n, err := nflog.New(conf)
	if err != nil {
		log.Fatalln("Error starting nflog:", err.Error())
	}

	for {
		select {
		case m := <-n.Messages():
			go handle(m, *urlFlag)
		case e := <-n.Errors():
			log.Fatalln("nflog error:", e.Error())
		}
	}
}

func handle(msg nflog.Msg, url string) {
	data := map[string]string{}
	data["text"] = describePacket(&msg)
	payload, err := json.Marshal(data)
	if err != nil {
		log.Fatalln("Unable to prepare message:", err)
	}

	buf := bytes.NewBuffer(payload)
	resp, err := http.Post(url, "application/json", buf)
	if err != nil {
		log.Fatalln("Unable to post message:", err)
	}
	defer resp.Body.Close()
	if _, err := ioutil.ReadAll(resp.Body); err != nil {
		log.Fatalln("Error reading response:", err)
	}
}

func describePacket(msg *nflog.Msg) string {
	// TODO: replace all of this with gopacket/layers ?

	var meta struct {
		types   []string
		srcIP   net.IP
		dstIP   net.IP
		proto   int
		srcPort int
		dstPort int
		extra   []string
	}

	var str bytes.Buffer
	if len(msg.Prefix) > 0 {
		str.WriteString(msg.Prefix)
		str.WriteString(": ")
	}

	payload := msg.Payload

	// Layer 3
	ip4, err := ipv4.ParseHeader(payload)
	if err == nil {
		meta.types = append(meta.types, "IPv4")
		meta.srcIP = ip4.Src
		meta.dstIP = ip4.Dst
		meta.proto = ip4.Protocol
		payload = payload[ip4.Len:]
	} else if ip6, err := ipv6.ParseHeader(payload); err == nil {
		meta.types = append(meta.types, "IPv6")
		meta.srcIP = ip6.Src
		meta.dstIP = ip6.Dst
		meta.proto = ip6.NextHeader
		// lets hope...
		payload = payload[40:]
	}

	if len(meta.types) == 0 {
		str.WriteString("Unable to parse packet")
		return str.String()
	}

	// Layer 4
	switch meta.proto {
	case 0:
		// noop
	case TCP:
		meta.types = append(meta.types, "TCP")
		tcp := &layers.TCP{}
		err = tcp.DecodeFromBytes(payload, gopacket.NilDecodeFeedback)
		if err != nil {
			meta.extra = append(meta.extra, err.Error())
		} else {
			meta.srcPort = int(tcp.SrcPort)
			meta.dstPort = int(tcp.DstPort)
		}
	case UDP:
		meta.types = append(meta.types, "UDP")
		udp := &layers.UDP{}
		err = udp.DecodeFromBytes(payload, gopacket.NilDecodeFeedback)
		if err != nil {
			meta.extra = append(meta.extra, err.Error())
		} else {
			meta.srcPort = int(udp.SrcPort)
			meta.dstPort = int(udp.DstPort)
		}
	}

	str.WriteString(strings.Join(meta.types, "+"))
	str.WriteString(" ")
	str.WriteString(meta.srcIP.String())
	if meta.srcPort != 0 {
		str.WriteString(":")
		str.WriteString(fmt.Sprintf("%d", meta.srcPort))
	}
	str.WriteString(" -> ")
	str.WriteString(meta.dstIP.String())
	if meta.dstPort != 0 {
		str.WriteString(":")
		str.WriteString(fmt.Sprintf("%d", meta.dstPort))
	}
	if len(meta.extra) > 0 {
		str.WriteString("\n```\n")
		for _, extra := range meta.extra {
			str.WriteString(extra)
			str.WriteString("\n")
		}
		str.WriteString("\n```")
	}

	return str.String()
}
