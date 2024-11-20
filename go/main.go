package main

import (
	"fmt"
	"os"
	"os/signal"
	"reflect"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func main() {
	spec, err := loadBiolatency()
	if err != nil {
		panic(err)
	}

	// Set configuration constants
	err = spec.RewriteConstants(map[string]interface{}{
		"my_value": uint32(42),
		//"my_value2": uint32(42), // ERROR
	})
	if err != nil {
		panic(err)
	}

	var objs biolatencyObjects
	err = spec.LoadAndAssign(&objs, nil)
	if err != nil {
		panic(err)
	}

	// Attach tracepoints
	// see https://github.com/cilium/ebpf/discussions/1372
	val := reflect.ValueOf(objs.biolatencyPrograms)
	typ := reflect.TypeOf(objs.biolatencyPrograms)
	for i := range val.NumField() {
		field := typ.Field(i)
		value := val.Field(i)

		tag := field.Tag.Get("ebpf")
		if tag == "" {
			panic("missing ebpf tag")
		}

		fmt.Printf("Attach %v to %v\n", tag, value)
		l, err := link.AttachRawTracepoint(link.RawTracepointOptions{
			Name:    tag,
			Program: value.Interface().(*ebpf.Program),
		})
		if err != nil {
			panic(err)
		}
		defer l.Close()
	}

	fmt.Printf("Waiting for events, press Ctrl-C to stop...")
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)
	for {
		select {
		case <-stop:
			goto out
		}
	}

out:
	fmt.Println()
	fmt.Println("done")

	// TODO: Iterate map
	var key biolatencyDiskLatencyKeyT
	var value uint64

	entries := objs.biolatencyMaps.BioLatencySeconds.Iterate()
	for entries.Next(&key, &value) {
		fmt.Printf("%v: %v\n", key, value)
	}
}
