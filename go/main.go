package main

import (
	"fmt"
	"os"
	"os/signal"

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
	var opts ebpf.CollectionOptions
	opts.Programs.LogLevel = ebpf.LogLevelStats | ebpf.LogLevelBranch | ebpf.LogLevelInstruction

	err = spec.LoadAndAssign(&objs, &opts)
	if err != nil {
		panic(err)
	}

	// Attach tracepoints
	// see https://github.com/cilium/ebpf/discussions/1372
	// TODO: Automate this using reflection?
	{
		l, err := link.AttachRawTracepoint(link.RawTracepointOptions{
			Name:    "block_rq_issue",
			Program: objs.BlockRqIssue,
		})
		if err != nil {
			panic(err)
		}
		defer l.Close()
	}
	{
		l, err := link.AttachRawTracepoint(link.RawTracepointOptions{
			Name:    "block_rq_insert",
			Program: objs.BlockRqInsert,
		})
		if err != nil {
			panic(err)
		}
		defer l.Close()
	}
	{
		l, err := link.AttachRawTracepoint(link.RawTracepointOptions{
			Name:    "block_rq_complete",
			Program: objs.BlockRqComplete,
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
