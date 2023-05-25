package main

import (
	"fmt"
	"syscall"
)

func main() {
	id, err := syscall.Sysctl("kern.uuid")
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s", id)
}
