//go:build ignore

package main

import (
	"crypto/sha256"
	"debug/elf"
	"fmt"
	"io"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		panic("usage: verify-static ELF")
	}
	f, err := elf.Open(os.Args[1])
	if err != nil {
		panic(err)
	}
	defer f.Close()
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			panic("collector has a dynamic interpreter")
		}
	}
	libs, err := f.ImportedLibraries()
	if err != nil {
		panic(err)
	}
	if len(libs) != 0 {
		panic("collector has dynamic dependencies")
	}
	input, err := os.Open(os.Args[1])
	if err != nil {
		panic(err)
	}
	defer input.Close()
	h := sha256.New()
	if _, err = io.Copy(h, input); err != nil {
		panic(err)
	}
	fmt.Printf("Verified static ELF (%s); SHA256=%x\n", f.Machine, h.Sum(nil))
}
