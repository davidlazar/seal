package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/davidlazar/seal/cmd/internal/seal"
)

var keyPath = flag.String("key", "", "path to key file")

func init() {
	log.SetFlags(0)
	log.SetPrefix("seal-cat: ")
}

func main() {
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		fmt.Println("Must specify at least one file argument.")
		os.Exit(1)
	}

	_, privateKey := seal.ReadPrivateKey(*keyPath)

	for _, file := range args {
		ctxt, err := ioutil.ReadFile(file)
		if err != nil {
			log.Fatal(err)
		}
		msg, err := seal.Open(privateKey, ctxt)
		if err != nil {
			log.Fatalf("error decrypting %s: %s", file, err)
		}
		os.Stdout.Write(msg)
	}
}
