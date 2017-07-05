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
	log.SetPrefix("seal: ")
}

func main() {
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		fmt.Println("Must specify at least one file argument.")
		os.Exit(1)
	}

	keyName, publicKey := seal.ReadPublicKey(*keyPath)

	for _, file := range args {
		msg, err := ioutil.ReadFile(file)
		if err != nil {
			log.Fatal(err)
		}
		ctxt := seal.Seal(publicKey, msg)
		newFile := file + ".sealed"
		err = ioutil.WriteFile(newFile, ctxt, 0600)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Wrote %s (encrypted with key %s)\n", newFile, keyName)
	}
}
