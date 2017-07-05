package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"text/template"

	"github.com/davidlazar/go-crypto/encoding/base32"
	"github.com/davidlazar/seal/cmd/internal/seal"
)

var keyPath = flag.String("key", "", "path to key file")

func init() {
	log.SetFlags(0)
	log.SetPrefix("seal-edit: ")
}

func main() {
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		fmt.Println("Must specify at least one file argument.")
		os.Exit(1)
	}

	needPrivateKey := false

	for _, file := range args {
		_, err := os.Stat(file)
		if err == nil {
			needPrivateKey = true
		} else if os.IsNotExist(err) {
			continue
		} else if err != nil {
			log.Fatal(err)
		}
	}

	var publicKey, privateKey *[32]byte
	var keyName string

	if needPrivateKey {
		keyName, privateKey = seal.ReadPrivateKey(*keyPath)
		publicKey = seal.PublicKey(privateKey)
	} else {
		keyName, publicKey = seal.ReadPublicKey(*keyPath)
	}

	for _, file := range args {
		origContent := getContents(file, privateKey)
		editor(file, origContent, keyName, publicKey)
	}
}

func getContents(file string, privateKey *[32]byte) []byte {
	origCtxt, err := ioutil.ReadFile(file)
	if os.IsNotExist(err) {
		return nil
	} else if err != nil {
		log.Fatal(err)
	}

	origContents, err := seal.Open(privateKey, origCtxt)
	if err != nil {
		log.Fatalf("error decrypting %s: %s", file, err)
	}
	return origContents
}

const lineSeparator = "------------------------ 8< ------------------------\n"

var headerTemplate = template.Must(template.New("header").Parse(
	`# File: {{.FileName}}
# Key: {{.KeyName}} ({{.Key}})
# Do not remove the following line.
{{.LineSeparator}}`))

type templateData struct {
	Key           string
	KeyName       string
	FileName      string
	LineSeparator string
}

func editor(file string, startContents []byte, keyName string, publicKey *[32]byte) {
	stdin := new(bytes.Buffer)
	err := headerTemplate.Execute(stdin, templateData{
		Key:           base32.EncodeToString(publicKey[:]),
		KeyName:       keyName,
		FileName:      file,
		LineSeparator: lineSeparator,
	})
	if err != nil {
		log.Fatalf("error executing template: %s", err)
	}
	if len(startContents) > 0 {
		stdin.Write(startContents)
	}

	stdout := new(bytes.Buffer)
	cmd := exec.Command("vis", "-")
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		log.Fatal(err)
	}

	data := stdout.Bytes()
	if len(data) == 0 {
		fmt.Fprintf(os.Stderr, "Did not modify %s (quit without save)\n", file)
		return
	}

	ix := bytes.Index(data, []byte(lineSeparator))
	if ix == -1 {
		log.Fatalf("missing line separator")
	}
	msg := data[ix+len(lineSeparator):]
	ctxt := seal.Seal(publicKey, msg)
	err = ioutil.WriteFile(file, ctxt, 0600)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Fprintf(os.Stderr, "Wrote %s (encrypted with key %s)\n", file, keyName)
}
