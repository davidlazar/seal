package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strings"
	"text/template"
	"time"

	"github.com/davidlazar/clipboard"
	"github.com/davidlazar/go-crypto/encoding/base32"
	"github.com/davidlazar/seal/cmd/internal/seal"
)

var keyPath = flag.String("key", "", "path to key file")

func init() {
	log.SetFlags(0)
	log.SetPrefix("seal-pw: ")
}

func main() {
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		fmt.Println("Must specify at least one file argument.")
		os.Exit(1)
	}

	if len(args) == 1 {
		_, err := os.Stat(args[0])
		if err == nil {
			readPW(args[0])
			return
		} else if os.IsNotExist(err) {
			createPW(args[0])
			return
		} else if err != nil {
			log.Fatal(err)
		}
	}

	// act like `cat` with multiple args
	_, privateKey := seal.ReadPrivateKey(*keyPath)
	for _, file := range args {
		ctxt, err := ioutil.ReadFile(file)
		if err != nil {
			log.Fatal(err)
		}
		msg, err := seal.Open(privateKey, ctxt)
		if err != nil {
			log.Printf("error decrypting %s: %s", file, err)
		}
		fmt.Println()
		os.Stdout.Write(msg)
	}
}

func readPW(file string) {
	_, privateKey := seal.ReadPrivateKey(*keyPath)
	ctxt, err := ioutil.ReadFile(file)
	if err != nil {
		log.Fatal(err)
	}
	msg, err := seal.Open(privateKey, ctxt)
	if err != nil {
		log.Printf("error decrypting %s: %s", file, err)
	}

	var clip []byte
	scanner := bufio.NewScanner(bytes.NewReader(msg))
	for scanner.Scan() {
		line := scanner.Text()
		if clip == nil && strings.HasPrefix(line, "clipboard: ") {
			clip = []byte(strings.TrimSpace(strings.TrimPrefix(line, "clipboard: ")))
		} else {
			fmt.Println(line)
		}
	}

	if clip != nil {
		fmt.Fprintf(os.Stderr, "Password copied to clipboard for 10 seconds.\n")
		clipboard.SetClipboardTemporarily(clip, 10*time.Second)
	}
}

const lineSeparator = "------------------------ 8< ------------------------\n"

var pwTemplate = template.Must(template.New("pw").Parse(
	`# File: {{.FileName}}
# Key: {{.KeyName}} ({{.Key}})
# Do not remove the following line.
{{.LineSeparator}}url:
username:
# Uncomment one of the following randomly generated passwords.
# clipboard: {{.ShortPassword}}
# clipboard: {{.LongPassword}}
`))

type templateData struct {
	Key           string
	KeyName       string
	FileName      string
	LineSeparator string

	LongPassword  string
	ShortPassword string
}

const longCharset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
const shortCharset = "abcdefghijklmnopqrstuvwxyz0123456789"

func genPassword(charset []rune, length int) string {
	m := 256 % len(charset)
	buf := make([]byte, 256)

	pw := make([]rune, 0, length)
	for len(pw) < length {
		_, err := rand.Read(buf)
		if err != nil {
			panic(err)
		}
		for i := 0; i < len(buf) && len(pw) < length; i++ {
			r := int(buf[i])
			// ensure uniform distribution mod len(charset)
			if r < 256-m {
				pw = append(pw, charset[r%len(charset)])
			}
		}
	}
	return string(pw)
}

var zeroNonce [24]byte

func createPW(file string) {
	keyName, publicKey := seal.ReadPublicKey(*keyPath)

	stdin := new(bytes.Buffer)
	err := pwTemplate.Execute(stdin, templateData{
		Key:           base32.EncodeToString(publicKey[:]),
		KeyName:       keyName,
		FileName:      file,
		LineSeparator: lineSeparator,

		LongPassword:  genPassword([]rune(longCharset), 32),
		ShortPassword: genPassword([]rune(shortCharset), 16),
	})
	if err != nil {
		log.Fatalf("error executing template: %s", err)
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
