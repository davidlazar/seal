package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/user"
	"path/filepath"

	"github.com/davidlazar/go-crypto/encoding/base32"
	"github.com/davidlazar/seal/cmd/internal/seal"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/ssh/terminal"
)

func init() {
	log.SetFlags(0)
	log.SetPrefix("seal-keygen: ")
}

func main() {
	appDir := seal.Appdir()
	err := os.Mkdir(appDir, 0700)
	if err == nil {
		fmt.Printf("Created directory %s\n", appDir)
	} else if !os.IsExist(err) {
		log.Fatal(err)
	}

	u, err := user.Current()
	if err != nil {
		log.Fatal(err)
	}
	privatePath := filepath.Join(appDir, u.Username+".privatekey")
	publicPath := filepath.Join(appDir, u.Username+".publickey")
	checkOverwrite(privatePath)
	checkOverwrite(publicPath)

	pw := confirmPassphrase()

	publicKey, privateKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	dk := seal.DeriveKey(pw)
	var boxKey [32]byte
	copy(boxKey[:], dk)
	var nonce [24]byte
	_, err = rand.Read(nonce[:])
	if err != nil {
		panic(err)
	}
	msg := privateKey[:]
	ctxt := secretbox.Seal(nonce[:], msg, &nonce, &boxKey)

	err = ioutil.WriteFile(publicPath, []byte(base32.EncodeToString(publicKey[:])+"\n"), 0600)
	if err != nil {
		log.Fatalf("failed to write public key: %s", err)
	}
	fmt.Printf("Wrote public key: %s\n", publicPath)

	err = ioutil.WriteFile(privatePath, []byte(base32.EncodeToString(ctxt)+"\n"), 0600)
	if err != nil {
		log.Fatalf("failed to write private key: %s", err)
	}
	fmt.Printf("Wrote private key: %s\n", privatePath)
}

func confirmPassphrase() []byte {
	for {
		fmt.Fprintf(os.Stderr, "Enter passphrase: ")
		pw, err := terminal.ReadPassword(0)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			log.Fatalf("terminal.ReadPassword: %s", err)
		}

		if len(pw) == 0 {
			continue
		}

		fmt.Fprintf(os.Stderr, "Enter same passphrase again: ")
		again, err := terminal.ReadPassword(0)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			log.Fatalf("terminal.ReadPassword: %s", err)
		}

		if bytes.Equal(pw, again) {
			return pw
		}

		fmt.Fprintf(os.Stderr, "Passphrases do not match. Try again.\n")
	}
}

func checkOverwrite(path string) {
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		return
	}
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s already exists.\n", path)
	fmt.Printf("Overwrite (y/N)? ")
	var yesno [3]byte
	n, err := os.Stdin.Read(yesno[:])
	if err != nil {
		log.Fatal(err)
	}
	if n == 0 {
		os.Exit(1)
	}
	if yesno[0] != 'y' && yesno[0] != 'Y' {
		os.Exit(1)
	}
}
