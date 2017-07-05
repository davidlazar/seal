package seal

import (
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/davidlazar/go-crypto/encoding/base32"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/ssh/terminal"
)

func Appdir() string {
	u, err := user.Current()
	if err != nil {
		log.Fatal(err)
	}
	return filepath.Join(u.HomeDir, ".seal")
}

func DeriveKey(passphrase []byte) []byte {
	dk, err := scrypt.Key(passphrase, []byte("seal"), 2<<15, 8, 1, 32)
	if err != nil {
		panic(err)
	}
	return dk
}

const ciphertextVersion byte = 1

var zeroNonce = new([24]byte)

func Seal(publicKey *[32]byte, msg []byte) []byte {
	freshPublicKey, freshPrivateKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	ctxt := make([]byte, 0, 1+len(freshPublicKey)+len(msg)+box.Overhead)
	ctxt = append(ctxt, ciphertextVersion)
	ctxt = append(ctxt, freshPublicKey[:]...)
	ctxt = box.Seal(ctxt, msg, zeroNonce, publicKey, freshPrivateKey)

	return []byte(base32.EncodeToString(ctxt) + "\n")
}

func Open(privateKey *[32]byte, ctxt []byte) ([]byte, error) {
	data, err := base32.DecodeString(strings.TrimSpace(string(ctxt)))
	if err != nil {
		return nil, fmt.Errorf("base32 decoding error: %s", err)
	}

	if data[0] != ciphertextVersion {
		return nil, fmt.Errorf("unknown ciphertext version: got %d, want %d", data[0], ciphertextVersion)
	}
	data = data[1:]

	var publicKey [32]byte
	copy(publicKey[:], data[0:32])

	msg, ok := box.Open(nil, data[32:], zeroNonce, &publicKey, privateKey)
	if !ok {
		return nil, fmt.Errorf("decryption failed")
	}

	return msg, nil
}

func PublicKey(privateKey *[32]byte) *[32]byte {
	var publicKey [32]byte
	curve25519.ScalarBaseMult(&publicKey, privateKey)
	return &publicKey
}

func ReadPublicKey(path string) (name string, publicKey *[32]byte) {
	if strings.HasSuffix(path, ".privatekey") {
		name, privateKey := ReadPrivateKey(path)
		return name, PublicKey(privateKey)
	}
	keyFile := findKeyFile(path, ".publickey")
	name = strings.TrimSuffix(filepath.Base(keyFile), ".publickey")
	data, err := ioutil.ReadFile(keyFile)
	if err != nil {
		log.Fatal(err)
	}

	// TODO in Go 1.9+ we can remove the TrimSpace call after updating the base32 package
	bs, err := base32.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		log.Fatalf("error decoding base32: %s: %s", keyFile, err)
	}

	if len(bs) != 32 {
		log.Fatalf("unexpected key length: %d bytes", len(bs))
	}

	publicKey = new([32]byte)
	copy(publicKey[:], bs)
	return name, publicKey
}

const nonceOverhead = 24

func ReadPrivateKey(path string) (name string, privateKey *[32]byte) {
	keyFile := findKeyFile(path, ".privatekey")
	name = strings.TrimSuffix(filepath.Base(keyFile), ".privatekey")
	data, err := ioutil.ReadFile(keyFile)
	if err != nil {
		log.Fatal(err)
	}

	bs, err := base32.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		log.Fatalf("error decoding base32: %s: %s", keyFile, err)
	}

	expectedSize := nonceOverhead + 32 + secretbox.Overhead
	if len(bs) != expectedSize {
		log.Fatalf("unexpected key length: got %d bytes, want %d", len(bs), expectedSize)
	}

	var nonce [24]byte
	copy(nonce[:], bs[0:24])
	ctxt := bs[24:]
	privateKey = new([32]byte)

	for {
		fmt.Fprintf(os.Stderr, "Enter passphrase for key %s: ", name)
		pw, err := terminal.ReadPassword(0)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			log.Fatalf("terminal.ReadPassword: %s", err)
		}

		dk := DeriveKey(pw)
		var boxKey [32]byte
		copy(boxKey[:], dk)

		msg, ok := secretbox.Open(nil, ctxt, &nonce, &boxKey)
		if ok {
			copy(privateKey[:], msg)
			break
		}
		fmt.Fprintln(os.Stderr, "Wrong passphrase. Try again.")
	}

	return name, privateKey
}

func findKeyFile(path string, extension string) string {
	if path == "" {
		dir := Appdir()
		matches, err := filepath.Glob(filepath.Join(dir, "*"+extension))
		if err != nil {
			panic(err)
		}
		switch len(matches) {
		case 0:
			fmt.Printf("No keys found in %s\n", dir)
			fmt.Println("Generate a new key using seal-keygen.")
			os.Exit(1)
		case 1:
			return matches[0]
		default:
			fmt.Printf("Found multiple keys: %v\n", matches)
			fmt.Println("Choose one using the -key flag.")
			os.Exit(1)
		}

	}

	_, err := os.Stat(path)
	if err == nil {
		return path
	}
	if !os.IsNotExist(err) {
		log.Fatal(err)
	}
	if filepath.IsAbs(path) {
		fmt.Printf("File not found: %s", path)
		os.Exit(1)
	}

	guess := filepath.Join(Appdir(), withExtension(path, extension))
	_, err = os.Stat(guess)
	if err == nil {
		return guess
	}
	if os.IsNotExist(err) {
		fmt.Printf("Key not found. Tried %q and %q.\n", path, guess)
		os.Exit(1)
	}
	log.Fatal(err)
	return ""

}

func withExtension(path string, ext string) string {
	if strings.HasSuffix(path, ext) {
		return path
	}
	return path + ext
}
