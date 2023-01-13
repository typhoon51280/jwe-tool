package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"

	color "github.com/fatih/color"
	jose "github.com/go-jose/go-jose/v3"
	jwt "github.com/golang-jwt/jwt/v4"
)

var privateKeyPath = flag.String("key", "", "private key path")
var token = flag.String("token", "", "token")

func main() {
	flag.Parse()

	keyBytes, err := os.ReadFile(*privateKeyPath)
	if err != nil {
		fmt.Printf("unable to read private key file: %v", err)
		os.Exit(1)
	}

	privateKey, err := LoadPrivateKey(keyBytes)
	if err != nil {
		fmt.Printf("unable to read private key: %v", err)
		os.Exit(1)
	}

	encryptedData, err := jose.ParseEncrypted(*token)
	if err != nil {
		fmt.Printf("unable to parse message: %v", err)
		os.Exit(1)
	}

	plaintext, err := encryptedData.Decrypt(privateKey)
	if err != nil {
		fmt.Printf("unable to decrypt message: %v", err)
		os.Exit(1)
	}

	jwtToken, err := jwt.Parse(string(plaintext), nil)
	if token == nil {
		fmt.Printf("malformed token: %v", err)
		os.Exit(1)
	}

	color.Set(color.FgHiYellow, color.Bold)
	fmt.Println("")
	fmt.Println("Token Header:")
	fmt.Println("-------------")
	color.Unset()
	if err := printJSON(jwtToken.Header); err != nil {
		fmt.Printf("failed to output header: %v", err)
		os.Exit(1)
	}

	color.Set(color.FgHiYellow, color.Bold)
	fmt.Println("")
	fmt.Println("Token Claims:")
	fmt.Println("-------------")
	color.Unset()
	if err := printJSON(jwtToken.Claims); err != nil {
		fmt.Printf("failed to output claims: %v", err)
		os.Exit(1)
	}

}

func printJSON(j interface{}) error {
	var out []byte
	var err error
	out, err = json.MarshalIndent(j, "", "    ")
	if err == nil {
		color.Set(color.BgRed, color.FgWhite, color.Bold)
		fmt.Println(string(out))
		color.Unset()
	}
	return err
}

func LoadPrivateKey(data []byte) (interface{}, error) {
	input := data

	block, _ := pem.Decode(data)
	if block != nil {
		input = block.Bytes
	}

	var priv interface{}
	priv, err0 := x509.ParsePKCS1PrivateKey(input)
	if err0 == nil {
		return priv, nil
	}

	priv, err1 := x509.ParsePKCS8PrivateKey(input)
	if err1 == nil {
		return priv, nil
	}

	priv, err2 := x509.ParseECPrivateKey(input)
	if err2 == nil {
		return priv, nil
	}

	return nil, errors.New("parse error, invalid private key")
}
