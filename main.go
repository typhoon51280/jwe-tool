package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/typhoon51280/jwe-tool/ioutil"
	"github.com/typhoon51280/jwe-tool/key"

	jose "github.com/go-jose/go-jose/v3"
	jwt "github.com/golang-jwt/jwt/v4"
)

var flgOp = flag.String("command", "decrypt", "encrypt|decrypt|verify|sign")
var privateKeyPath = flag.String("key", "", "private key path")
var token = flag.String("token", "", "token")
var publicKeyPath = flag.String("pub", "", "public key path")
var jwksPath = flag.String("jwks", "", "JWKS file path")
var kid = flag.String("kid", "PROSPECT", "Key ID")
var inFile = flag.String("in", "", "output file path")
var outFile = flag.String("out", "", "output file path")
var encryptFullFlag = flag.Bool("full", false, "encrypt full flag")
var encryptAlgFlag = flag.String("algEnc", "RSA-OAEP", "encrypt algorithm")
var encryptEncFlag = flag.String("enc", "A128GCM", "encrypt encoding")
var signAlgFlag = flag.String("algSig", "RS256", "encrypt algorithm")

func main() {
	flag.Parse()
	switch *flgOp {
	case "encrypt":
		encrypt()
	case "decrypt":
		decrypt()
	case "verify":
		verify()
	case "sign":
		sign()
	default:
		fmt.Println("pass either encrypt|decrypt|verify|sign")
	}
}

func decrypt() {

	privateKey, err := key.LoadPrivateKey(*privateKeyPath)
	if err != nil {
		log.Fatalf("unable to read private key: %v", err)
	}

	var data string
	if len(*token) > 0 {
		data = *token
	} else if len(*inFile) > 0 {
		data = ioutil.LoadInput(*inFile)
	} else {
		log.Fatalln("pass either -in or -token")
	}

	encryptedData, err := jose.ParseEncrypted(data)
	if err != nil {
		log.Fatalf("unable to parse message: %v", err)
	}

	plaintext, err := encryptedData.Decrypt(privateKey)
	if err != nil {
		log.Fatalf("unable to decrypt message: %v", err)
	}

	ioutil.PrintText(plaintext)

	jwtToken, err := jwt.Parse(string(plaintext), nil)
	if token == nil {
		log.Fatalf("malformed token: %v", err)
	}

	ioutil.PrintHeader(jwtToken.Header)
	ioutil.PrintClaims(jwtToken.Claims)

	fmt.Println("")
}

func encrypt() {

	pub, err := key.LoadPublicKey(*publicKeyPath)
	if err != nil {
		fmt.Printf("unable to read public key: %v\n", err)
	}

	alg := jose.KeyAlgorithm(*encryptAlgFlag)
	enc := jose.ContentEncryption(*encryptEncFlag)

	// fmt.Printf("alg: %s\n", alg)
	// fmt.Printf("pub: %s\n", pub)
	// fmt.Printf("enc: %s\n", enc)

	crypter, err := jose.NewEncrypter(enc, jose.Recipient{Algorithm: alg, Key: pub}, nil)
	if err != nil {
		fmt.Printf("unable to instantiate encrypter: %v\n", err)
		os.Exit(1)
	}

	jsonBytes, err := os.ReadFile(*inFile)
	if err != nil {
		fmt.Printf("unable to read json file: %v", err)
		os.Exit(1)
	}

	obj, err := crypter.Encrypt(jsonBytes)
	if err != nil {
		fmt.Printf("unable to encrypt: %v", err)
		os.Exit(1)
	}

	var msg string
	if *encryptFullFlag {
		msg = obj.FullSerialize()
	} else {
		msg, err = obj.CompactSerialize()
		if err != nil {
			fmt.Printf("unable to serialize message: %v", err)
			os.Exit(1)
		}
	}
	ioutil.WriteOutput(*outFile, []byte(msg))
}

func sign() {
	payload, err := os.ReadFile(*inFile)
	if err != nil {
		log.Fatalf("Error load payload: %v", err)
	}
	privateKey, err := key.LoadPrivateKey(*privateKeyPath)
	if err != nil {
		log.Fatalf("Error load private key: %v", err)
	}
	alg := jose.SignatureAlgorithm(*signAlgFlag)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: privateKey}, nil)
	if err != nil {
		log.Fatalf("Signer not created: %v", err)
	}
	object, err := signer.Sign(payload)
	if err != nil {
		log.Fatalf("Error sign  %v", err)
	}
	serialized, err := object.CompactSerialize()
	if err != nil {
		log.Fatalf("Error serialization  %v", err)
	}
	ioutil.WriteOutput(*outFile, []byte(serialized))
}

func verify() {
	jws := ioutil.LoadInput(*inFile)
	publicKey, err := key.LoadPublicKey(*publicKeyPath)
	if err != nil {
		log.Fatalf("Error reading private key: %v", err)
	}
	tokenSigned, err := jose.ParseSigned(jws)
	if err != nil {
		log.Fatalf("Error parsing jws: %v", err)
	}
	fmt.Printf("tokenSigned: %v\n", tokenSigned.FullSerialize())

	verified, err := tokenSigned.Verify(publicKey)

	jwt.Parse()
	if err != nil {
		log.Fatalf("Error verifying jws: %v", err)
	}
	fmt.Printf("Verified: %s\n", verified)

}
