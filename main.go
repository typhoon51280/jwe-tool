package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/typhoon51280/jwe-tool/crypto"
	"github.com/typhoon51280/jwe-tool/ioutil"
	"github.com/typhoon51280/jwe-tool/key"

	jose "github.com/go-jose/go-jose/v3"
	jwt "github.com/golang-jwt/jwt/v4"
)

var flgOp = flag.String("command", "decrypt", "encrypt|decrypt|verify|sign")
var privateKeyPath = flag.String("encKey", "", "private enc key path")
var token = flag.String("token", "", "token")
var publicKeyPath = flag.String("encPub", "", "public enc key path")
var signPrivateKeyPath = flag.String("sigKey", "", "private sign key path")
var signPublicKeyPath = flag.String("sigPub", "", "public sign key path")
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
	fmt.Printf("encryptedData: %v", encryptedData)
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

	var pub interface{}
	pub, err := key.LoadPublicKey(*publicKeyPath, *kid)
	if err != nil {
		log.Fatalf("%v", err)
	}
	// if len(*jwksPath) > 0 {
	// 	data := key.LoadJSONWebKeySet(*jwksPath, *kid)
	// 	if len(data) > 0 {
	// 		pub = data[0].Public().Key
	// 	}
	// } else {
	// 	data, err := key.LoadPublicKey(*publicKeyPath)
	// 	if err != nil {
	// 		fmt.Printf("unable to read public key: %v\n", err)
	// 	}
	// 	pub = data
	// }
	input, err := os.ReadFile(*inFile)
	if err != nil {
		log.Fatalf("unable to read json file: %v", err)
	}

	output := crypto.Encode(input, pub, *encryptAlgFlag, *encryptEncFlag, *encryptFullFlag)
	ioutil.WriteOutput(*outFile, []byte(output))
}

func sign() {
	payload, err := os.ReadFile(*inFile)
	if err != nil {
		log.Fatalf("Error load payload: %v", err)
	}
	privateKey, err := key.LoadPrivateKey(*signPrivateKeyPath)
	if err != nil {
		log.Fatalf("Error load private key: %v", err)
	}
	serialized := crypto.Sign(payload, privateKey, *signAlgFlag)
	ioutil.WriteOutput(*outFile, []byte(serialized))
}

func verify() {
	jws := ioutil.LoadInput(*inFile)
	publicKey, err := key.LoadPublicKey(*publicKeyPath, "")
	if err != nil {
		log.Fatalf("Error reading private key: %v", err)
	}
	tokenSigned, err := jose.ParseSigned(jws)
	if err != nil {
		log.Fatalf("Error parsing jws: %v", err)
	}
	fmt.Printf("tokenSigned: %v\n", tokenSigned.FullSerialize())

	verified, err := tokenSigned.Verify(publicKey)
	if err != nil {
		log.Fatalf("Error verifying jws: %v", err)
	}
	fmt.Printf("Verified: %s\n", verified)

}
