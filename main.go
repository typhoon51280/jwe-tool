package main

import (
	"encoding/json"
	"flag"
	"fmt"

	"github.com/rs/zerolog/log"
	"github.com/typhoon51280/jwe-tool/crypto"
	"github.com/typhoon51280/jwe-tool/ioutil"
	"github.com/typhoon51280/jwe-tool/key"
)

var flgOp = flag.String("command", "decrypt", "encrypt|decrypt|verify|sign")
var token = flag.String("token", "", "token")
var encKeyPath = flag.String("encKey", "", "encrypt key path")

// var publicKeyPath = flag.String("encPub", "", "public enc key path")
var sigKeyPath = flag.String("sigKey", "", "sign key path")

// var signPublicKeyPath = flag.String("sigPub", "", "public sign key path")
var jwksPath = flag.String("jwks", "", "JWKS file path")
var kid = flag.String("kid", "PROSPECT", "Key ID")
var inFile = flag.String("in", "", "output file path")
var outFile = flag.String("out", "", "output file path")
var encryptFullFlag = flag.Bool("encFull", false, "encrypt full flag")
var encryptAlgFlag = flag.String("algEnc", "RSA-OAEP", "encrypt algorithm")
var encryptEncFlag = flag.String("enc", "A128GCM", "encrypt encoding")
var signAlgFlag = flag.String("algSig", "RS256", "encrypt algorithm")
var signFullFlag = flag.Bool("signFull", false, "sign full flag")

func main() {
	ioutil.InitLogger(ioutil.LogParameters{})
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

	if len(*encKeyPath) == 0 {
		log.Fatal().Msg("Missing parameter: -encKey")
	}
	if len(*inFile) == 0 && len(*token) == 0 {
		log.Fatal().Msg("Pass either -in or -token")
	}

	log.Info().Msg("Start decrypting ...")

	input := *token
	if len(*inFile) > 0 {
		input = ioutil.LoadInputStr(*inFile)
	}

	encKey, err := key.LoadPrivateKey(*encKeyPath)
	if err != nil {
		log.Fatal().Err(err).Msgf("Error loading encrypt private key %v", *encKeyPath)
	}
	log.Debug().Msgf("Decrypt Private Key Loaded")

	encOptions := crypto.EncodeOptions{
		Algorithm: *encryptAlgFlag,
		Encoding:  *encryptEncFlag,
		Key:       encKey,
		Full:      *encryptFullFlag,
		Sign:      len(*sigKeyPath) > 0,
	}
	signOptions := crypto.SignOptions{
		Algorithm: *signAlgFlag,
		Full:      *signFullFlag,
	}

	plaintext := crypto.Decode(input, encOptions, signOptions)

	ioutil.PrintText(plaintext)
	ioutil.PrintJWT(plaintext)

	log.Info().Msg("DONE :)")
}

func encrypt() {

	if len(*encKeyPath) == 0 {
		log.Fatal().Msg("Missing parameter: -encKey")
	}
	if len(*inFile) == 0 {
		log.Fatal().Msg("Missing parameter: -in")
	}

	log.Info().Msg("Start encrypting ...")

	input := ioutil.LoadInputStr(*inFile)

	encKey, err := key.LoadPublicKey(*encKeyPath, *kid)
	if err != nil {
		log.Fatal().Err(err).Msgf("Error loading encrypt public key %v %v", *encKeyPath, kid)
	}
	log.Debug().Msgf("Encrypt Public Key Loaded")

	encOptions := crypto.EncodeOptions{
		Algorithm: *encryptAlgFlag,
		Encoding:  *encryptEncFlag,
		Key:       encKey,
		Full:      *encryptFullFlag,
		Sign:      len(*sigKeyPath) > 0,
	}
	signOptions := crypto.SignOptions{
		Algorithm: *signAlgFlag,
		Full:      *signFullFlag,
	}
	if encOptions.Sign {
		sigKey, err1 := key.LoadPrivateKey(*sigKeyPath)
		if err1 != nil {
			log.Fatal().Err(err1).Msgf("Error loading sign private key %v", *sigKeyPath)
		}
		signOptions.Key = sigKey
	}

	output := crypto.Encode(input, encOptions, signOptions)
	ioutil.WriteOutput(*outFile, output)

	log.Info().Msg("DONE :)")

}

func sign() {

	if len(*sigKeyPath) == 0 {
		log.Fatal().Msg("Missing parameter: -sigKey")
	}
	if len(*inFile) == 0 {
		log.Fatal().Msg("Missing parameter: -in")
	}

	log.Info().Msg("Start signing ...")

	input := ioutil.LoadInputStr(*inFile)

	sigKey, err := key.LoadPrivateKey(*sigKeyPath)
	if err != nil {
		log.Fatal().Err(err).Msgf("Error loading sign private key %v", *sigKeyPath)
	}
	log.Debug().Msg("Sign Private Key Loaded")

	signOptions := crypto.SignOptions{
		Algorithm: *signAlgFlag,
		Key:       sigKey,
		Full:      *signFullFlag,
	}

	serialized := crypto.Sign(input, signOptions)
	ioutil.WriteOutput(*outFile, serialized)

	log.Info().Msg("DONE :)")

}

func verify() {

	if len(*sigKeyPath) == 0 {
		log.Fatal().Msg("Missing parameter: -sigKey")
	}
	if len(*inFile) == 0 {
		log.Fatal().Msg("Missing parameter: -in")
	}

	log.Info().Msg("Start verifying ...")

	input := ioutil.LoadInputStr(*inFile)

	sigKey, err := key.LoadPublicKey(*sigKeyPath, *kid)
	if err != nil {
		log.Fatal().Err(err).Msgf("Error loading sign public key %v %v", *sigKeyPath, *kid)
	}
	log.Debug().Msg("Sign Public Key Loaded")

	signOptions := crypto.SignOptions{
		Algorithm: *signAlgFlag,
		Key:       sigKey,
		Full:      *signFullFlag,
	}

	plaintext := crypto.Verify(input, signOptions)
	var jwt interface{}
	json.Unmarshal([]byte(plaintext), &jwt)
	ioutil.PrintBody(jwt)

	log.Info().Msg("DONE :)")

}
