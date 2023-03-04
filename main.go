package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"strings"

	"github.com/fatih/color"
	"github.com/rs/zerolog/log"
	"github.com/typhoon51280/jwe-tool/crypto"
	"github.com/typhoon51280/jwe-tool/ioutil"
	"github.com/typhoon51280/jwe-tool/key"
)

var flgOp = flag.String("command", "decrypt", "encrypt|decrypt|verify|sign")
var token = flag.String("token", "", "token")
var encKeyPath = flag.String("enc", "", "encrypt key path")
var sigKeyPath = flag.String("sig", "", "sign key path")
var kid = flag.String("kid", "PROSPECT", "Key ID")
var inFile = flag.String("in", "", "output file path")
var outFile = flag.String("out", "", "output file path")
var serializationMode = flag.String("mode", "compact", "serialization mode: compact|full")
var encryptCypher = flag.String("cypher", "A128GCM", "encrypt cypher")
var encryptAlgorithm = flag.String("alg-encode", "RSA-OAEP", "encrypt algorithm")
var signAlgorithm = flag.String("alg-sign", "RS256", "encrypt algorithm")

// Logging
var logLevel = flag.String("log", "info", "log level: panic|fatal|error|warn|info|debug|trace\\all")
var logFilePath = flag.String("logfile", "", "log file path")

func main() {
	flag.Parse()
	logFile := ioutil.CreateLogFile(*logFilePath)
	if logFile != nil {
		defer logFile.Close()
	}
	ioutil.InitLogger(ioutil.LogParameters{
		File:  logFile,
		Level: *logLevel,
	})
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

func createEncOptions(key interface{}) crypto.EncodeOptions {
	encOptions := crypto.EncodeOptions{
		Algorithm: *encryptAlgorithm,
		Encoding:  *encryptCypher,
		Key:       key,
		Full:      (strings.ToLower(*serializationMode) == "full"),
		Sign:      len(*sigKeyPath) > 0,
	}
	return encOptions
}

func createSignOptions(key interface{}) crypto.SignOptions {
	signOptions := crypto.SignOptions{
		Algorithm: *signAlgorithm,
		Full:      (strings.ToLower(*serializationMode) == "full"),
		Key:       key,
	}
	return signOptions
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

	encPrivateKeyBytes := ioutil.LoadInput(*encKeyPath)
	encPrivateKey, err := key.LoadPrivateKey(encPrivateKeyBytes, true)
	if err != nil {
		log.Fatal().Err(err).Msgf("Error loading encrypt private key %v", *encKeyPath)
	}
	log.Debug().Msgf("Decrypt Private Key Loaded")

	encOptions := createEncOptions(encPrivateKey)
	signOptions := crypto.SignOptions{}
	if encOptions.Sign {
		sigPublicKeyBytes := ioutil.LoadInput(*sigKeyPath)
		if sigPublicKey, err := key.LoadPublicKey(sigPublicKeyBytes, *kid, true); err != nil {
			log.Fatal().Err(err).Msgf("Error loading sign public key %v", *sigKeyPath)
		} else {
			signOptions = createSignOptions(sigPublicKey)
		}
	}

	plaintext := crypto.Decode(input, encOptions, signOptions)

	ioutil.PrintText(plaintext, "Plaintext:", color.BgCyan, color.FgWhite, color.Bold)
	ioutil.PrintJWT(plaintext, signOptions.Key)

	log.Info().Msg("DONE 😀")
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

	encPublicKeyBytes := ioutil.LoadInput(*encKeyPath)
	encPublicKey, err := key.LoadPublicKey(encPublicKeyBytes, *kid, true)
	if err != nil {
		log.Fatal().Err(err).Msgf("Error loading encrypt public key %v %v", *encKeyPath, kid)
	}
	log.Debug().Msgf("Encrypt Public Key Loaded")

	encOptions := createEncOptions(encPublicKey)
	signOptions := crypto.SignOptions{}
	if encOptions.Sign {
		sigPrivateKeyBytes := ioutil.LoadInput(*sigKeyPath)
		if sigPrivateKey, err := key.LoadPrivateKey(sigPrivateKeyBytes, true); err != nil {
			log.Fatal().Err(err).Msgf("Error loading sign private key %v", *sigKeyPath)
		} else {
			signOptions = createSignOptions(sigPrivateKey)
		}
	}

	output := crypto.Encode(input, encOptions, signOptions)
	if *serializationMode == "full" {
		var fullJSON interface{}
		if err := json.Unmarshal([]byte(output), &fullJSON); err != nil {
			log.Fatal().Err(err).Msg("Failed unmarshalling JSON payload")
		} else {
			output = ioutil.PrettyJSON(fullJSON)
		}
	}
	if len(*outFile) > 0 {
		ioutil.WriteOutput(*outFile, output)
	} else {
		ioutil.PrintText(output, "Encrypted Data:", color.BgRed, color.FgWhite, color.Bold)
	}

	log.Info().Msg("DONE 😀")

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

	sigPrivateKeyBytes := ioutil.LoadInput(*sigKeyPath)
	sigPrivateKey, err := key.LoadPrivateKey(sigPrivateKeyBytes, true)
	if err != nil {
		log.Fatal().Err(err).Msgf("Error loading sign private key %s", *sigKeyPath)
	}
	log.Info().Msg("Sign Private Key Loaded")

	signOptions := crypto.SignOptions{
		Algorithm: *signAlgorithm,
		Key:       sigPrivateKey,
		Full:      (strings.ToLower(*serializationMode) == "full"),
	}

	serialized := crypto.Sign(input, signOptions)
	log.Info().Msg("Signed payload")

	ioutil.WriteOutput(*outFile, serialized)

	log.Info().Msg("DONE 😀")

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

	sigPublicKeyBytes := ioutil.LoadInput(*sigKeyPath)
	sigPublicKey, err := key.LoadPublicKey(sigPublicKeyBytes, *kid, true)
	if err != nil {
		log.Fatal().Err(err).Msgf("Error loading sign public key %v %v", *sigKeyPath, *kid)
	}
	log.Info().Msg("Sign Public Key Loaded")

	signOptions := crypto.SignOptions{
		Algorithm: *signAlgorithm,
		Key:       sigPublicKey,
		Full:      (strings.ToLower(*serializationMode) == "full"),
	}

	plaintext := crypto.Verify(input, signOptions)
	log.Info().Msg("Veryfied payload")
	var jwt interface{}
	json.Unmarshal([]byte(plaintext), &jwt)
	ioutil.PrintBody(jwt)

	log.Info().Msg("DONE 😀")

}
