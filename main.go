package main

import (
	"flag"
	"fmt"

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
var encryptCypher = flag.String("cypher", "A128GCM", "encrypt cypher")
var encryptAlgorithm = flag.String("alg-encode", "RSA-OAEP", "encrypt algorithm")
var signAlgorithm = flag.String("alg-sign", "RS256", "encrypt algorithm")
var duration = flag.String("duration", "1h", "token duration")

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

func createEncOptions(privateKey interface{}, publicKey interface{}) crypto.EncodeOptions {
	encOptions := crypto.EncodeOptions{
		Algorithm:  *encryptAlgorithm,
		Encoding:   *encryptCypher,
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}
	return encOptions
}

func createSignOptions(privateKey interface{}, publicKey interface{}) crypto.SignOptions {
	signOptions := crypto.SignOptions{
		Algorithm:  *signAlgorithm,
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		Kid:        *kid,
		Duration:   *duration,
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

	encKeyBytes := ioutil.LoadInput(*encKeyPath)
	encPrivateKey, encPublicKey, err := key.LoadKeyPair(encKeyBytes, true)
	if err != nil {
		log.Fatal().Err(err).Msgf("Error loading encrypt private key %v", *encKeyPath)
	}
	log.Debug().Msgf("Decrypt Private Key Loaded")

	encOptions := createEncOptions(encPrivateKey, encPublicKey)
	sigKeyBytes := ioutil.LoadInput(*sigKeyPath)
	sigPublicKey, err := key.LoadPublicKey(sigKeyBytes, *kid, true)
	if err != nil {
		log.Fatal().Err(err).Msgf("Error loading sign public key %v", *sigKeyPath)
	}
	signOptions := createSignOptions(nil, sigPublicKey)

	plaintext, token := crypto.Decode(input, encOptions, signOptions)
	log.Info().Msgf("JWT Serialized |-\n%s", ioutil.PrintText("JWT", plaintext, color.BgCyan, color.FgWhite, color.Bold))
	log.Info().Msgf("JWT Parsed |-\n%s", ioutil.PrintJWT(token, signOptions.PublicKey))

	if len(*outFile) > 0 {
		ioutil.WriteOutput(*outFile, plaintext)
	}

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

	encKeyBytes := ioutil.LoadInput(*encKeyPath)
	encPublicKey, err := key.LoadPublicKey(encKeyBytes, *kid, true)
	if err != nil {
		log.Fatal().Err(err).Msgf("Error loading encrypt public key %v %v", *encKeyPath, kid)
	}
	log.Debug().Msgf("Encrypt Public Key Loaded")

	encOptions := createEncOptions(nil, encPublicKey)
	sigKeyBytes := ioutil.LoadInput(*sigKeyPath)
	sigPrivateKey, sigPublicKey, err := key.LoadKeyPair(sigKeyBytes, true)
	if err != nil {
		log.Fatal().Err(err).Msgf("Error loading sign private key %v", *sigKeyPath)
	}
	signOptions := createSignOptions(sigPrivateKey, sigPublicKey)

	tokenEncrypted, token := crypto.Encode(input, encOptions, signOptions)
	log.Info().Msgf("JWT Parsed |-\n%s", ioutil.PrintJWT(token, signOptions.PublicKey))
	log.Info().Msgf("JWE Serialized |-\n%s", ioutil.PrintText("JWE", tokenEncrypted, color.BgCyan, color.FgWhite, color.Bold))

	if len(*outFile) > 0 {
		ioutil.WriteOutput(*outFile, tokenEncrypted)
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

	sigKeyBytes := ioutil.LoadInput(*sigKeyPath)
	sigPrivateKey, sigPublicKey, err := key.LoadKeyPair(sigKeyBytes, true)
	if err != nil {
		log.Fatal().Err(err).Msgf("Error loading sign private key %s", *sigKeyPath)
	}
	log.Info().Msg("Sign Private Key Loaded")

	signOptions := createSignOptions(sigPrivateKey, sigPublicKey)

	serialized, token := crypto.Sign(input, signOptions)

	if len(*outFile) > 0 {
		ioutil.WriteOutput(*outFile, serialized)
	}

	log.Info().Msgf("JWT Parsed |-\n%s", ioutil.PrintJWT(token, signOptions.PublicKey))
	log.Info().Msgf("JWT Serialized |-\n%s", ioutil.PrintText("JWT", serialized, color.BgCyan, color.FgWhite, color.Bold))

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

	sigKeyBytes := ioutil.LoadInput(*sigKeyPath)
	sigPublicKey, err := key.LoadPublicKey(sigKeyBytes, *kid, true)
	if err != nil {
		log.Fatal().Err(err).Msgf("Error loading sign public key %v %v", *sigKeyPath, *kid)
	}
	log.Info().Msg("Sign Public Key Loaded")

	signOptions := createSignOptions(nil, sigPublicKey)
	token := crypto.Verify(input, signOptions)

	log.Info().Msgf("JWT Serialized |-\n%s", ioutil.PrintText("JWT", token.Raw, color.BgCyan, color.FgWhite, color.Bold))
	log.Info().Msgf("JWT Parsed |-\n%s", ioutil.PrintJWT(token, signOptions.PublicKey))

	log.Info().Msg("DONE 😀")

}
