package crypto

import (
	"log"

	"github.com/go-jose/go-jose/v3"
)

func Encode(payload []byte, publicKey interface{}, algorithm string, encoding string, full bool) string {
	alg := jose.KeyAlgorithm(algorithm)
	enc := jose.ContentEncryption(encoding)
	recpt := jose.Recipient{Algorithm: alg, Key: publicKey}
	opts := jose.EncrypterOptions{}
	crypter, err := jose.NewEncrypter(enc, recpt, &opts)
	if err != nil {
		log.Fatalf("unable to instantiate encrypter: %v\n", err)
	}

	obj, err := crypter.Encrypt(payload)
	if err != nil {
		log.Fatalf("unable to encrypt: %v", err)
	}

	if full {
		return obj.FullSerialize()
	} else {
		msg, err := obj.CompactSerialize()
		if err != nil {
			log.Fatalf("unable to serialize message: %v", err)
		}
		return msg
	}
}
