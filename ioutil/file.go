package ioutil

import (
	"os"

	"github.com/rs/zerolog/log"
)

func LoadInputStr(filename string) string {
	return string(LoadInput(filename))
}

func LoadInput(filename string) []byte {
	inBytes, err := os.ReadFile(filename)
	if err != nil {
		log.Fatal().Err(err).Msgf("unable to read file %v", filename)
	}
	return inBytes
}

func WriteOutput(path string, text string) {
	var err error

	if path != "" {
		err = os.WriteFile(path, []byte(text), 0666)
	} else {
		PrintText(text)
	}

	if err != nil {
		log.Fatal().Err(err).Msgf("unable to write file %v", path)
	}

}
