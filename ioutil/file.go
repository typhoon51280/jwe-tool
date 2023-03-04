package ioutil

import (
	"os"

	"github.com/rs/zerolog/log"
)

func LoadInputStr(filename string) string {
	return string(LoadInput(filename))
}

func LoadInput(filename string) []byte {
	log.Trace().Msgf("Reading file [%s] ...", filename)
	inBytes, err := os.ReadFile(filename)
	if err != nil {
		log.Fatal().Err(err).Msgf("Unable to read file %v", filename)
	}
	log.Info().Msgf("Reading from file [%s] completed with success.", filename)
	return inBytes
}

func WriteOutput(filename string, text string) {
	log.Trace().Msgf("Writing file [%s] ...", filename)
	if err := os.WriteFile(filename, []byte(text), 0666); err != nil {
		log.Fatal().Err(err).Msgf("Unable to write file %v", filename)
	}
	log.Info().Msgf("Writing to file [%s] completed with success.", filename)
}
