package ioutil

import (
	"log"
	"os"
)

func LoadInput(filename string) string {
	inBytes, err := os.ReadFile(filename)
	if err != nil {
		log.Fatalf("unable to read file: %v", err)
	}
	return string(inBytes)
}

func WriteOutput(path string, data []byte) {
	var err error

	if path != "" {
		err = os.WriteFile(path, data, 0666)
	} else {
		_, err = os.Stdout.Write(data)
	}

	if err != nil {
		log.Fatalf("unable to write output: %v", err)
	}

}
