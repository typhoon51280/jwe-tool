package ioutil

import (
	"encoding/json"
	"fmt"

	"github.com/fatih/color"
	"github.com/golang-jwt/jwt/v4"
	"github.com/rs/zerolog/log"
)

func PrintJSON(j interface{}) error {
	var out []byte
	var err error
	out, err = json.MarshalIndent(j, "", "    ")
	if err == nil {
		color.Set(color.BgRed, color.FgWhite, color.Bold)
		fmt.Print(string(out))
		color.Unset()
	}
	return err
}

func PrintText(plaintext string) {
	color.Set(color.FgHiYellow, color.Bold)
	fmt.Println("\nPlaintext:")
	fmt.Println("-------------")
	color.Unset()
	color.Set(color.BgCyan, color.FgWhite, color.Bold)
	fmt.Print(string(plaintext))
	color.Unset()
	color.Set(color.FgHiYellow, color.Bold)
	fmt.Print("\n-------------\n\n")
	color.Unset()
}

func PrintHeader(header interface{}) {
	color.Set(color.FgHiYellow, color.Bold)
	fmt.Println("\nToken Header:")
	fmt.Println("-------------")
	color.Unset()
	if err := PrintJSON(header); err != nil {
		log.Fatal().Err(err).Msg("failed to output header")
	}
	color.Unset()
	color.Set(color.FgHiYellow, color.Bold)
	fmt.Print("\n-------------\n\n")
}

func PrintBody(body interface{}) {
	color.Set(color.FgHiYellow, color.Bold)
	fmt.Println("\nToken Body:")
	fmt.Println("-------------")
	color.Unset()
	if err := PrintJSON(body); err != nil {
		log.Fatal().Err(err).Msg("failed to output body")
	}
	color.Unset()
	color.Set(color.FgHiYellow, color.Bold)
	fmt.Print("\n-------------\n\n")
}

func PrintJWT(plaintext string) {
	jwtToken, err := jwt.Parse(plaintext, nil)
	if err != nil {
		log.Fatal().Err(err).Msg("Error Parsing JWT")
	}
	PrintHeader(jwtToken.Header)
	PrintBody(jwtToken.Claims)
}
