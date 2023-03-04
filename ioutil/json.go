package ioutil

import (
	"encoding/json"
	"fmt"

	"github.com/fatih/color"
	"github.com/golang-jwt/jwt/v4"
	"github.com/rs/zerolog/log"
)

func PrettyJSON(j interface{}) string {
	if out, err := json.MarshalIndent(j, "", "    "); err != nil {
		log.Error().Err(err).Msg("Failed JSON pretty output")
		return ""
	} else {
		return string(out)
	}

}

func PrintText(plaintext string, header string, colors ...color.Attribute) {
	color.Set(color.FgHiYellow, color.Bold)
	fmt.Printf("\n%s", header)
	fmt.Println("\n-------------")
	color.Unset()
	// color.Set(color.BgCyan, color.FgWhite, color.Bold)
	color.Set(colors...)
	fmt.Print(plaintext)
	color.Unset()
	color.Set(color.FgHiYellow, color.Bold)
	fmt.Print("\n-------------\n\n")
	color.Unset()
}

func PrintHeader(header interface{}) {
	PrintText(PrettyJSON(header), "Token Header:", color.BgRed, color.FgWhite, color.Bold)
}

func PrintBody(body interface{}) {
	PrintText(PrettyJSON(body), "Token Body:", color.BgRed, color.FgWhite, color.Bold)
}

func PrintJWT(plaintext string, key interface{}) {
	jwtToken, err := jwt.Parse(plaintext, func(t *jwt.Token) (interface{}, error) {
		return key, nil
	})
	if err != nil {
		log.Fatal().Err(err).Msg("Error Parsing JWT")
	}
	PrintHeader(jwtToken.Header)
	PrintBody(jwtToken.Claims)
}
