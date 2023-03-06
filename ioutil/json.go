package ioutil

import (
	"encoding/json"
	"strings"

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

func PrintText(title string, body string, colors ...color.Attribute) string {
	var b strings.Builder
	info := color.New(color.FgHiYellow, color.Bold).FprintfFunc()
	content := color.New(colors...).FprintfFunc()
	info(&b, "\n------------------\n")
	info(&b, "%s", title)
	info(&b, "\n------------------\n")
	content(&b, "%s", body)
	info(&b, "\n")
	return b.String()
}

func PrintJWT(token jwt.Token, key interface{}) string {
	signature, _ := token.SigningString()
	var b strings.Builder
	b.WriteString(PrintText("Token Header", PrettyJSON(token.Header), color.BgRed, color.FgWhite, color.Bold))
	b.WriteString(PrintText("Token Signature", signature, color.BgRed, color.FgWhite, color.Bold))
	b.WriteString(PrintText("Token Claims", PrettyJSON(token.Claims), color.BgRed, color.FgWhite, color.Bold))

	return b.String()
}
