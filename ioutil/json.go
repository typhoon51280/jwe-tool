package ioutil

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/fatih/color"
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

func PrintText(plaintext []byte) {
	color.Set(color.FgHiYellow, color.Bold)
	fmt.Println("\nPlaintext:")
	fmt.Println("-------------")
	color.Unset()
	color.Set(color.BgCyan, color.FgWhite, color.Bold)
	fmt.Print(string(plaintext))
	color.Unset()
}

func PrintHeader(header interface{}) {
	color.Set(color.FgHiYellow, color.Bold)
	fmt.Println("\n\nToken Header:")
	fmt.Println("-------------")
	color.Unset()
	if err := PrintJSON(header); err != nil {
		log.Fatalf("failed to output header: %v", err)
	}
}

func PrintClaims(claims interface{}) {
	color.Set(color.FgHiYellow, color.Bold)
	fmt.Println("\n\nToken Claims:")
	fmt.Println("-------------")
	color.Unset()
	if err := PrintJSON(claims); err != nil {
		log.Fatalf("failed to output claims: %v", err)
	}
}
