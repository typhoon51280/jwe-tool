package ioutil

import (
	"os"
	"strings"
	"time"

	// "runtime/debug"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/rs/zerolog/pkgerrors"
)

type LogParameters struct {
	File  *os.File
	Level string
}

func InitLogger(params LogParameters) {
	// buildInfo, _ := debug.ReadBuildInfo()
	logLevel := zerolog.InfoLevel
	if params.Level != "" {
		if strings.ToLower(params.Level) == "all" {
			params.Level = zerolog.LevelTraceValue
		}
		logLevel, _ = zerolog.ParseLevel(params.Level)
	}
	if logLevel == zerolog.TraceLevel {
		zerolog.ErrorStackMarshaler = pkgerrors.MarshalStack
	}
	output := os.Stdout
	if params.File != nil {
		output = params.File
	}
	log.Logger = zerolog.New(zerolog.ConsoleWriter{Out: output, TimeFormat: time.RFC3339}).
		Level(logLevel).
		With().
		Timestamp().
		Caller().
		Stack().
		// Int("pid", os.Getpid()).
		// Str("go_version", buildInfo.GoVersion).
		Logger()
}

func CreateLogFile(filename string) *os.File {
	if filename != "" {
		file, err := os.OpenFile(
			filename,
			os.O_APPEND|os.O_CREATE|os.O_WRONLY,
			0664)
		if err != nil {
			panic(err)
		}
		return file
	}
	return nil
}
