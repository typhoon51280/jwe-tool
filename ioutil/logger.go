package ioutil

import (
	"os"
	// "runtime/debug"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/rs/zerolog/pkgerrors"
)

type LogParameters struct {
	file       string
	level      string
	stacktrace bool
}

func InitLogger(params LogParameters) {
	// buildInfo, _ := debug.ReadBuildInfo()
	logLevel := zerolog.TraceLevel
	if params.level != "" {
		logLevel, _ = zerolog.ParseLevel(params.level)
	}
	if params.stacktrace {
		zerolog.ErrorStackMarshaler = pkgerrors.MarshalStack
	}
	output := os.Stderr
	if params.file != "" {
		file, err := os.OpenFile(
			params.file,
			os.O_APPEND|os.O_CREATE|os.O_WRONLY,
			0664,
		)
		if err != nil {
			panic(err)
		}
		defer file.Close()
		output = file
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
