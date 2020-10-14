// Copyright (C) 2020-2021,  0xN3utr0n

// Kanis is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Kanis is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Kanis. If not, see <http://www.gnu.org/licenses/>.

package logger

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog"
)

// From zerolog color-types
const (
	colorBlack = iota + 30
	colorRed
	colorGreen
	colorYellow
	colorBlue
	colorMagenta
	colorCyan
	colorWhite

	colorBold     = 1
	colorDarkGray = 90
)

type Logger struct {
	logger *zerolog.Logger
}

// Only one global stdout instance to avoid races
var stdout zerolog.ConsoleWriter

// InfoS Send Info type message.
func (l *Logger) InfoS(msg string, module string) {
	l.logger.Info().Str("Module", module).Msg(msg)
}

// InfoS Send Debug type message.
func (l *Logger) DebugS(msg string, module string) {
	l.logger.Debug().Str("Module", module).Msg(msg)
}

// InfoS Send Warn type message.
func (l *Logger) WarnS(msg string, module string) {
	l.logger.Warn().Str("Module", module).Msg(msg)
}

// InfoS Send Error type message.
func (l *Logger) ErrorS(err error, module string) {
	l.logger.Error().Str("Module", module).Err(err).Send()
}

// InfoS Send Fatal type message. It's meant to gracefully
// terminate the program.
func (l *Logger) FatalS(msg error, module string) {
	l.ErrorS(msg, module)

	proc, err := os.FindProcess(os.Getpid())
	if err != nil {
		l.ErrorS(err, module)
		os.Exit(1)
	}

	if err := proc.Signal(os.Interrupt); err != nil {
		l.ErrorS(err, module)
		os.Exit(1)
	}

	// Wait to die (hopefully the only sleep()
	// that will ever be needed).
	time.Sleep(time.Hour * 1)
}

func (l *Logger) Info(module string) *zerolog.Event {
	return l.logger.Info().Str("Module", module)
}

func (l *Logger) Warn(module string) *zerolog.Event {
	return l.logger.Warn().Str("Module", module)
}

func (l *Logger) Debug(module string) *zerolog.Event {
	return l.logger.Debug().Str("Module", module)
}

func (l *Logger) Error(err error, module string) *zerolog.Event {
	return l.logger.Error().Str("Module", module).Err(err)
}

// KillHandler sets a new signal handler and creates a channel
// to receive the notificitions.
func KillHandler() <-chan os.Signal {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	return sig
}

// New creates a new Logger instance.
func New(file string, console bool) (*Logger, error) {
	var w io.Writer

	fd, err := os.OpenFile(file, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0644)
	if err != nil {
		return nil, err
	}

	w = fd
	if console {
		stdout = newConsole()
		w = io.MultiWriter(stdout, fd)
	}

	l := zerolog.New(w).With().Timestamp().Logger()
	return &Logger{logger: &l}, nil
}

// SetDebug Sets the global debug flag.
func SetDebug(debug bool) {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	if debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}
}

// newConsole Creates a new logger pointing to stdout.
func newConsole() zerolog.ConsoleWriter {
	// Only allow one stdout Writer
	if stdout.Out != nil {
		return stdout
	}

	console := zerolog.ConsoleWriter{Out: os.Stdout, NoColor: false, TimeFormat: time.RFC3339}

	console.FormatTimestamp = func(i interface{}) string {
		return fmt.Sprintf("\x1b[%dm%v\x1b[0m", colorWhite, i)
	}

	console.FormatFieldValue = func(i interface{}) string {
		switch i {
		case "Threat":
			return fmt.Sprintf("\x1b[%dm%s\x1b[0m", colorYellow, i)
		case "Event":
			return fmt.Sprintf("\x1b[%dm%s\x1b[0m", colorRed, i)
		default:
			return fmt.Sprintf("%s", i)
		}
	}

	return console
}
