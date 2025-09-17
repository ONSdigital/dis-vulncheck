package output

import (
	"github.com/fatih/color"
)

var (
	infoC    = color.New(color.FgHiBlue)
	warningC = color.New(color.FgHiYellow)
	errorC   = color.New(color.FgHiRed)
	successC = color.New(color.FgHiGreen)
)

func Info(msg string) {
	infoC.Println(msg)
}

func InfoSprintf(msg string, args ...interface{}) string {
	return infoC.Sprintf(msg, args...)
}

func Warn(msg string) {
	warningC.Println(msg)
}

func WarnSprintf(msg string, args ...interface{}) string {
	return warningC.Sprintf(msg, args...)
}

func Error(msg string) {
	errorC.Println(msg)
}

func ErrorSprintf(msg string, args ...interface{}) string {
	return errorC.Sprintf(msg, args...)
}

func Success(msg string) {
	successC.Println(msg)
}

func SuccessSprintf(msg string, args ...interface{}) string {
	return successC.Sprintf(msg, args...)
}
