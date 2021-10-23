package main

import (
	"flag"
)

const (
	defaultFlagString = ""
	flagBoolIsNil     = false
)

type FlagSetter struct {
	FileNameFlag *string // default defaultFlagString
	SetupFlag    *bool   // default flagBoolIsNil
	ResetFlag    *bool   // default flagBoolIsNil
	EncryptFlag  *bool   // default flagBoolIsNil
	DecryptFlag  *bool   // default flagBoolIsNil
}

func (p *FlagSetter) FlagSetting() {
	p.SetupFlag = flag.Bool("setup", flagBoolIsNil, "configure a new YubiKey")
	p.ResetFlag = flag.Bool("reset", flagBoolIsNil, "reset a YubiKey")
	p.EncryptFlag = flag.Bool("encrypt", flagBoolIsNil, "encrypt some file")
	p.FileNameFlag = flag.String("filename", defaultFlagString, "file to encrypt or decrypt")
	p.DecryptFlag = flag.Bool("decrypt", flagBoolIsNil, "decrypt some file")
	flag.Parse()
}
