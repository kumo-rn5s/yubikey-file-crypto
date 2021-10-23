package main

import (
	"fmt"
	"os"
)

func flagTest() {
	var flagtest FlagSetter
	flagtest.FlagSetting()
	fmt.Println(*flagtest.SetupFlag)
	fmt.Println(*flagtest.ResetFlag)
	fmt.Println(*flagtest.DecryptFlag)
	fmt.Println(*flagtest.EncryptFlag)
	fmt.Println(*flagtest.FileNameFlag)
}

func ExampleFlag() {
	// set flag value of test
	old := os.Args
	testArgs := []string{"serial", "-setup", "-reset", "-decrypt", "-encrypt", "-filename", "hoge.txt"}
	os.Args = testArgs
	flagTest()
	os.Args = old
	// Output:
	// true
	// true
	// true
	// true
	// hoge.txt
}
