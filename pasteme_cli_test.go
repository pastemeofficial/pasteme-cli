package main

import (
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/pbkdf2"
)

func TestMain(m *testing.M) {
	code := m.Run()
	os.Exit(code)
}

func TestGenerateRandomBytes(t *testing.T) {
	a := assert.New(t)
	rb, err := GenerateRandomBytes(24)
	expected := len(make([]byte, 24))
	actual := len(rb)

	if err != nil {
		t.Fatalf("We could not get enough random bytes")
	}

	if !a.Equal(expected, actual) {
		t.Fatalf("We could not get the speicifed amount of bytes")
	}
}

func TestDeriveKey(t *testing.T) {
	a := assert.New(t)
	//test with predefined passphrase and salt
	mockPassphrase := "passphrase"
	mockSalt := []byte("randomSalt")
	mockPbkdf2 := pbkdf2.Key([]byte(mockPassphrase), mockSalt, 1000, 32, sha256.New)
	pbkdf2result, saltResult := deriveKey(mockPassphrase, mockSalt)

	if !a.Equal(mockPbkdf2, pbkdf2result) {
		t.Fatalf("The derived keys do not match!")
	}

	if !a.Equal(mockSalt, saltResult) {
		t.Fatalf("The salts do not match!")
	}

	//test with random passphrase and salt
	randomPassphrase, _ := GenerateRandomBytes(28)
	randomSalt, _ := GenerateRandomBytes(8)
	randomPbkdf2result, randomSaltresult := deriveKey(string(randomPassphrase), randomSalt)

	if !a.NotEqual(randomPbkdf2result, pbkdf2result) {
		t.Fatalf("The mock matches the random generated pbkdf2 data. This is not good!")
	}

	if !a.NotEqual(randomSaltresult, saltResult) {
		t.Fatalf("The mock matches the random generated salt data. This is not good!")
	}
}

func TestEncrypt(t *testing.T) {
	a := assert.New(t)

	//test with predefined passphrase and salt
	mockPassphrase := "passphrase"
	plainText := "Some random text to encrypt"
	result := encrypt(mockPassphrase, []byte(plainText))
	resultArr := strings.Split(result, "-")

	if !a.Equal(len(resultArr), 3) {
		t.Fatalf("The result is not in the correct format")
	}
}

func TestIsValidMinutes(t *testing.T) {
	a := assert.New(t)
	validMinutes := []int64{5, 10, 60, 1440, 10080, 43800}

	for _, minute := range validMinutes {
		result := IsValidMinutes(minute)
		if !a.Equal(result, true) {
			t.Fatalf("The result does not match the expectations.")
		}
	}
}

func TestAction(t *testing.T) {
	type error interface {
		Error() string
	}

	var err error
	//var result string
	a := assert.New(t)

	err = SetupApp([]string{"cmd", ""})

	if !a.Equal("paste_name_error", err.Error()) {
		t.Fatalf("The expected result did not match the required result. (%s, %s)", err, "paste_name_error")
	}

	//second run with name parameter
	err = SetupApp([]string{"cmd", "--name", "Asddd"})
	//
	if !a.Equal("paste_length_error", err.Error()) {
		t.Fatalf("The expected result did not match the required result. (%s, %s)", err, "paste_length_error")
	}

	//third run without minutes flag
	err = SetupApp([]string{"cmd", "--name", "Asddd", "--body", "This is a random paste body"})
	//
	if !a.Equal("expires_not_found", err.Error()) {
		t.Fatalf("The expected result did not match the required result. (%s, %s)", err.Error(), "expires_not_found")
	}

	//with minutes flag
	err = SetupApp([]string{"cmd", "--name", "Asddd", "--body", "This is a random paste body", "--expires", "5"})
	//
	if !a.Equal(nil, err) {
		t.Fatalf("The expected result did not match the required result. (%s, %s)", err.Error(), "minutes_not_found")
	}

	//with destroy flag
	err = SetupApp([]string{"cmd", "--name", "Asddd", "--body", "This is a random paste body", "--destroy"})
	//
	if !a.Equal(nil, err) {
		t.Fatalf("The expected result did not match the required result. (%s, %s)", err.Error(), "minutes_not_found")
	}

	//with source flag
	err = SetupApp([]string{"cmd", "--name", "Asddd", "--body", "This is a random paste body", "--source", "--destroy"})
	//
	if !a.Equal(nil, err) {
		t.Fatalf("The expected result did not match the required result. (%s, %s)", err.Error(), "minutes_not_found")
	}

	fmt.Println(err)
}

func SetupApp(args []string) error {
	//var res string
	var err error
	app := cli.NewApp()
	app.Writer = ioutil.Discard
	app.Name = "Paste.me"
	app.Version = "v0.0.3"
	app.Usage = "Share your pastes securely"

	app.Flags = []cli.Flag{
		&cli.StringFlag{
			Name:  "name",
			Usage: "Insert the name of the paste here.",
		},
		&cli.StringFlag{
			Name:  "body",
			Usage: "Here you can insert the paste body or send it through cli.",
		},
		&cli.Int64Flag{
			Name:  "expires",
			Usage: "Here you will be able to set an expiration time for your pastes. The expiration time should be defined in minutes. Allowed values for the time being: 5,10,60,1440,10080,43800.",
		},
		&cli.BoolFlag{
			Name:  "destroy",
			Usage: "With this flag, you are posting the paste with a 'Self Destruct' flag. The link will work only once.",
		},
		&cli.BoolFlag{
			Name:  "source",
			Usage: "With this flag, you are posting a paste which is some kind of source code. Syntax highlighting will be applied.",
		},
	}

	app.Action = Action

	err = app.Run(args)

	return err
}

func TestBase(t *testing.T) {
	os.Args = []string{"cmd", "--name", "Asddd", "--body", "This is a random paste body", "--source", "--destroy"}
	main()
}

func TestWithFile(t *testing.T) {
	os.Args = []string{"cmd", "--name", "Asddd", "--body", "This is a random paste body", "--source", "--destroy", "--file", "./samplefiles/test1.txt", "--file", "./samplefiles/test2.txt"}
	main()
}
