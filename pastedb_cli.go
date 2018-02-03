package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/urfave/cli"
	"golang.org/x/crypto/pbkdf2"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

type Paste struct {
	Paste struct {
		Name struct {
			Data string `json:"data"`
			Iv   string `json:"iv"`
			Salt string `json:"salt"`
		} `json:"name"`
		Body struct {
			Data string `json:"data"`
			Iv   string `json:"iv"`
			Salt string `json:"salt"`
		} `json:"body"`
	} `json:"paste"`
	SourceCode     bool  `json:"sourceCode"`
	SelfDestruct   bool  `json:"selfDestruct"`
	ExpiresMinutes int64 `json:"expiresMinutes"`
}

type PasteSuccess struct {
	Msg  string `json:"msg"`
	Uuid string `json:"uuid"`
}

func main() {
	app := cli.NewApp()
	app.Name = "PasteDB"
	app.Version = "0.0.1"
	app.Usage = "Share your pastes securely"

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "name",
			Usage: "Insert the name of the paste here.",
		},
		cli.StringFlag{
			Name:  "body",
			Usage: "Here you can insert the paste body or send it through cli.",
		},
		cli.Int64Flag{
			Name:  "expire",
			Usage: "Here you will be able to set an expiration time for your pastes. The expiration time should be defined in minutes. Allowed values for the time being: 5,10,60,1440,10080,43800.",
		},
		cli.BoolFlag{
			Name:  "destroy",
			Usage: "With this flag, you are posting the paste with a 'Self Destruct' flag. The link will work only once.",
		},
		cli.BoolFlag{
			Name:  "source",
			Usage: "With this flag, you are posting a paste which is some kind of source code. Syntax highlighting will be applied.",
		},
	}

	app.Action = func(c *cli.Context) error {
		name := c.String("name")
		sourceCode := c.Bool("source")
		destroy := c.Bool("destroy")
		body := c.String("body")
		minutes := c.Int64("expire")
		pasteText := ""

		if len(name) == 0 {
			fmt.Println("Please provide a name for your paste. Use the --help if in doubt.")
			os.Exit(1)
		}

		terminalText, err := ReadDataFromTerminal()

		if len(terminalText) > 0 {
			pasteText = terminalText
		} else {
			//if len(body) > 0 {
			pasteText = body
		}

		if err != nil || len(pasteText) == 0 {
			fmt.Println("Your paste has a length of 0. Try again, but this time try to put some content.")
			os.Exit(1)
		}

		if !destroy && !IsValidMinutes(minutes) {
			fmt.Println("You did not provide a valid minutes flag. See --help for more insight on this one.")
			os.Exit(1)
		}

		rb, err := GenerateRandomBytes(28)

		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		rand.Read(rb)
		h := sha256.New()
		h.Write(rb)
		passPhrase := hex.EncodeToString(h.Sum(nil))
		encryptName := encrypt(passPhrase, name)
		encryptData := encrypt(passPhrase, pasteText)
		splittedEncryptName := strings.Split(encryptName, "-")
		splittedEncryptData := strings.Split(encryptData, "-")
		//split encrypt result
		paste := &Paste{}
		paste.Paste.Name.Data = splittedEncryptName[2]
		paste.Paste.Name.Iv = splittedEncryptName[1]
		paste.Paste.Name.Salt = splittedEncryptName[0]
		paste.Paste.Body.Data = splittedEncryptData[2]
		paste.Paste.Body.Iv = splittedEncryptData[1]
		paste.Paste.Body.Salt = splittedEncryptData[0]
		paste.SourceCode = sourceCode
		paste.SelfDestruct = destroy
		if !destroy {
			paste.ExpiresMinutes = minutes
		}

		jsonValue, _ := json.Marshal(paste)
		//fmt.Println(string(jsonValue))
		resp, err := http.Post("https://api.pastedb.io/api/paste/new", "application/json", bytes.NewBuffer(jsonValue))
		//resp.Body.Read(res)
		bodyBytes, err := ioutil.ReadAll(resp.Body)
		bodyString := string(bodyBytes)

		if err != nil {
			fmt.Println("There was some problem while sending the paste data. Please try again later or contact the site administrator.")
			os.Exit(1)
		}

		if resp.StatusCode == 200 {
			res := PasteSuccess{}
			err = json.Unmarshal([]byte(bodyString), &res)

			if err != nil {
				fmt.Println("We received an invalid response from the server. Please contact the site administrator.")
				os.Exit(1)
			}

			fmt.Println("Paste added successfully")
			fmt.Println("Share this url to your friends: https://pastedb.io/paste/" + res.Uuid + "#" + passPhrase)
		} else {
			fmt.Println("There was some error while pasting your data. Please try again later or contact the Pastedb admin!")
		}

		return nil
	}

	app.Run(os.Args)
}

// @SRC: https://gist.github.com/dopey/c69559607800d2f2f90b1b1ed4e550fb
// GenerateRandomBytes returns securely generated random bytes.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}

	return b, nil
}

func SendRequest(pasteBodyData string, pasteBodyIv string, pasteNameData string, pasteNameIv string) error {

	return nil
}

func ReadDataFromTerminal() (string, error) {
	var result string
	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) == 0 {
		bytes, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			panic(err)
		}
		result = string(bytes)
	}
	return result, nil
}

func deriveKey(passphrase string, salt []byte) ([]byte, []byte) {
	if salt == nil {
		salt = make([]byte, 8)
		// http://www.ietf.org/rfc/rfc2898.txt
		// Salt.
		rand.Read(salt)
	}
	return pbkdf2.Key([]byte(passphrase), salt, 1000, 32, sha256.New), salt
}

func encrypt(passphrase, plaintext string) string {
	key, salt := deriveKey(passphrase, nil)
	iv := make([]byte, 12)
	// http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
	// Section 8.2
	rand.Read(iv)
	b, _ := aes.NewCipher(key)
	aesgcm, _ := cipher.NewGCM(b)
	data := aesgcm.Seal(nil, iv, []byte(plaintext), nil)
	return hex.EncodeToString(salt) + "-" + hex.EncodeToString(iv) + "-" + hex.EncodeToString(data)
}

func IsValidMinutes(minutes int64) bool {
	switch minutes {
	case
		5, 10, 60, 1440, 10080, 43800:
		return true
	}
	return false
}

//func decrypt(passphrase, ciphertext string) string {
//	arr := strings.Split(ciphertext, "-")
//	salt, _ := hex.DecodeString(arr[0])
//	iv, _ := hex.DecodeString(arr[1])
//	data, _ := hex.DecodeString(arr[2])
//	key, _ := deriveKey(passphrase, salt)
//	b, _ := aes.NewCipher(key)
//	aesgcm, _ := cipher.NewGCM(b)
//	data, _ = aesgcm.Open(nil, iv, data, nil)
//	return string(data)
//}
