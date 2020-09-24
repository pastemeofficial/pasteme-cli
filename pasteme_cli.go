package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/pbkdf2"
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
	Files          []Files `json:"files"`
	SourceCode     bool    `json:"sourceCode"`
	SelfDestruct   bool    `json:"selfDestruct"`
	ExpiresMinutes int64   `json:"expiresMinutes"`
}

type Files struct {
	Name struct {
		Data   string `json:"data"`
		Vector string `json:"iv"`
		Salt   string `json:"salt"`
	} `json:"name"`
	Content struct {
		Data   string `json:"data"`
		Vector string `json:"iv"`
		Salt   string `json:"salt"`
	} `json:"content"`
}

type PasteSuccess struct {
	Msg   string `json:"msg"`
	Paste struct {
		Uuid string `json:"uuid"`
	} `json:"paste"`
}

func main() {
	app := cli.NewApp()
	app.Name = "Paste.me"
	app.Version = "v0.0.3"
	app.Usage = "Share your pastes securely"

	app.Flags = []cli.Flag{
		&cli.StringSliceFlag{
			Name:  "file",
			Usage: "One or more files to attach to the paste. If you want to attach more than one file, use --file more times!",
		},
		&cli.StringFlag{
			Name:     "name",
			Usage:    "Insert the name of the paste here.",
			Required: true,
		},
		&cli.StringFlag{
			Name:     "body",
			Usage:    "Here you can insert the paste body or send it through cli.",
			Required: true,
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

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func Action(c *cli.Context) error {
	var err error
	name := c.String("name")
	sourceCode := c.Bool("source")
	destroy := c.Bool("destroy")
	body := c.String("body")
	expires := c.Int64("expires")
	files := c.StringSlice("file")
	pasteText := ""

	if len(name) == 0 {
		fmt.Println("Please provide a name for your paste. Use the --help if in doubt.")
		return errors.New("paste_name_error")
	}

	var terminalText string
	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) == 0 {
		terminalText, err = ReadDataFromTerminal(os.Stdin)
		if err != nil {
			return err
		}
	} else {
		if len(body) > 0 {
			terminalText, err = ReadDataFromTerminal(strings.NewReader(body))
		} else {
			terminalText = ""
		}
	}

	if len(terminalText) > 0 {
		pasteText = terminalText
	} else {
		pasteText = body
	}

	if err != nil || len(pasteText) == 0 {
		fmt.Println("Your paste has a length of 0. Try again, but this time try to put some content.")
		return errors.New("paste_length_error")
	}

	// if destroy is set, pass a valid expires to the paste
	// the paste will still self-destruct, this is so we are
	// on par with the WEB UI
	if destroy {
		expires = 60 // expires is not considered for self-destruct pastes
	}

	if !destroy && !IsValidMinutes(expires) {
		fmt.Println("You did not provide a valid expires flag. See --help for more insight on this one.")
		return errors.New("expires_not_found")
	}

	rb, err := GenerateRandomBytes(28)

	if err != nil {
		fmt.Println("Not enough entropy for random bytes! Please try again!")
		os.Exit(1)
	}

	//rand.Read(rb)
	h := sha256.New()
	h.Write(rb)
	passPhrase := hex.EncodeToString(h.Sum(nil))
	encryptName := encrypt(passPhrase, []byte(name))
	encryptData := encrypt(passPhrase, []byte(pasteText))
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
	// Note: The cli client does not support sending files yet!
	// process the files if any
	paste.Files = ProcessFiles(files, passPhrase)

	if !destroy {
		paste.ExpiresMinutes = expires
	}

	jsonValue, _ := json.Marshal(paste)

	req, err := http.NewRequest("POST", "https://api.paste.me/api/paste/new", bytes.NewBuffer(jsonValue))
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)

	if err != nil {
		log.Fatal(err)
	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()

	if err != nil {
		return cli.NewExitError("There was some problem while sending the paste data. Please try again later or contact the site administrator.", 15)
	}

	if resp.StatusCode == 200 {
		res := PasteSuccess{}
		err = json.Unmarshal(bodyBytes, &res)

		if err != nil {
			return cli.NewExitError("We received an invalid response from the server. Please contact the site administrator.", 16)
		}

		msg := `Paste added successfully!
Share this url to your friends: https://paste.me/paste/` + res.Paste.Uuid + `#` + passPhrase
		fmt.Println(msg)
		return nil
	} else {
		return cli.NewExitError("There was some error while pasting your data. Please try again later or contact the Paste.me admin!", 17)
	}

	return nil
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

func ReadDataFromTerminal(r io.Reader) (string, error) {
	var result string
	rBytes, err := ioutil.ReadAll(r)
	if err != nil {
		return "", err
	}
	result = string(rBytes)
	return result, nil
}

// @SRC: https://gist.github.com/tscholl2/dc7dc15dc132ea70a98e8542fefffa28
func deriveKey(passPhrase string, salt []byte) ([]byte, []byte) {
	if salt == nil {
		salt = make([]byte, 8)
		// http://www.ietf.org/rfc/rfc2898.txt
		// Salt.
		rand.Read(salt)
	}
	return pbkdf2.Key([]byte(passPhrase), salt, 1000, 32, sha256.New), salt
}

// @SRC: https://gist.github.com/tscholl2/dc7dc15dc132ea70a98e8542fefffa28
func encrypt(passphrase string, plaintext []byte) string {
	key, salt := deriveKey(passphrase, nil)
	iv := make([]byte, 12)
	// http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
	// Section 8.2
	rand.Read(iv)
	b, _ := aes.NewCipher(key)
	aesgcm, _ := cipher.NewGCM(b)
	data := aesgcm.Seal(nil, iv, plaintext, nil)
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

func ProcessFiles(files []string, passPhrase string) []Files {
	var postFiles []Files
	for _, file := range files {
		if exists := CheckIfFileExists(file); exists == true {

			encryptFileName := encrypt(passPhrase, []byte(filepath.Base(file)))
			fileNameSplitted := strings.Split(encryptFileName, "-")

			encryptFileContent := encrypt(passPhrase, ReadFile(file))
			encryptFileContentSplitted := strings.Split(encryptFileContent, "-")

			postFile := Files{}
			postFile.Name.Data = fileNameSplitted[2]
			postFile.Name.Vector = fileNameSplitted[1]
			postFile.Name.Salt = fileNameSplitted[0]

			postFile.Content.Data = encryptFileContentSplitted[2]
			postFile.Content.Vector = encryptFileContentSplitted[1]
			postFile.Content.Salt = encryptFileContentSplitted[0]

			postFiles = append(postFiles, postFile)
		} else {
			fmt.Printf("The file %s either does not exist or is a directory! Please provide a correct path!\n", file)
			os.Exit(1)
		}
	}

	return postFiles
}

// Check if file exists and it is not a directory...
func CheckIfFileExists(path string) bool {
	fileInfo, err := os.Stat(path)

	if os.IsNotExist(err) {
		return false
	}

	return !fileInfo.IsDir()
}

func ReadFile(path string) []byte {
	dat, err := ioutil.ReadFile(path)

	if err != nil {
		fmt.Printf("There was an error while reading the file! %s => %v\n", path, err)
		os.Exit(1)
	}

	return dat
}
