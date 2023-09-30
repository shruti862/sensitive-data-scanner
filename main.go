package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"unicode"

	"github.com/urfave/cli"
)

func main() {
	app := cli.NewApp()
	app.Name = "Sensitive Data Scanner"
	app.Usage = "Scan for sensitive data in a text file"
	app.Version = "1.0.0"

	app.Commands = []cli.Command{
		{
			Name:    "scan",
			Aliases: []string{"s"},
			Usage:   "Scan for sensitive data in a text file",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "input, i",
					Usage: "Input file",
				},
				cli.BoolFlag{
					Name:  "encrypt, e",
					Usage: "Encrypt the input file",
				},
				cli.BoolFlag{
					Name:  "scanner, sc",
					Usage: "Scans the input file for sensitive data",
				},
				cli.BoolFlag{
					Name:  "decrypt, d",
					Usage: "Decrypt the input file",
				},
				cli.StringFlag{
					Name:  "passphrase, p",
					Usage: "Encryption/Decryption passphrase",
				},
			},
			Action: func(c *cli.Context) error {
				inputFileName := c.String("input")
				encryptFiles := c.Bool("encrypt")
				decryptFiles := c.Bool("decrypt")
				passphrase := c.String("passphrase")
                scanner:=c.Bool("scanner")

				if encryptFiles && decryptFiles {
					return fmt.Errorf("cannot encrypt and decrypt at the same time")
				}
                if scanner{
				res, _ := findPasswordsInFile(inputFileName)

				 if res {
					fmt.Println("Sensitive data found")
					
				} else {
					fmt.Println("No sensitive data found.")
				}
				}
				if encryptFiles {
					outputFileName := inputFileName + ".enc"
					err := encryptFile(inputFileName, outputFileName, passphrase)
					if err != nil {
						return err
					}
					fmt.Printf("Encryption successful. Encrypted file: %s\n", outputFileName)
				}



                 if decryptFiles {
                    outputFileName := strings.TrimSuffix(inputFileName, ".enc")
                    err := decryptFile(inputFileName, outputFileName, passphrase)
                     if err != nil {
                            return err
                                     }
                           fmt.Printf("Decryption successful. Decrypted file: %s\n", outputFileName)
                         }




				return nil
						 },
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		fmt.Println(err)
	}
}
func createHash(key string) string {
	hasher := md5.New()
	hasher.Write([]byte(key))
	return hex.EncodeToString(hasher.Sum(nil))
}

func encrypt(data []byte, passphrase string) ([]byte, error) {
	block, err := aes.NewCipher([]byte(createHash(passphrase)))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

func decrypt(data []byte, passphrase string) ([]byte, error) {
	key := []byte(createHash(passphrase))
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
func encryptFile(inputFileName string, outputFileName string, passphrase string) error {
	data, err := os.ReadFile(inputFileName)
	if err != nil {
		return err
	}

	ciphertext, err := encrypt(data, passphrase)
	if err != nil {
		return err
	}

	return os.WriteFile(outputFileName, ciphertext, 0644)
}
func decryptFile(inputFileName string, outputFileName string, passphrase string) error {
	data, err := os.ReadFile(inputFileName)
	if err != nil {
		return err
	}

	plaintext, err := decrypt(data, passphrase)
	if err != nil {
		return err
	}

	return os.WriteFile(outputFileName, plaintext, 0644)
}

func findPasswordsInFile(filePath string) (bool, []string) {
	var ans bool = false
	file, err := os.Open(filePath)
	if err != nil {
		fmt.Println(err)
	}
	defer file.Close()

	passwordPattern :=  `[A-Za-z\d!@#$%^&*()_+{}\[\]:;<>,.?~\\]{8,}`
	phoneNumberPattern := `\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b`
    hexadecimalPattern :=`\b[0-9]*[a-fA-F-][0-9a-fA-F-]*(?:-[0-9]*[a-fA-F-][0-9a-fA-F-]*)*\b`
	 tokenPattern:=`\b[A-Za-z0-9]{8,}\b`

	scanner := bufio.NewScanner(file)
	lineNum := 0

	sensitiveData := []string{}
	for scanner.Scan() {
		line := scanner.Text()
		lineNum++

		if isPassword, password := findPassword(line, passwordPattern); isPassword && len(password) >= 8 {
			fmt.Printf("Some sensitive data found in line %d: %v\n", lineNum, password)
			sensitiveData = append(sensitiveData, password)
			ans = true
		}

		phoneNumbers := findPhoneNumbers(line, phoneNumberPattern)
		SensitiveData :=findHexadecimalMatches(line,hexadecimalPattern)
	    token:=findToken(line,tokenPattern)

		if len(phoneNumbers) > 0 {
			fmt.Printf("Phone number found in line %d: %v\n", lineNum, phoneNumbers)
			ans = true
			sensitiveData = append(sensitiveData, phoneNumbers...)
		}
		if len(token) > 0 {
			fmt.Printf("some sensitive data in line %d: %v\n", lineNum, token)
            ans=true
            sensitiveData =append(sensitiveData, token...)
	
		}
		
		if len(SensitiveData) > 0 {
            fmt.Printf("some sensitive  data found in line %d: %v\n",lineNum , SensitiveData)
			sensitiveData = append(sensitiveData, SensitiveData...)
        }
	}

	if err := scanner.Err(); err != nil {
		fmt.Println(err)
	}

	return ans, sensitiveData
}

func findPassword(text, pattern string) (bool, string) {
	re := regexp.MustCompile(pattern)
	matches := re.FindAllString(text, -1)

	for _, match := range matches {
		if len(match) >= 8 && containsSpecialSymbols(match) {
			return true, match
		}
	}

	return false, ""
}

func containsSpecialSymbols(text string) bool {
	specialSymbols := "!@#$%^&*()_+{}[]:;<>,.?~\\-"
	for _, char := range text {
		if strings.ContainsRune(specialSymbols, char) {
			return true
		}
	}
	return false
}

func findPhoneNumbers(text, pattern string) []string {
	re := regexp.MustCompile(pattern)
	matches := re.FindAllString(text, -1)

	return matches
}
func findToken(text, pattern string) []string {
	re := regexp.MustCompile(pattern)
	matches := re.FindAllString(text, -1)
    standaloneHexMatches := []string{}
    for _, match := range matches {
		if containsDigits(match) &&  isAlphanumericHex(match) && hasAtLeastTwoCapitalLetters(match){
			standaloneHexMatches = append(standaloneHexMatches, match)
			        }
    }
    
    return standaloneHexMatches
}




func findHexadecimalMatches(text, pattern string) []string {
    re := regexp.MustCompile(pattern)
    matches := re.FindAllString(text, -1)
    
    // Filter out hexadecimal matches that are part of other words or patterns
    standaloneHexMatches := []string{}
    for _, match := range matches {
		if containsDigits(match) &&  isAlphanumericHex(match) {
			standaloneHexMatches = append(standaloneHexMatches, match)
			        }
    }
    
    return standaloneHexMatches
}

func isAlphanumericHex(text string) bool {
    for _, char := range text {
        if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') {
            return true
        }
    }
    return false
}

func containsDigits(word string) bool {
	for _, char := range word {
		if unicode.IsDigit(char) {
			return true
		}
	}
	return false
}

func hasAtLeastTwoCapitalLetters(word string) bool {
	count := 0

	for _, char := range word {
		if unicode.IsUpper(char) {
			count++
			if count >= 2 {
				return true
			}
		}
	}

	return false
}