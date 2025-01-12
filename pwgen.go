package main

import (
    "flag"
    "fmt"
    "github.com/google/go-tpm/legacy/tpm2"
    "io"
    "os"
)

const (
    minLength = 13
    charset   = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!?@#$%&/*()-+=.,:;"
)

func main() {
    var numPasswords, passwordLength int
    flag.IntVar(&numPasswords, "n", 1, "Number of passwords to generate")
    flag.IntVar(&passwordLength, "l", minLength, "Length of passwords (minimum 13)")
    flag.Parse()

    if numPasswords < 1 {
        fmt.Println("Number of passwords must be at least 1")
        os.Exit(1)
    }

    if passwordLength < minLength {
        fmt.Printf("Password length must be at least %d characters\n", minLength)
        os.Exit(1)
    }

    rwc, err := tpm2.OpenTPM()
    if err != nil {
        fmt.Printf("Failed to open TPM: %v\n", err)
        return
    }
    defer rwc.Close()

    for i := 0; i < numPasswords; i++ {
        password := generatePassword(rwc, passwordLength)
        fmt.Println(password)
    }
}

func generatePassword(rwc io.ReadWriteCloser, length int) string {
    result := make([]byte, length)
    charsetLen := len(charset)
    maxValid := uint8(256 - (256 % charsetLen))

    for i := 0; i < length; {
        random, _ := tpm2.GetRandom(rwc, 1)
        if random[0] >= maxValid {
            continue
        }
        result[i] = charset[random[0]%byte(charsetLen)]
        i++
    }

    return string(result)
}
