package main

import (
	"fmt"
	"os"

	"github.com/99designs/aws-vault/keyring"
	"github.com/99designs/aws-vault/prompt"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"gopkg.in/alecthomas/kingpin.v2"
)

type AddCommandInput struct {
	Profile string
	Keyring keyring.Keyring
	FromEnv bool
}

func AddCommand(app *kingpin.Application, input AddCommandInput) {
	var accessKeyId, secretKey string

	if input.FromEnv {
		if accessKeyId = os.Getenv("AWS_ACCESS_KEY_ID"); accessKeyId == "" {
			app.Fatalf("Missing value for AWS_ACCESS_KEY_ID")
			return
		}
		if secretKey = os.Getenv("AWS_SECRET_ACCESS_KEY"); secretKey == "" {
			app.Fatalf("Missing value for AWS_SECRET_ACCESS_KEY")
			return
		}
	} else {
		var err error
		if accessKeyId, err = prompt.TerminalPrompt("Enter Access Key ID: "); err != nil {
			app.Fatalf(err.Error())
			return
		}
		if secretKey, err = prompt.TerminalPrompt("Enter Secret Access Key: "); err != nil {
			app.Fatalf(err.Error())
			return
		}
	}

	creds := credentials.Value{AccessKeyID: accessKeyId, SecretAccessKey: secretKey}
	provider := &KeyringProvider{Keyring: input.Keyring, Profile: input.Profile}

	if err := provider.Store(creds); err != nil {
		app.Fatalf(err.Error())
		return
	}

	fmt.Printf("Added credentials to profile %q in vault", input.Profile)

	sessions, err := NewKeyringSessions(input.Keyring)
	if err != nil {
		app.Fatalf(err.Error())
		return
	}

	if n, _ := sessions.Delete(input.Profile); n > 0 {
		fmt.Printf("Deleted %d existing sessions.", n)
	}
}
