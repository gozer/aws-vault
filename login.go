package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"

	"github.com/99designs/aws-vault/keyring"
	"github.com/99designs/aws-vault/prompt"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/skratchdot/open-golang/open"
	"gopkg.in/alecthomas/kingpin.v2"
)

type LoginCommandInput struct {
	Profile   string
	Keyring   keyring.Keyring
	MfaToken  string
	MfaPrompt prompt.PromptFunc
	UseStdout bool
}

func LoginCommand(app *kingpin.Application, input LoginCommandInput) {
	provider, err := NewVaultProvider(input.Keyring, input.Profile, VaultOptions{
		AssumeRoleDuration: MaxAssumeRoleDuration,
		MfaToken:           input.MfaToken,
		MfaPrompt:          input.MfaPrompt,
	})
	if err != nil {
		app.Fatalf(err.Error())
		return
	}

	creds := credentials.NewCredentials(provider)
	val, err := creds.Get()
	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == "NoCredentialProviders" {
			app.Fatalf("No credentials found for profile %q", input.Profile)
			return
		} else {
			app.Fatalf(err.Error())
		}
	}

	jsonBytes, err := json.Marshal(map[string]string{
		"sessionId":    val.AccessKeyID,
		"sessionKey":   val.SecretAccessKey,
		"sessionToken": val.SessionToken,
	})
	if err != nil {
		app.Fatalf(err.Error())
		return
	}

	req, err := http.NewRequest("GET", "https://signin.aws.amazon.com/federation", nil)
	if err != nil {
		app.Fatalf(err.Error())
		return
	}

	q := req.URL.Query()
	q.Add("Action", "getSigninToken")
	q.Add("Session", string(jsonBytes))
	req.URL.RawQuery = q.Encode()

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		app.Fatalf(err.Error())
		return
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		app.Fatalf(err.Error())
		return
	}

	var respParsed map[string]string

	if err = json.Unmarshal([]byte(body), &respParsed); err != nil {
		app.Fatalf(err.Error())
		return
	}

	signinToken, ok := respParsed["SigninToken"]
	if !ok {
		app.Fatalf("Expected a response with SigninToken")
		return
	}

	loginUrl := fmt.Sprintf(
		"https://signin.aws.amazon.com/federation?Action=login&Issuer=aws-vault&Destination=%s&SigninToken=%s",
		url.QueryEscape("https://console.aws.amazon.com/"),
		url.QueryEscape(signinToken),
	)

	if input.UseStdout {
		fmt.Println(loginUrl)
	} else if err = open.Run(loginUrl); err != nil {
		log.Println(err)
		fmt.Println(loginUrl)
	}
}
