package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
)

func main() {
	authDomain := os.Getenv("AUTH_DOMAIN")
	clientId := os.Getenv("CLIENT_ID")
	redirectURL := os.Getenv("REDIRECT_URL")

	// Complete the OIDC PKCE auth code flow, see auth.go
	token := AuthorizeUser(authDomain, clientId, redirectURL)

	// Use our access token to get info about us
	client := &http.Client{}
	req, _ := http.NewRequest("GET", fmt.Sprintf("https://%s.onelogin.com/oidc/2/me", authDomain), nil)
	req.Header.Set("Authorization", "Bearer "+token)

	res, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
	}

	data, _ := ioutil.ReadAll(res.Body)
	res.Body.Close()
	fmt.Printf("%s\n", data)
}
