package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"golang.org/x/net/websocket"
	"gopkg.in/jcmturner/gokrb5.v7/config"
	"gopkg.in/jcmturner/gokrb5.v7/keytab"
	"gopkg.in/jcmturner/gokrb5.v7/spnego"
)

var (
	cfg *config.Config
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func setUpAuthGuard(keytabPath string) (*log.Logger, *keytab.Keytab) {
	l := log.New(os.Stderr, "GOKRB5 Service: ", log.Ldate|log.Ltime|log.Lshortfile)
	b, err := keytab.Load("serv.keytab")
	must(err)
	return l, b

}
func kerberosHandshakeHandler(wsconf *websocket.Config, req *http.Request) error {
	// Do not check origin
	ctx := req.Context()
	if validUser, ok := ctx.Value(spnego.CTXKeyAuthenticated).(bool); ok && validUser {
		return nil
	}
	// panic("Authentification Failed.")
	return fmt.Errorf("authentification failed")
	// ok, creds, err := service.VerifyAPREQ(APReq, s)

}
