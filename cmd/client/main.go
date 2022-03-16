package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/jroimartin/gocui"
	"golang.org/x/net/websocket"
)

func main() {
	var (
		username string
		keytab   string
		// spn       string
		realm     string
		port      int
		principal string
	)
	flag.StringVar(&username, "username", "", "Chat username")
	flag.IntVar(&port, "port", 5001, "Server port")
	flag.StringVar(&keytab, "keytab", "", "Keytab Path")
	// flag.StringVar(&spn, "spn", "", "Service Principal Name")
	flag.StringVar(&realm, "realm", "INSAT.TN", "Realm Name")
	flag.StringVar(&principal, "principal", "", " Client Principal Name")

	flag.Parse()
	if len(strings.TrimSpace(username)) == 0 {
		log.Fatal("missing -username option (required)")
	}
	if len(strings.TrimSpace(keytab)) == 0 {
		log.Fatal("missing -keytab option (required)")
	}
	// if len(strings.TrimSpace(spn)) == 0 {
	// 	log.Fatal("missing -spn option (required)")
	// }
	if len(strings.TrimSpace(principal)) == 0 {
		log.Fatal("missing -principal option (required)")
	}
	// setUpAuth("user.keytab", "user", "INSAT.TN")
	_, _, authenticated := setUpAuth(keytab, principal, realm)
	if !authenticated {
		LOG_ERROR("Authentification failed!", "Authentification Failed!", nil)
		os.Exit(1)
	}

	config, err := websocket.NewConfig(fmt.Sprintf("ws://:%v/", port), "http://")
	config.Header.Set("Username", username)
	if err != nil {
		log.Fatal(err)
	}
	connection, err := websocket.DialConfig(config)
	if err != nil {
		log.Fatal(err)
	}
	ui, err := NewUI(connection, username)
	if err != nil {
		log.Fatal(err)
	}
	defer ui.Close()

	ui.SetManagerFunc(ui.layout)
	if err := ui.SetKeybinding("", gocui.KeyCtrlC, gocui.ModNone, ui.quit); err != nil {
		log.Fatalln(err)
	}
	if err := ui.SetKeybinding("input", gocui.KeyEnter, gocui.ModNone, ui.sendMsg); err != nil {
		log.Fatalln(err)
	}
	go ui.receiveMsg()
	if err = ui.MainLoop(); err != nil && err != gocui.ErrQuit {
		log.Fatalln(err)
	}
}
