package main

import (
	"fmt"
	"log"
	"os"

	"gopkg.in/jcmturner/gokrb5.v7/client"
	"gopkg.in/jcmturner/gokrb5.v7/config"
	"gopkg.in/jcmturner/gokrb5.v7/crypto"
	"gopkg.in/jcmturner/gokrb5.v7/keytab"
	"gopkg.in/jcmturner/gokrb5.v7/messages"
	"gopkg.in/jcmturner/gokrb5.v7/types"
)

const (
	kRB5CONF = `[libdefaults]
	default_realm = INSAT.TN

# The following krb5.conf variables are only for MIT Kerberos.
	kdc_timesync = 1
	ccache_type = 4
	forwardable = true
	proxiable = true

# The following encryption type specification will be used by MIT Kerberos
# if uncommented.  In general, the defaults in the MIT Kerberos code are
# correct and overriding these specifications only serves to disable new
# encryption types as they are added, creating interoperability problems.
#
# The only time when you might need to uncomment these lines and change
# the enctypes is if you have local software that will break on ticket
# caches containing ticket encryption types it doesn't know about (such as
# old versions of Sun Java).

#	default_tgs_enctypes = des3-hmac-sha1
#	default_tkt_enctypes = des3-hmac-sha1
#	permitted_enctypes = des3-hmac-sha1

# The following libdefaults parameters are only for Heimdal Kerberos.
	fcc-mit-ticketflags = true

[realms]
	INSAT.TN = {
		kdc = kdc.insat.tn:88
		admin_server = kdc.insat.tn
	}
	ATHENA.MIT.EDU = {
		kdc = kerberos.mit.edu
		kdc = kerberos-1.mit.edu
		kdc = kerberos-2.mit.edu:88
		admin_server = kerberos.mit.edu
		default_domain = mit.edu
	}
	ZONE.MIT.EDU = {
		kdc = casio.mit.edu
		kdc = seiko.mit.edu
		admin_server = casio.mit.edu
	}
	CSAIL.MIT.EDU = {
		admin_server = kerberos.csail.mit.edu
		default_domain = csail.mit.edu
	}
	IHTFP.ORG = {
		kdc = kerberos.ihtfp.org
		admin_server = kerberos.ihtfp.org
	}
	1TS.ORG = {
		kdc = kerberos.1ts.org
		admin_server = kerberos.1ts.org
	}
	ANDREW.CMU.EDU = {
		admin_server = kerberos.andrew.cmu.edu
		default_domain = andrew.cmu.edu
	}
        CS.CMU.EDU = {
                kdc = kerberos-1.srv.cs.cmu.edu
                kdc = kerberos-2.srv.cs.cmu.edu
                kdc = kerberos-3.srv.cs.cmu.edu
                admin_server = kerberos.cs.cmu.edu
        }
	DEMENTIA.ORG = {
		kdc = kerberos.dementix.org
		kdc = kerberos2.dementix.org
		admin_server = kerberos.dementix.org
	}
	stanford.edu = {
		kdc = krb5auth1.stanford.edu
		kdc = krb5auth2.stanford.edu
		kdc = krb5auth3.stanford.edu
		master_kdc = krb5auth1.stanford.edu
		admin_server = krb5-admin.stanford.edu
		default_domain = stanford.edu
	}
        UTORONTO.CA = {
                kdc = kerberos1.utoronto.ca
                kdc = kerberos2.utoronto.ca
                kdc = kerberos3.utoronto.ca
                admin_server = kerberos1.utoronto.ca
                default_domain = utoronto.ca
	}

[domain_realm]
	.insat.tn = INSAT.TN
	insat.tn = INSAT.TN
	.mit.edu = ATHENA.MIT.EDU
	mit.edu = ATHENA.MIT.EDU
	.media.mit.edu = MEDIA-LAB.MIT.EDU
	media.mit.edu = MEDIA-LAB.MIT.EDU
	.csail.mit.edu = CSAIL.MIT.EDU
	csail.mit.edu = CSAIL.MIT.EDU
	.whoi.edu = ATHENA.MIT.EDU
	whoi.edu = ATHENA.MIT.EDU
	.stanford.edu = stanford.edu
	.slac.stanford.edu = SLAC.STANFORD.EDU
        .toronto.edu = UTORONTO.CA
        .utoronto.ca = UTORONTO.CA

`
)

var (
	DEBUG_LOG = "1"
)

var l = log.New(os.Stderr, "GOKRB5 Client: ", log.LstdFlags)

func LOG_ERROR(msgDebug string, userFriendlyError string, err error) {
	if DEBUG_LOG == "1" {
		l.Fatalf(msgDebug, err)
		return
	}
	l.Fatalf(userFriendlyError)
}

func setUpAuth(keytabPath string, spn string, realm string) (*client.Client, *log.Logger, bool) {
	authenticated := false
	DEBUG_LOG = os.Getenv("CLI_CHAT_DEBUG")
	//defer profile.Start(profile.TraceProfile).Stop()
	// Load the keytab
	kt, err := keytab.Load(keytabPath)
	if err != nil {
		// l.Fatalf("could not load client keytab: %v", err)
		LOG_ERROR("could not load client keytab: %v", "Encountered Issue Whilst Loading Keytab.", err)
	}

	// Load the client krb5 config
	conf, err := config.NewConfigFromString(kRB5CONF)
	if err != nil {
		// l.Fatalf("could not load krb5.conf: %v", err)
		LOG_ERROR("could not load krb5.conf: %v", "Encountered Issue Whilst Loading krb5.conf.", err)
	}
	addr := os.Getenv("TEST_KDC_ADDR")
	if addr != "" {
		conf.Realms[0].KDC = []string{addr + ":88"}
	}

	// Create the client with the keytab

	cl := client.NewClientWithKeytab(spn, realm, kt, conf, client.Logger(l), client.DisablePAFXFAST(true))
	if err != nil {
		panic(err)
	}
	// Setting up for the AP_REQ
	tkt, key, err := cl.GetServiceTicket("server")
	if err != nil {
		fmt.Println(tkt, err)
		// log.Fatal("Error obtaining the service ticket.")
		LOG_ERROR("Error obtaining the service ticket: %v", "Encountered An Issue While Obtaining the Service Ticket", err)
	}

	auth, authError := types.NewAuthenticator(cl.Credentials.Realm(), cl.Credentials.CName())
	if authError != nil {
		// log.Fatal("Error obtaining the Authenticator")
		LOG_ERROR("Error obtaining the Authenticator: %v", "Encountered An Issue While obtaining the Authenticator", err)
	}

	etype, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		// log.Fatal("Encountered Error when getting the Encryption Type")
		LOG_ERROR("Could not get the ticket's key encryption type: %v", "Encountered An Issue while determining the Ticket Encryption Key Type", err)
	}

	err = auth.GenerateSeqNumberAndSubKey(key.KeyType, etype.GetKeyByteSize())
	if err != nil {
		LOG_ERROR("Could not get the Sequence Number and Subkey: %v", "Encountered An Issue while determining the Ticket Sequence Number", err)
	}
	// Creating the AP_REQ section
	AP_REQ, err := messages.NewAPReq(tkt, key, auth)
	if err != nil {
		LOG_ERROR("Error during AP Request to the KDC: %v", "Could not Establish Request to the KDC Server", err)
	}
	fmt.Println("Ticket's Principal Name is: ", AP_REQ.Ticket.SName.PrincipalNameString(), "For Realm: ", AP_REQ.Ticket.Realm)
	authenticated = true
	return cl, l, authenticated
}
