package casdk

import (
	"fmt"
	"testing"
)

var client *FabricCAClient
var err error

func init() {
	client, err = NewCAClient("./caconfig.yaml", nil)
	if err != nil {
		panic(err)
	}
}

func checkErr(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}

func initIdentity() *Identity {
	key := `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg1hfDwg1of0NFCn1J
rc5dnrTqfLQR2sfla2hxsaraxsGhRANCAATUSREPc0rByvHtn9R4mIuJcsiwKE+u
+QF6Uw1QypzzbRFPUatez6b9QRzNcq2lskOIB6+eD/Z1lVbZsw+9SLoI
-----END PRIVATE KEY-----`
	cert := `-----BEGIN CERTIFICATE-----
MIICbDCCAhOgAwIBAgIUaDlNH+Ofxk0ltm8YpLxbLdFMkYcwCgYIKoZIzj0EAwIw
czELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDVNh
biBGcmFuY2lzY28xGTAXBgNVBAoTEG9yZzEuZXhhbXBsZS5jb20xHDAaBgNVBAMT
E2NhLm9yZzEuZXhhbXBsZS5jb20wHhcNMTkxMTI0MTUwNTAwWhcNMjAxMTIzMTUx
MDAwWjAhMQ8wDQYDVQQLEwZjbGllbnQxDjAMBgNVBAMTBWFkbWluMFkwEwYHKoZI
zj0CAQYIKoZIzj0DAQcDQgAE1EkRD3NKwcrx7Z/UeJiLiXLIsChPrvkBelMNUMqc
820RT1GrXs+m/UEczXKtpbJDiAevng/2dZVW2bMPvUi6CKOB1jCB0zAOBgNVHQ8B
Af8EBAMCB4AwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUE7lqCB7kW9U60O/ajAGp
iUvGc14wKwYDVR0jBCQwIoAg5xmhZslKvW1mYTAezU8dKZP/boqf68a3H6pmMF1H
hDAwIwYDVR0RBBwwGoIYY2Eub3JnMS5leGFtcGxlLmNvbTo3MDU0MEIGCCoDBAUG
BwgBBDZ7ImF0dHJzIjp7ImhmLkFmZmlsaWF0aW9uIjoib3JnMSIsImhmLlR5cGUi
OiJjbGllbnQifX0wCgYIKoZIzj0EAwIDRwAwRAIgdIHMyz7OKXmfm3DUnFsLYrkt
F4BBV1KhcYhUOG6eYD8CIAWBgznvdlQkNDjpN6QNfJMiUi+3zHb1UL3drFgHbFb2
-----END CERTIFICATE-----`
	idn, err := InitAdminIdentity([]byte(cert), []byte(key))
	if err != nil {
		panic(err)
	}
	return idn
}

func TestFabricCAClient_GetCaInfo(t *testing.T) {
	res, err := client.GetCaInfo()
	checkErr(t, err)
	fmt.Println(res)
}

func TestFabricCAClient_Enroll(t *testing.T) {
	enrollReq := CaEnrollmentRequest{
		EnrollmentId: "test1",
		Secret:       "test1",
	}
	idn, err := client.Enroll(enrollReq)
	checkErr(t, err)
	//privKey, ok := idn.PrivateKey.(*ecdsa.PrivateKey)
	cert, privKey, pubKey, err := idn.GetStoreData()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("--------- cert -------- \n", string(cert))
	fmt.Println("--------- privateKey -------- \n", string(privKey))
	fmt.Println("--------- publicKey -------- \n", string(pubKey))
}

func TestFabricCAClient_Register(t *testing.T) {
	idn := initIdentity()
	req := CARegistrationRequest{
		EnrolmentId:    "ca5",
		Type:           "tls",
		Secret:         "ca5",
		MaxEnrollments: -1,
		Attrs:          nil,
		CAName:         client.ServerInfo.CAName,
	}
	res, err := client.Register(idn, &req)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(res)
}

func TestFabricCAClient_GetIdentity(t *testing.T) {
	idn := initIdentity()
	res, err := client.GetIdentity(idn, "test2", "")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(res)
}


func TestFabricCAClient_Revoke(t *testing.T) {
	idn := initIdentity()
	req := CARevocationRequest{
		EnrollmentId:"ca4",
	}
	res, err := client.Revoke(idn, &req)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(res)
}

func TestFabricCAClient_NewKey(t *testing.T) {
	pri, pub, err := client.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(string(pri))
	fmt.Println(string(pub))
}

func TestFabricCAClient_EnrollByKey(t *testing.T) {
	/*pri, _, err := client.NewKey()
	checkErr(t, err)*/
	pri := []byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgc11Utvqv9UlT8MSN
/UIS5amvpqIA+gTBib4Z0+/DThyhRANCAAQakkETGas3qLAUjCQH4IzILXzeYECA
kF5euyxOHGJjxPyYXRm+5LPMzKI/vEOcE3xDQhlv9OPNG7sMT9Tfn96U
-----END PRIVATE KEY-----`)
	enrollReq := CaEnrollmentRequest{
		EnrollmentId: "test2",
		Secret:       "test2",
	}
	id, err := client.EnrollByKey(enrollReq, pri)
	checkErr(t, err)
	//privKey, ok := idn.PrivateKey.(*ecdsa.PrivateKey)
	cert, privKey, pubKey, err := id.GetStoreData()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("--------- cert -------- \n", string(cert))
	fmt.Println("--------- privateKey -------- \n", string(privKey))
	fmt.Println("--------- publicKey -------- \n", string(pubKey))
}