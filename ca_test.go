package casdk

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
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
		EnrollmentId: "caa1",
		Secret:       "caa1",
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
		EnrolmentId:    "caa1",
		Type:           "user",
		Secret:         "caa1",
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

var caa12 = `-----BEGIN CERTIFICATE-----
MIICfTCCAiOgAwIBAgIUQ+vibRt0JDjT/o7zy/EUkhLmgBUwCgYIKoZIzj0EAwIw
czELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDVNh
biBGcmFuY2lzY28xGTAXBgNVBAoTEG9yZzEuZXhhbXBsZS5jb20xHDAaBgNVBAMT
E2NhLm9yZzEuZXhhbXBsZS5jb20wHhcNMTkxMTI2MDU0MDAwWhcNMjAxMTI1MDU0
NTAwWjAeMQ0wCwYDVQQLEwR1c2VyMQ0wCwYDVQQDEwRjYWExMFkwEwYHKoZIzj0C
AQYIKoZIzj0DAQcDQgAEeiqcBhtcrJG6FMueS8h3IItyBrwS/XRxssewJ/fnBmky
sCkDrL8qEY7zBu5XjF9Ccx7ELCPBaFr7cQAZ87iJb6OB6TCB5jAOBgNVHQ8BAf8E
BAMCB4AwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUgKiZubF5moh6vk3YdwUSve9p
uL8wKwYDVR0jBCQwIoAg5xmhZslKvW1mYTAezU8dKZP/boqf68a3H6pmMF1HhDAw
IwYDVR0RBBwwGoIYY2Eub3JnMS5leGFtcGxlLmNvbTo3MDU0MFUGCCoDBAUGBwgB
BEl7ImF0dHJzIjp7ImhmLkFmZmlsaWF0aW9uIjoiIiwiaGYuRW5yb2xsbWVudElE
IjoiY2FhMSIsImhmLlR5cGUiOiJ1c2VyIn19MAoGCCqGSM49BAMCA0gAMEUCIQDb
bSnTy7hbYyZeJs0BOey3kGZzKZwyZDyoCWxa2R2j6AIgGxyb2Da52OimiPMWt8v9
qhz/e25kZCpZO3WWu+IaaAs=
-----END CERTIFICATE-----`

func TestFabricCAClient_Revoke(t *testing.T) {
	idn := initIdentity()
	cert := `-----BEGIN CERTIFICATE-----
MIICezCCAiOgAwIBAgIUV6Lwwfo/rnf22o1Lx2JecEwOXFYwCgYIKoZIzj0EAwIw
czELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDVNh
biBGcmFuY2lzY28xGTAXBgNVBAoTEG9yZzEuZXhhbXBsZS5jb20xHDAaBgNVBAMT
E2NhLm9yZzEuZXhhbXBsZS5jb20wHhcNMTkxMTI2MDUzOTAwWhcNMjAxMTI1MDU0
NDAwWjAeMQ0wCwYDVQQLEwR1c2VyMQ0wCwYDVQQDEwRjYWExMFkwEwYHKoZIzj0C
AQYIKoZIzj0DAQcDQgAE4W/0iH//8Y9UqioqXHKDGXtnwokCwVttCHFzaDgSTRps
N4vqCgNRkGMJgqQKxKrolEQPE6qkeN19ytBkqagbyKOB6TCB5jAOBgNVHQ8BAf8E
BAMCB4AwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQU7fbwjxWKK9DUpArJi+Fo3Dj6
hXUwKwYDVR0jBCQwIoAg5xmhZslKvW1mYTAezU8dKZP/boqf68a3H6pmMF1HhDAw
IwYDVR0RBBwwGoIYY2Eub3JnMS5leGFtcGxlLmNvbTo3MDU0MFUGCCoDBAUGBwgB
BEl7ImF0dHJzIjp7ImhmLkFmZmlsaWF0aW9uIjoiIiwiaGYuRW5yb2xsbWVudElE
IjoiY2FhMSIsImhmLlR5cGUiOiJ1c2VyIn19MAoGCCqGSM49BAMCA0YAMEMCIHqK
WH1J0PVeLMva4dHQfSx2Ju1NQAWoEUsN56DvaKBiAh8wcKPqXIllObUAzQ1IpNxz
sZv1NAuvK4eONhSI3a6p
-----END CERTIFICATE-----`
	serial, aki, err := client.GetCertSerialAki([]byte(cert))
	if err != nil {
		t.Fatal(err)
	}

	req := CARevocationRequest{
		//EnrollmentId: "ca5", // 根据注册用户注销其证书
		Serial: serial,
		AKI:    aki,
		GenCRL: true,
	}
	res, err := client.Revoke(idn, &req)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("%#v", res)
}

func TestFabricCAClient_NewKey(t *testing.T) {
	pri, pub, err := client.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(string(pri))
	fmt.Println(string(pub))

	pri, pub, err = client.NewKey()
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

func TestECCryptSuite_Sign(t *testing.T) {
	pri := []byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgc11Utvqv9UlT8MSN
/UIS5amvpqIA+gTBib4Z0+/DThyhRANCAAQakkETGas3qLAUjCQH4IzILXzeYECA
kF5euyxOHGJjxPyYXRm+5LPMzKI/vEOcE3xDQhlv9OPNG7sMT9Tfn96U
-----END PRIVATE KEY-----`)
	prikey, err := ParsePemKey(pri)
	checkErr(t, err)
	res, err := client.Crypto.Sign([]byte("asdasd"), prikey)
	checkErr(t, err)
	fmt.Println(hex.EncodeToString(res))
}

func TestECCryptSuite_Verify(t *testing.T) {
	pri := []byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgc11Utvqv9UlT8MSN
/UIS5amvpqIA+gTBib4Z0+/DThyhRANCAAQakkETGas3qLAUjCQH4IzILXzeYECA
kF5euyxOHGJjxPyYXRm+5LPMzKI/vEOcE3xDQhlv9OPNG7sMT9Tfn96U
-----END PRIVATE KEY-----`)
	prikey, err := ParsePemKey(pri)
	checkErr(t, err)

	sign := "304402207a3268555083b2dfcbea7ddd13425bf80c878f1ee913a847ade0933bc14ce0c7022015143aff86eadd0859a71704ed625620934ebdd04e589b16fbf3880776ac3071"
	signByte, err := hex.DecodeString(sign)
	checkErr(t, err)

	//hash := client.Crypto.Hash([]byte("123123"))

	res, err := client.Crypto.Verify(&prikey.PublicKey, signByte, []byte("asdasd"))
	checkErr(t, err)
	fmt.Println(res)
}

// Verifying with a custom list of root certificates.
const rootPEM = `-----BEGIN CERTIFICATE-----
MIICUTCCAfegAwIBAgIQE+VOW9WwnOuXLdiLTEOARDAKBggqhkjOPQQDAjBzMQsw
CQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMNU2FuIEZy
YW5jaXNjbzEZMBcGA1UEChMQb3JnMS5leGFtcGxlLmNvbTEcMBoGA1UEAxMTY2Eu
b3JnMS5leGFtcGxlLmNvbTAeFw0xOTExMjAwMTMzMDBaFw0yOTExMTcwMTMzMDBa
MHMxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1T
YW4gRnJhbmNpc2NvMRkwFwYDVQQKExBvcmcxLmV4YW1wbGUuY29tMRwwGgYDVQQD
ExNjYS5vcmcxLmV4YW1wbGUuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
3+CUhwBMTCspp/Le/CeOQYCAJGdKriWXIIReeE12mkOIG3kPSe6m1DSwzuMCPfDy
8qkYg96SNsGYtFkDiRpViqNtMGswDgYDVR0PAQH/BAQDAgGmMB0GA1UdJQQWMBQG
CCsGAQUFBwMCBggrBgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MCkGA1UdDgQiBCDn
GaFmyUq9bWZhMB7NTx0pk/9uip/rxrcfqmYwXUeEMDAKBggqhkjOPQQDAgNIADBF
AiEAxtGw+IpkJ2NtmsU4JVK4AFPWG4w6gKM5/+p9SFn1RXoCIA0hTW/9A0CQB9+1
5y/FILN2m3Po36z2YfeG9sK/g1vN
-----END CERTIFICATE-----`
const certPEM1 = `-----BEGIN CERTIFICATE-----
MIICtjCCAl2gAwIBAgIUcedCz7UqJihZGNQ5k/Hs+DfMRUwwCgYIKoZIzj0EAwIw
czELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDVNh
biBGcmFuY2lzY28xGTAXBgNVBAoTEG9yZzEuZXhhbXBsZS5jb20xHDAaBgNVBAMT
E2NhLm9yZzEuZXhhbXBsZS5jb20wHhcNMTkxMTI1MTIxNzAwWhcNMjAxMTI0MTIy
MjAwWjA6MQ0wCwYDVQQLEwR1c2VyMSkwJwYDVQQDEyA2YjRiZTQ5YTdlNzY5Njc1
ZDI1OWFmZTQ5YWRlNmJiNzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABFLLOG5v
ZlN+YfQ9ZgDsSE+VGWwnrrY4iErbZbFkZdch8X/Q6nChCWZM3z0q1suuTMcSBV3X
PjYyCYX3+4exQBujggEGMIIBAjAOBgNVHQ8BAf8EBAMCB4AwDAYDVR0TAQH/BAIw
ADAdBgNVHQ4EFgQUYChbyifv8YPqsUFxMqQZmQCaz2swKwYDVR0jBCQwIoAg5xmh
ZslKvW1mYTAezU8dKZP/boqf68a3H6pmMF1HhDAwIwYDVR0RBBwwGoIYY2Eub3Jn
MS5leGFtcGxlLmNvbTo3MDU0MHEGCCoDBAUGBwgBBGV7ImF0dHJzIjp7ImhmLkFm
ZmlsaWF0aW9uIjoiIiwiaGYuRW5yb2xsbWVudElEIjoiNmI0YmU0OWE3ZTc2OTY3
NWQyNTlhZmU0OWFkZTZiYjciLCJoZi5UeXBlIjoidXNlciJ9fTAKBggqhkjOPQQD
AgNHADBEAiAQcqIeFWH+ttoAsy6RnjAkNqC36e2wm1DTP1TR/FNMywIgPpGxQ549
6jFNaiDH4o1W4EmuDWCPZkjaV6enrcwk+kY=
-----END CERTIFICATE-----`
const certPEM = `-----BEGIN CERTIFICATE-----
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
const certLocal = `-----BEGIN CERTIFICAET-----
MIIDYzCCAkugAwIBAgIRAMfEqEfgSlXWzN1CekM+v0swDQYJKoZIhvcNAQELBQAw
UDEhMB8GA1UEChMYTWFubmluZyBQdWJsaWNhdGlvbnMgQ28uMQ4wDAYDVQQLEwVC
b29rczEbMBkGA1UEAxMSR28gV2ViIFByb2dyYW1taW5nMB4XDTE5MTEyNjAxMjMx
OVoXDTIwMTEyNTAxMjMxOVowUDEhMB8GA1UEChMYTWFubmluZyBQdWJsaWNhdGlv
bnMgQ28uMQ4wDAYDVQQLEwVCb29rczEbMBkGA1UEAxMSR28gV2ViIFByb2dyYW1t
aW5nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnVkJy/Y8XHlAqOSZ
edMaMsUPpD4dZbmF+I05ahoy0c3INNhRnFBfMR4dsJB01XcganrvE99A022vTy70
IPUsRQtF0LiTh5Z0kW707hH+cF62GyqGjDnXdjpWil6cMGOI0YIyN5nCmN40xdbY
/uaqGgY4O3oR48ij5DeX/1gZO2Sax+h2JlX7a0oFKEe4ujc1dAHNWuL+LK6AMyOI
OfNVbo5tN6Z0avq+sQ8bSWDx4RxSEDROn7olRGEClkQi5EoHA9dIpDSOVAiv7t8A
OKtZmTKppcCvIV7rXtbt8XoawJyv2KfBCu0DnK+NxkCBxa7/9JZ1hu7z3eEt8ERP
9ZWugQIDAQABozgwNjAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUH
AwEwDwYDVR0RBAgwBocEfwAAATANBgkqhkiG9w0BAQsFAAOCAQEAPlbi1QlxQ7BQ
Hj8Ai9GSyy7jT/dzEeNgfjRYZhwv9/qlQuOd/Bv0rmgho2zVjoWbQ+h0oDaZmWI7
gjn3f04T+54NHdAjOAvb7o+g6hPt+HC/m1BYcBIWQ8tkjv1WLEXtajGgOe1AFW/I
22feooVT5AtX1Jro8lj4owMun5nXPDETtCxack4VUHanMpj/rdMsJvBZtlmEmCrX
1rl5rmcFdDCbbzS8K2cs+u4zBM14x1vZciBAU/GrzWWKdQVYCF1iRfpiR6yYtHF8
++du9mCBSsrNZWXRAZJtjhMCK6mLoHHhICmymRNGZ/gF8U3mc/NNx7HHl5aV+sik
qP0GLLTUKA==
-----END CERTIFICAET-----`

func Test_x509Verify(t *testing.T) {
	// First, create the set of root certificates. For this example we only
	// have one. It's also possible to omit this in order to use the
	// default root set of the current operating system.
	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM([]byte(rootPEM))
	if !ok {
		panic("failed to parse root certificate")
	}
	/*in := x509.NewCertPool()
	ok := in.AppendCertsFromPEM([]byte(certPEM1))
	if !ok {
		panic("failed to parse root certificate")
	}*/

	block, _ := pem.Decode([]byte(certPEM1))
	if block == nil {
		panic("failed to parse certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic("failed to parse certificate: " + err.Error())
	}
	opts := x509.VerifyOptions{
		//DNSName: "mail.google.com",
		Roots: roots,
		//Intermediates: in,
	}
	chain, err := cert.Verify(opts)
	if err != nil {
		t.Fatal("failed to verify certificate: " + err.Error())
	}
	fmt.Println(len(chain), len(chain[0]))
	/*for k, v := range chain {
		for
	}*/
	fmt.Printf("%#v", chain[0])
}

func Test_x509CheckSignatureFrom(t *testing.T) {
	rootCert, err := ParsePemCert([]byte(certPEM1))
	if err != nil {
		t.Fatal(err)
	}
	childCert, err := ParsePemCert([]byte(rootPEM))
	err = childCert.CheckSignatureFrom(rootCert)
	fmt.Println(err)
}

func TestFabricCAClient_Gencrl(t *testing.T) {
	res, err := client.Gencrl(initIdentity())
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range res.TBSCertList.RevokedCertificates {
		fmt.Printf("%x\n", v.SerialNumber)
	}
}

const CRL = `-----BEGIN X509 CRL-----
MIIBfTCCASMCAQEwCgYIKoZIzj0EAwIwczELMAkGA1UEBhMCVVMxEzARBgNVBAgT
CkNhbGlmb3JuaWExFjAUBgNVBAcTDVNhbiBGcmFuY2lzY28xGTAXBgNVBAoTEG9y
ZzEuZXhhbXBsZS5jb20xHDAaBgNVBAMTE2NhLm9yZzEuZXhhbXBsZS5jb20XDTE5
MTEyNjAxNTkzNVoXDTE5MTEyNzAxNTkzNVowTjAlAhQKcpJt2nU2L5GZa2dv9T8a
G+ls4BcNMTkxMTI1MDE1NDE0WjAlAhRTyySCvCZ2LJnaokxNhO3LifngkhcNMTkx
MTI1MDE1NjMwWqAvMC0wKwYDVR0jBCQwIoAg5xmhZslKvW1mYTAezU8dKZP/boqf
68a3H6pmMF1HhDAwCgYIKoZIzj0EAwIDSAAwRQIhAJ5q3wMSpbYimRBZjyF0jAhN
I2ofLBo8ctfZepHRmNnSAiACyPBU6DjkmcdnKMwKW3Qc9RXTm2afT0PhNuc4xsLF
4Q==
-----END X509 CRL-----`

func Test_parseCrl(t *testing.T) {
	crlList, err := x509.ParseCRL([]byte(CRL))
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range crlList.TBSCertList.RevokedCertificates {
		fmt.Println(v)
	}
}

func Test_getSerial(t *testing.T) {
	revokeCert := `-----BEGIN CERTIFICATE-----
MIICtjCCAl2gAwIBAgIUYozTGAUIj0KRdgmjldkiVHr4e7UwCgYIKoZIzj0EAwIw
czELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDVNh
biBGcmFuY2lzY28xGTAXBgNVBAoTEG9yZzEuZXhhbXBsZS5jb20xHDAaBgNVBAMT
E2NhLm9yZzEuZXhhbXBsZS5jb20wHhcNMTkxMTI1MTAyNTAwWhcNMjAxMTI0MTAz
MDAwWjA6MQ0wCwYDVQQLEwR1c2VyMSkwJwYDVQQDEyA0NGIyYmM2ZDVjZTQ0YmE2
NzE0MjdiM2NiNGM4NWYyNjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABN/STZaE
I04cEXv0sCGBoP8wtDSoQQeiDPxHB/ap8lSYF5ihYxq90cGJPTMKEjaPys9yUyIp
p5sh+ycUYhe5WBujggEGMIIBAjAOBgNVHQ8BAf8EBAMCB4AwDAYDVR0TAQH/BAIw
ADAdBgNVHQ4EFgQUKflE731sLhVgBP9SCLQXjcvi7H8wKwYDVR0jBCQwIoAg5xmh
ZslKvW1mYTAezU8dKZP/boqf68a3H6pmMF1HhDAwIwYDVR0RBBwwGoIYY2Eub3Jn
MS5leGFtcGxlLmNvbTo3MDU0MHEGCCoDBAUGBwgBBGV7ImF0dHJzIjp7ImhmLkFm
ZmlsaWF0aW9uIjoiIiwiaGYuRW5yb2xsbWVudElEIjoiNDRiMmJjNmQ1Y2U0NGJh
NjcxNDI3YjNjYjRjODVmMjYiLCJoZi5UeXBlIjoidXNlciJ9fTAKBggqhkjOPQQD
AgNHADBEAiAnhoXkIJACZaH837BTlh0f3Oi8dx8M1OKR4ftI40MJZwIgdxqsDWYQ
2vJN57aTSvtWHkgBnqg0Y7bxzEEblQDldmg=
-----END CERTIFICATE-----`
	cert, err := ParsePemCert([]byte(revokeCert))
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(cert.SerialNumber.String())
	fmt.Printf("%x", cert.SerialNumber)
	//fmt.Println(cert.SerialNumber)
}
