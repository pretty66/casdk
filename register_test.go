package casdk

import (
	"fmt"
	"testing"
)

func init() {
	client, err = NewCAClient("./caconfig.yaml", nil)
	if err != nil {
		panic(err)
	}
}

func TestB64Decode(t *testing.T) {
	c := `LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNVVENDQWZlZ0F3SUJBZ0lRRStWT1c5V3duT3VYTGRpTFRFT0FSREFLQmdncWhrak9QUVFEQWpCek1Rc3cKQ1FZRFZRUUdFd0pWVXpFVE1CRUdBMVVFQ0JNS1EyRnNhV1p2Y201cFlURVdNQlFHQTFVRUJ4TU5VMkZ1SUVaeQpZVzVqYVhOamJ6RVpNQmNHQTFVRUNoTVFiM0puTVM1bGVHRnRjR3hsTG1OdmJURWNNQm9HQTFVRUF4TVRZMkV1CmIzSm5NUzVsZUdGdGNHeGxMbU52YlRBZUZ3MHhPVEV4TWpBd01UTXpNREJhRncweU9URXhNVGN3TVRNek1EQmEKTUhNeEN6QUpCZ05WQkFZVEFsVlRNUk13RVFZRFZRUUlFd3BEWVd4cFptOXlibWxoTVJZd0ZBWURWUVFIRXcxVApZVzRnUm5KaGJtTnBjMk52TVJrd0Z3WURWUVFLRXhCdmNtY3hMbVY0WVcxd2JHVXVZMjl0TVJ3d0dnWURWUVFECkV4TmpZUzV2Y21jeExtVjRZVzF3YkdVdVkyOXRNRmt3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUUKMytDVWh3Qk1UQ3NwcC9MZS9DZU9RWUNBSkdkS3JpV1hJSVJlZUUxMm1rT0lHM2tQU2U2bTFEU3d6dU1DUGZEeQo4cWtZZzk2U05zR1l0RmtEaVJwVmlxTnRNR3N3RGdZRFZSMFBBUUgvQkFRREFnR21NQjBHQTFVZEpRUVdNQlFHCkNDc0dBUVVGQndNQ0JnZ3JCZ0VGQlFjREFUQVBCZ05WSFJNQkFmOEVCVEFEQVFIL01Da0dBMVVkRGdRaUJDRG4KR2FGbXlVcTliV1poTUI3TlR4MHBrLzl1aXAvcnhyY2ZxbVl3WFVlRU1EQUtCZ2dxaGtqT1BRUURBZ05JQURCRgpBaUVBeHRHdytJcGtKMk50bXNVNEpWSzRBRlBXRzR3NmdLTTUvK3A5U0ZuMVJYb0NJQTBoVFcvOUEwQ1FCOSsxCjV5L0ZJTE4ybTNQbzM2ejJZZmVHOXNLL2cxdk4KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=`
	res, err := B64Decode(c)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(string(res))
}

func Test_register(t *testing.T) {
	idn := initIdentity()
	attr := make([]CaRegisterAttribute, 0)
	/*attr[0] = CaRegisterAttribute{
		Name:  "name",
		Value: "xiao mi",
		ECert: false,
	}
	attr[1] = CaRegisterAttribute{
		Name:  "org_code",
		Value: "niqweqweq",
		ECert: true,
	}*/
	req := CARegistrationRequest{
		EnrolmentId:    "test_203",
		Type:           "operator",
		Secret:         "test_203",
		MaxEnrollments: -1,
		Attrs:          attr,
		CAName:         client.ServerInfo.CAName,
	}
	res, err := client.Register(idn, &req)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(res)
}

func Test_Enroll(t *testing.T) {
	enrollId := "test_203"
	//attrs := make([]CaEnrollAttribute, 2)
	/*attrs[0] = CaEnrollAttribute{
		Name:     "names",
		Optional: false,
	}*/
	/*attrs[0] = CaEnrollAttribute{
		Name:     "org_code",
		Optional: true,
	}
	attrs[1] = CaEnrollAttribute{
		Name:     "org_code2",
		Optional: false,
	}*/
	/*attrs[1] = CaEnrollAttribute{
		Name:     "hf.Type",
		Optional: true,
	}
	attrs[2] = CaEnrollAttribute{
		Name:     "names",
		Optional: false,
	}*/
	enrollReq := CaEnrollmentRequest{
		EnrollmentId: enrollId,
		Secret:       "test_203",
		Attrs:        nil,
	}
	idn, err := client.Enroll(enrollReq)
	checkErr(t, err)
	//privKey, ok := idn.PrivateKey.(*ecdsa.PrivateKey)
	cert, privKey, pubKey, err := idn.GetStoreData()
	if err != nil {
		t.Fatal(err)
	}
	writeData(enrollId+"_cert", cert)
	writeData(enrollId+"_privateKey", privKey)
	fmt.Println("--------- cert -------- \n", string(cert))
	fmt.Println("--------- privateKey -------- \n", string(privKey))
	fmt.Println("--------- publicKey -------- \n", string(pubKey))
}
