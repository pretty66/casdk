package casdk

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path"
)

type Identity struct {
	Certificate *x509.Certificate
	PrivateKey  interface{}
	MspId       string
}

var ID *Identity

func (i *Identity) SaveCert(ca *FabricCAClient, enreq *CaEnrollmentRequest, cainfo *CAGetCertResponse) error {
	var mspDir string
	var err error

	is, err := IsPathExists(ca.FilePath)
	if err != nil || !is {
		return err
	}
	//保存tls证书
	//	if enreq.Profile == "tls" {
	//		err = saveTLScert(ca, i, cainfo)
	//		if err != nil {
	//			return err
	//		}
	//		return nil
	//	}

	if enreq == nil {
		mspDir = path.Join(ca.FilePath, "/msp")
	} else {
		mspfile := enreq.EnrollmentId + "msp"
		mspDir = path.Join(ca.FilePath, mspfile)
	}
	//保存根证书
	caPath := path.Join(mspDir, "/cacerts")
	err = os.MkdirAll(caPath, os.ModePerm)
	if err != nil {
		return err
	}
	caFile := path.Join(caPath, "ca-cert.pem")
	caPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cainfo.RootCertificates[0].Raw,
		},
	)
	err = ioutil.WriteFile(caFile, caPem, 0644)
	if err != nil {
		return err
	}
	//保存中间证书
	if len(cainfo.IntermediateCertificates) > 0 {
		intercaPath := path.Join(mspDir, "/intermediatecerts")
		err = os.MkdirAll(intercaPath, os.ModePerm)
		if err != nil {
			return err
		}
		caFile = path.Join(intercaPath, "intermediate-certs.pem")
		for _, interca := range cainfo.IntermediateCertificates {
			intercaPem := pem.EncodeToMemory(interca)
			fd, err := os.OpenFile(caFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, os.ModePerm)
			if err != nil {
				return err
			}
			fd.Write(intercaPem)
			fd.Write([]byte("\n"))
			fd.Close()
		}
	}
	//保存证书
	certPath := path.Join(mspDir + "/signcerts")
	err = os.MkdirAll(certPath, os.ModePerm)
	if err != nil {
		return err
	}
	certFile := path.Join(certPath, "cert.pem")
	certPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: i.Certificate.Raw,
		},
	)
	err = ioutil.WriteFile(certFile, certPem, 0644)
	if err != nil {
		return err
	}
	//保存私钥
	keyPath := path.Join(mspDir, "/keystore")
	err = os.MkdirAll(keyPath, os.ModePerm)
	if err != nil {
		return err
	}
	keyFile := path.Join(keyPath, "key.pem")
	keyByte, err := x509.MarshalECPrivateKey(i.PrivateKey.(*ecdsa.PrivateKey))
	if err != nil {
		return err
	}
	keyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: keyByte,
		},
	)
	err = ioutil.WriteFile(keyFile, keyPem, 0644)
	if err != nil {
		return nil
	}
	return nil
}

//Save crl
func SaveCrl(ca *FabricCAClient, request *CARevocationRequest, result *CARevokeResult) error {
	var err error
	mspfile := request.EnrollmentId + "msp"
	mspDir := path.Join(ca.FilePath, mspfile)
	crlPath := path.Join(mspDir, "/crls")
	err = os.MkdirAll(crlPath, os.ModePerm)
	if err != nil {
		return err
	}
	crlFile := path.Join(crlPath, "crl.pem")

	crl, err := base64.StdEncoding.DecodeString(result.CRL)
	if err != nil {
		return err
	}
	crlPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "X509 CRL",
			Bytes: crl,
		},
	)
	err = ioutil.WriteFile(crlFile, crlPem, 0644)
	if err != nil {
		return err
	}
	return nil
}

func (i *Identity) SaveTLScert(ca *FabricCAClient, cainfo *CAGetCertResponse) error {
	var err error
	mspDir := path.Join(ca.FilePath, "/tlsmsp")

	//保存根证书
	caPath := path.Join(mspDir, "/tlscacerts")
	err = os.MkdirAll(caPath, os.ModePerm)
	if err != nil {
		return err
	}
	caFile := path.Join(caPath, "ca-cert.pem")
	caPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cainfo.RootCertificates[0].Raw,
		},
	)
	err = ioutil.WriteFile(caFile, caPem, 0644)
	if err != nil {
		return err
	}
	//保存中间证书
	if len(cainfo.IntermediateCertificates) > 0 {
		intercaPath := path.Join(mspDir, "/tlsintermediatecerts")
		err = os.MkdirAll(intercaPath, os.ModePerm)
		if err != nil {
			return err
		}
		caFile = path.Join(intercaPath, "intermediate-certs.pem")
		for _, interca := range cainfo.IntermediateCertificates {
			interca_pem := pem.EncodeToMemory(interca)
			fd, err := os.OpenFile(caFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, os.ModePerm)
			if err != nil {
				return err
			}
			fd.Write(interca_pem)
			fd.Write([]byte("\n"))
			fd.Close()
		}
	}
	//保存证书
	certPath := path.Join(mspDir + "/signcerts")
	err = os.MkdirAll(certPath, os.ModePerm)
	if err != nil {
		return err
	}
	certFile := path.Join(certPath, "cert.pem")
	certPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: i.Certificate.Raw,
		},
	)
	err = ioutil.WriteFile(certFile, certPem, 0644)
	if err != nil {
		return err
	}
	//保存私钥
	keyPath := path.Join(mspDir, "/keystore")
	err = os.MkdirAll(keyPath, os.ModePerm)
	if err != nil {
		return err
	}
	keyFile := path.Join(keyPath, "key.pem")
	keyByte, err := x509.MarshalECPrivateKey(i.PrivateKey.(*ecdsa.PrivateKey))
	if err != nil {
		return err
	}
	keyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: keyByte,
		},
	)
	err = ioutil.WriteFile(keyFile, keyPem, 0644)
	if err != nil {
		return nil
	}
	return nil
}

func (i *Identity) GetPemCert() []byte {
	return CertToPem(i.Certificate)
}

func (i *Identity) GetPemPrivateKey() ([]byte, error) {
	raw, err := x509.MarshalPKCS8PrivateKey(i.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("Failed marshalling Privatekey [%s]", err)
	}
	b := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw})
	return b, nil
}

func (i *Identity) GetPemPublicKey() (b []byte, err error) {
	privKey, ok := i.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		err = errors.New("privateKey type error")
		return
	}
	raw, err := x509.MarshalPKIXPublicKey(privKey.Public())
	if err != nil {
		return nil, fmt.Errorf("Failed marshalling PublicKey [%s]", err)
	}
	b = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: raw})
	return b, nil
}

func (i *Identity) GetStoreData() (cert, privateKey, publicKey []byte, err error) {
	cert = i.GetPemCert()
	privateKey, err = i.GetPemPrivateKey()
	if err != nil {
		return
	}
	publicKey, err = i.GetPemPublicKey()
	if err != nil {
		return
	}
	return
}



func (i *Identity) setPemPrivateKey(privateKey []byte) {

}



func InitAdminIdentity(cert, privateKey []byte) (*Identity, error) {
	var err error
	adminIdn := &Identity{}
	adminIdn.PrivateKey, err = ParsePemKey(privateKey)
	if err != nil {
		return nil, err
	}
	adminIdn.Certificate, err = ParsePemCert(cert)
	if err != nil {
		return nil, err
	}
	return adminIdn, nil
}