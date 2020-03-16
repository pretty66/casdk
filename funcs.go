package casdk

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
)

func B64Encode(buf []byte) string {
	return base64.StdEncoding.EncodeToString(buf)
}

func B64Decode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

func IsLowS(k *ecdsa.PublicKey, s *big.Int) (bool, error) {
	halfOrder, ok := ecCurveHalfOrders[k.Curve]
	if !ok {
		return false, fmt.Errorf("curve not recognized [%s]", k.Curve)
	}

	return s.Cmp(halfOrder) != 1, nil

}

func ToLowS(k *ecdsa.PublicKey, s *big.Int) (*big.Int, bool, error) {
	lowS, err := IsLowS(k, s)
	if err != nil {
		return nil, false, err
	}

	if !lowS {
		// Set s to N - s that will be then in the lower part of signature space
		// less or equal to half order
		s.Sub(k.Params().N, s)

		return s, true, nil
	}

	return s, false, nil
}

func CertToPem(cert *x509.Certificate) []byte {
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	return pem.EncodeToMemory(block)
}

func ParsePemCert(cert []byte) (*x509.Certificate, error) {
	p, _ := pem.Decode(cert)
	if p == nil || len(p.Bytes) == 0 {
		return nil, errors.New("cert parse error")
	}
	return x509.ParseCertificate(p.Bytes)
}

func ParsePemKey(key []byte) (*ecdsa.PrivateKey, error) {
	p, _ := pem.Decode(key)
	if p == nil || len(p.Bytes) == 0 {
		return nil, errors.New("key parse error")
	}
	privateKey, err := DERToPrivateKey(p.Bytes)
	if err != nil {
		return nil, err
	}
	ecdsaPrivateKey, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		err = errors.New("privateKey type error")
	}
	return ecdsaPrivateKey, nil
}

func DERToPrivateKey(der []byte) (key interface{}, err error) {

	if key, err = x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err = x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			return
		default:
			return nil, errors.New("Found unknown private key type in PKCS#8 wrapping")
		}
	}

	if key, err = x509.ParseECPrivateKey(der); err == nil {
		return
	}

	return nil, errors.New("Invalid key type. The DER must contain an rsa.PrivateKey or ecdsa.PrivateKey")
}

func GetCertSerialNumber(pemCert []byte) (string, string, error) {
	cert, err := ParsePemCert(pemCert)
	if err != nil {
		return "", "", err
	}

	return fmt.Sprintf("%x", cert.SerialNumber), hex.EncodeToString(cert.AuthorityKeyId), nil
}

func GetPemPrivateKey(key interface{}) ([]byte, error) {
	if key == nil {
		return nil, fmt.Errorf("PrivateKey not found")
	}
	raw, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("Failed marshalling Privatekey [%s]", err)
	}
	b := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw})
	return b, nil
}

func GetPemPublicKey(key interface{}) ([]byte, error) {
	if key == nil {
		return nil, fmt.Errorf("PublicKey not found")
	}
	// privateKey.Public()
	raw, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, fmt.Errorf("Failed marshalling PublicKey [%s]", err)
	}
	b := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: raw})
	return b, nil
}
