package casdk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"golang.org/x/crypto/sha3"
	"hash"
	"math/big"
	"net"
	"net/mail"
)

// CryptSuite defines common interface for different crypto implementations.
// Currently Hyperledger Fabric supports only Elliptic curves.

type CryptoSuite interface {
	// GenerateKey returns PrivateKey.
	GenerateKey() (interface{}, error)
	// CreateCertificateRequest will create CSR request. It takes enrolmentId and Private key
	CreateCertificateRequest(enrollmentId string, key interface{}, hosts []string) ([]byte, error)
	// Sign signs message. It takes message to sign and Private key
	Sign(msg []byte, k interface{}) ([]byte, error)
	// Hash computes Hash value of provided data. Hash function will be different in different crypto implementations.
	Hash(data []byte) []byte
	// new key to byte
	NewKey() (CryptoSuite, error)
	// get privateKey byte
	GetPemPrivateKey() ([]byte, error)
	// get publicKey byte
	GetPemPublicKey() ([]byte, error)
	// verify by public
	Verify(private interface{}, signature, digest []byte) (valid bool, err error)
}

var (
	// precomputed curves half order values for efficiency
	ecCurveHalfOrders = map[elliptic.Curve]*big.Int{
		elliptic.P224(): new(big.Int).Rsh(elliptic.P224().Params().N, 1),
		elliptic.P256(): new(big.Int).Rsh(elliptic.P256().Params().N, 1),
		elliptic.P384(): new(big.Int).Rsh(elliptic.P384().Params().N, 1),
		elliptic.P521(): new(big.Int).Rsh(elliptic.P521().Params().N, 1),
	}
)

type ECCryptSuite struct {
	curve        elliptic.Curve
	sigAlgorithm x509.SignatureAlgorithm
	key          *ecdsa.PrivateKey
	hashFunction func() hash.Hash
}

type eCDSASignature struct {
	R, S *big.Int
}

func (c *ECCryptSuite) NewKey() (CryptoSuite, error) {
	/*if c.key != nil {
		return c, nil
	}*/
	key, err := ecdsa.GenerateKey(c.curve, rand.Reader)
	if err != nil {
		return nil, err
	}
	res := &ECCryptSuite{
		curve:        c.curve,
		sigAlgorithm: c.sigAlgorithm,
		key:          key,
		hashFunction: c.hashFunction,
	}
	return res, nil
}

func (c *ECCryptSuite) GetPemPrivateKey() ([]byte, error) {
	if c.key == nil {
		return nil, fmt.Errorf("PrivateKey not found")
	}
	raw, err := x509.MarshalPKCS8PrivateKey(c.key)
	if err != nil {
		return nil, fmt.Errorf("Failed marshalling Privatekey [%s]", err)
	}
	b := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw})
	return b, nil
}

func (c *ECCryptSuite) GetPemPublicKey() ([]byte, error) {
	if c.key == nil {
		return nil, fmt.Errorf("PrivateKey not found")
	}

	raw, err := x509.MarshalPKIXPublicKey(c.key.Public())
	if err != nil {
		return nil, fmt.Errorf("Failed marshalling PublicKey [%s]", err)
	}
	b := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: raw})
	return b, nil
}

func (c *ECCryptSuite) GenerateKey() (interface{}, error) {
	key, err := ecdsa.GenerateKey(c.curve, rand.Reader)
	if err != nil {
		return nil, err
	}
	c.key = key

	return key, nil
}

func (c *ECCryptSuite) CreateCertificateRequest(enrollmentId string, key interface{}, hosts []string) ([]byte, error) {
	if enrollmentId == "" {
		return nil, ErrEnrollmentIdMissing
	}
	subj := pkix.Name{
		CommonName: enrollmentId,
	}
	rawSubj := subj.ToRDNSequence()

	asn1Subj, err := asn1.Marshal(rawSubj)
	if err != nil {
		return nil, err
	}

	ipAddr := make([]net.IP, 0)
	emailAddr := make([]string, 0)
	dnsAddr := make([]string, 0)

	for i := range hosts {
		if ip := net.ParseIP(hosts[i]); ip != nil {
			ipAddr = append(ipAddr, ip)
		} else if email, err := mail.ParseAddress(hosts[i]); err == nil && email != nil {
			emailAddr = append(emailAddr, email.Address)
		} else {
			dnsAddr = append(dnsAddr, hosts[i])
		}
	}

	template := x509.CertificateRequest{
		RawSubject:         asn1Subj,
		SignatureAlgorithm: c.sigAlgorithm,
		IPAddresses:        ipAddr,
		EmailAddresses:     emailAddr,
		DNSNames:           dnsAddr,
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
	if err != nil {
		return nil, err
	}
	csr := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
	return csr, nil
}

func (c *ECCryptSuite) Sign(msg []byte, k interface{}) ([]byte, error) {
	key, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, ErrInvalidKeyType
	}
	var h []byte
	h = c.Hash(msg)
	R, S, err := ecdsa.Sign(rand.Reader, key, h)
	if err != nil {
		return nil, err
	}
	S, _, err = ToLowS(&key.PublicKey, S)
	if err != nil {
		return nil, err
	}
	sig, err := asn1.Marshal(eCDSASignature{R, S})
	if err != nil {
		return nil, err
	}
	return sig, nil
}

func (c *ECCryptSuite) Hash(data []byte) []byte {
	h := c.hashFunction()
	h.Write(data)
	return h.Sum(nil)
}

func NewECCryptoSuiteFromConfig(config CryptoConfig) (CryptoSuite, error) {
	var suite *ECCryptSuite

	switch config.Algorithm {
	case "P256-SHA256":
		suite = &ECCryptSuite{curve: elliptic.P256(), sigAlgorithm: x509.ECDSAWithSHA256}
	case "P384-SHA384":
		suite = &ECCryptSuite{curve: elliptic.P384(), sigAlgorithm: x509.ECDSAWithSHA384}
	case "P521-SHA512":
		suite = &ECCryptSuite{curve: elliptic.P521(), sigAlgorithm: x509.ECDSAWithSHA512}
	default:
		return nil, ErrInvalidAlgorithm
	}

	switch config.Hash {
	case "SHA2-256":
		suite.hashFunction = sha256.New
	case "SHA2-384":
		suite.hashFunction = sha512.New384
	case "SHA3-256":
		suite.hashFunction = sha3.New256
	case "SHA3-384":
		suite.hashFunction = sha3.New384
	default:
		return nil, ErrInvalidHash
	}
	return suite, nil
}

// 私钥 签名 待签名的数据
func (c *ECCryptSuite) Verify(public interface{}, signature, digest []byte) (valid bool, err error) {
	k, ok := public.(*ecdsa.PublicKey)
	if !ok {
		err = fmt.Errorf("public key error")
		return
	}
	r, s, err := c.UnmarshalECDSASignature(signature)
	if err != nil {
		return false, fmt.Errorf("Failed unmashalling signature [%s]", err)
	}

	lowS, err := IsLowS(k, s)
	if err != nil {
		return false, err
	}

	if !lowS {
		return false, fmt.Errorf("Invalid S. Must be smaller than half the order [%s].", s)
	}
	hashByte := c.Hash(digest)
	return ecdsa.Verify(k, hashByte, r, s), nil
}

func (c *ECCryptSuite) UnmarshalECDSASignature(raw []byte) (*big.Int, *big.Int, error) {
	// Unmarshal
	sig := new(eCDSASignature)
	_, err := asn1.Unmarshal(raw, sig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed unmashalling signature [%s]", err)
	}
	// Validate sig
	if sig.R == nil {
		return nil, nil, errors.New("invalid signature, R must be different from nil")
	}
	if sig.S == nil {
		return nil, nil, errors.New("invalid signature, S must be different from nil")
	}

	if sig.R.Sign() != 1 {
		return nil, nil, errors.New("invalid signature, R must be larger than zero")
	}
	if sig.S.Sign() != 1 {
		return nil, nil, errors.New("invalid signature, S must be larger than zero")
	}

	return sig.R, sig.S, nil
}
