package casdk

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
)

func NewCAClient(path string, transport *http.Transport) (*FabricCAClient, error) {
	config, err := NewCAConfig(path)
	if err != nil {
		return nil, err
	}
	return NewCaClientFromConfig(*config, transport)
}

func NewCaClientFromConfig(config CAConfig, transport *http.Transport) (*FabricCAClient, error) {
	var crypto CryptoSuite
	var err error

	switch config.CryptoConfig.Family {
	case "ecdsa":
		crypto, err = NewECCryptoSuiteFromConfig(config.CryptoConfig)
		if err != nil {
			return nil, err
		}
	default:
		return nil, ErrInvalidAlgorithmFamily
	}
	return &FabricCAClient{
		SkipTLSVerification: config.SkipTLSValidation,
		Url:                 config.Url,
		Crypto:              crypto,
		Transport:           transport,
		MspId:               config.MspId,
		FilePath:            config.FilePath,
		ServerInfo: ServerInfo{
			CAName: config.CaName,
		},
	}, nil
}

// 生成一对公私钥
func (f *FabricCAClient) NewKey() (privateKey, publicKey []byte, err error) {
	key, err := f.Crypto.NewKey()
	if err != nil {
		return
	}
	privateKey, err = key.GetPemPrivateKey()
	if err != nil {
		return
	}
	publicKey, err = key.GetPemPublicKey()
	if err != nil {
		return
	}
	return
}

// GetCaCertificateChain gets root and intermediate certificates used by FabricCA server.
// This certificates must be presented to Fabric entities (peers, orderers) as MSP so they can verify that request
// are from valid entities.
// caName is the name of the CA that should be used. FabricCa support more than one CA server on same endpoint and
// this names are used to distinguish between them. If empty default CA instance will be used.
func (f *FabricCAClient) GetCaInfo() (*CAGetCertResponse, error) {
	reqJson, err := json.Marshal(caInfoRequest{CaName: f.ServerInfo.CAName})
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequest("GET", fmt.Sprintf("%s/api/v1/cainfo", f.Url), bytes.NewBuffer(reqJson))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpClient := &http.Client{Transport: f.getTransport()}
	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		result := new(caInfoResponse)
		if err := json.Unmarshal(body, result); err != nil {
			return nil, err
		}
		if !result.Success {
			return nil, err
		}
		certs, err := base64.StdEncoding.DecodeString(result.Result.CAChain)
		if err != nil {
			return nil, err
		}

		var root []*x509.Certificate
		var intermediate []*pem.Block

		for len(certs) > 0 {
			var block *pem.Block
			block, certs = pem.Decode(certs)
			if block == nil {
				break
			}

			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("error parsing certificate from ca chain")
			}
			if !cert.IsCA {
				return nil, fmt.Errorf("invalid certificate in ca chain")
			}
			// If authority key id is not present or if it is present and equal to subject key id,
			// then it is a root certificate
			if len(cert.AuthorityKeyId) == 0 || bytes.Equal(cert.AuthorityKeyId, cert.SubjectKeyId) {
				root = append(root, cert)
			} else {
				intermediate = append(intermediate, block)
			}
		}
		return &CAGetCertResponse{
			RootCertificates:         root,
			IntermediateCertificates: intermediate,
			Version:                  result.Result.Version,
			CAName:                   result.Result.CAName,
		}, nil
	}
	return nil, fmt.Errorf("non 200 response: %v message is: %s", resp.StatusCode, string(body))
}

// 给已注册的用户申请一个ca证书
//Enroll execute enrollment request for registered user in FabricCA server.
//On success new Identity with ECert and generated csr are returned.
func (f *FabricCAClient) Enroll(request CaEnrollmentRequest) (*Identity, error) {

	// create new cert and send it to CA for signing
	key, err := f.Crypto.GenerateKey()
	if err != nil {
		return nil, err
	}
	var hosts []string
	if len(request.Hosts) == 0 {
		parsedUrl, err := url.Parse(f.Url)
		if err != nil {
			return nil, err
		}
		hosts = []string{parsedUrl.Host}
	} else {
		hosts = request.Hosts
	}
	if request.CAName == "" {
		request.CAName = f.ServerInfo.CAName
	}
	// 构建证书请求csr
	csr, err := f.Crypto.CreateCertificateRequest(request.EnrollmentId, key, hosts)
	if err != nil {
		return nil, err
	}
	crm, err := json.Marshal(certificateRequest{CR: string(csr), CaEnrollmentRequest: request})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("%s/api/v1/enroll", f.Url), bytes.NewBuffer(crm))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(request.EnrollmentId, request.Secret)
	httpClient := &http.Client{Transport: f.getTransport()}
	resp, err := httpClient.Do(req)

	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		enrResp := new(enrollmentResponse)
		if err := json.Unmarshal(body, enrResp); err != nil {
			return nil, err
		}
		if !enrResp.Success {
			return nil, concatErrors(enrResp.Errors)
		}

		cabyte, err := base64.StdEncoding.DecodeString(enrResp.Result.ServerInfo.CAChain)
		if err != nil {
			return nil, err
		}
		cablock, _ := pem.Decode(cabyte)
		cacert, err := x509.ParseCertificate(cablock.Bytes)
		f.ServerInfo.CAName = enrResp.Result.ServerInfo.CAName
		f.ServerInfo.CACert = cacert

		rawCert, err := base64.StdEncoding.DecodeString(enrResp.Result.Cert)
		if err != nil {
			return nil, err
		}
		a, _ := pem.Decode(rawCert)
		cert, err := x509.ParseCertificate(a.Bytes)
		if err != nil {
			return nil, err
		}
		return &Identity{Certificate: cert, PrivateKey: key, MspId: f.MspId}, nil
	}
	return nil, fmt.Errorf("non 200 response: %v message is: %s", resp.StatusCode, string(body))
}

// 根据私钥申请证书
func (f *FabricCAClient) EnrollByKey(request CaEnrollmentRequest, pemPrivateKey []byte) (*Identity, error) {
	key, err := ParsePemKey(pemPrivateKey)
	if err != nil {
		return nil, err
	}
	var hosts []string
	if len(request.Hosts) == 0 {
		parsedUrl, err := url.Parse(f.Url)
		if err != nil {
			return nil, err
		}
		hosts = []string{parsedUrl.Host}
	} else {
		hosts = request.Hosts
	}
	if request.CAName == "" {
		request.CAName = f.ServerInfo.CAName
	}
	// 构建证书请求csr
	csr, err := f.Crypto.CreateCertificateRequest(request.EnrollmentId, key, hosts)
	if err != nil {
		return nil, err
	}
	crm, err := json.Marshal(certificateRequest{CR: string(csr), CaEnrollmentRequest: request})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("%s/api/v1/enroll", f.Url), bytes.NewBuffer(crm))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(request.EnrollmentId, request.Secret)
	httpClient := &http.Client{Transport: f.getTransport()}
	resp, err := httpClient.Do(req)

	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		enrResp := new(enrollmentResponse)
		if err := json.Unmarshal(body, enrResp); err != nil {
			return nil, err
		}
		if !enrResp.Success {
			return nil, concatErrors(enrResp.Errors)
		}

		cabyte, err := base64.StdEncoding.DecodeString(enrResp.Result.ServerInfo.CAChain)
		if err != nil {
			return nil, err
		}
		cablock, _ := pem.Decode(cabyte)
		cacert, err := x509.ParseCertificate(cablock.Bytes)
		f.ServerInfo.CAName = enrResp.Result.ServerInfo.CAName
		f.ServerInfo.CACert = cacert

		rawCert, err := base64.StdEncoding.DecodeString(enrResp.Result.Cert)
		if err != nil {
			return nil, err
		}
		a, _ := pem.Decode(rawCert)
		cert, err := x509.ParseCertificate(a.Bytes)
		if err != nil {
			return nil, err
		}
		return &Identity{Certificate: cert, PrivateKey: key, MspId: f.MspId}, nil
	}
	return nil, fmt.Errorf("non 200 response: %v message is: %s", resp.StatusCode, string(body))
}

// Register registers new user in fabric-ca server. In registration request attributes, affiliation and
// max enrolments must be set.
// It is responsibility of the SDK user to ensure passwords are with big entropy.
// Identity parameter is certificate for user that makes registration and this user MUST have the role for
// registering new users.
func (f *FabricCAClient) Register(identity *Identity, req *CARegistrationRequest) (string, error) {
	if req.EnrolmentId == "" {
		return "", ErrEnrollmentIdMissing
	}
	/*if req.Affiliation == "" {
		return "", ErrAffiliationMissing
	}*/
	if req.Type == "" {
		return "", ErrTypeMissing
	}
	if identity == nil {
		return "", ErrCertificateEmpty
	}
	reqJson, err := json.Marshal(req)
	if err != nil {
		return "", err
	}

	httpReq, err := http.NewRequest("POST", fmt.Sprintf("%s/api/v1/register", f.Url), bytes.NewBuffer(reqJson))
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	token, err := f.createToken(identity, reqJson, httpReq.Method, httpReq.URL.RequestURI())
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("authorization", token)

	httpClient := &http.Client{Transport: f.getTransport()}

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		result := new(caRegisterResponse)
		if err = json.Unmarshal(body, result); err != nil {
			return "", err
		}
		if !result.Success {
			return "", concatErrors(result.Errors)
		}
		if len(result.Errors) > 0 {
			return "", concatErrors(result.Errors)
		}
		return result.Result.Secret, nil
	}
	return "", fmt.Errorf("non 200 response: %v message is: %s", resp.StatusCode, string(body))
}

func (f *FabricCAClient) createToken(identity *Identity, request []byte, method, uri string) (string, error) {

	b64body := B64Encode(request)
	b64cert := B64Encode(identity.GetPemCert())
	b64uri := B64Encode([]byte(uri))
	payload := method + "." + b64uri + "." + b64body + "." + b64cert

	sig, err := f.Crypto.Sign([]byte(payload), identity.PrivateKey)
	if err != nil {
		return "", err
	}

	token := b64cert + "." + B64Encode(sig)
	return token, nil
}

func (f *FabricCAClient) getTransport() *http.Transport {
	var tr *http.Transport
	if f.Transport == nil {
		tr = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: f.SkipTLSVerification},
		}
	} else {
		tr = f.Transport
	}
	return tr
}

// Revoke revokes ECert in fabric-ca server.
// Note that this request will revoke certificate ONLY in FabricCa server. Peers (for now) do not know
// about this certificate revocation.
// It is responsibility of the SDK user to update peers and set this certificate in every peer revocation list.
func (f *FabricCAClient) Revoke(identity *Identity, request *CARevocationRequest) (*CARevokeResult, error) {
	reqJson, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequest("POST", fmt.Sprintf("%s/api/v1/revoke", f.Url), bytes.NewBuffer(reqJson))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	token, err := f.createToken(identity, reqJson, httpReq.Method, httpReq.URL.RequestURI())
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("authorization", token)

	httpClient := &http.Client{Transport: f.getTransport()}
	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		result := new(caRevokeResponse)
		if err := json.Unmarshal(body, result); err != nil {
			return nil, err
		}
		if !result.Success {
			return nil, concatErrors(result.Errors)
		}
		return &result.Result, nil
	}
	return nil, fmt.Errorf("non 200 response: %v message is: %s", resp.StatusCode, string(body))
}

func (f *FabricCAClient) GetIdentity(identity *Identity, id string, caName string) (*CAGetIdentityResponse, error) {
	if identity == nil {
		return nil, ErrCertificateEmpty
	}
	if len(id) == 0 {
		return nil, ErrIdentityNameMissing
	}

	httpReq, err := http.NewRequest("GET", fmt.Sprintf("%s/api/v1/identities/%s", f.Url, id), bytes.NewBuffer(nil))
	if err != nil {
		return nil, err
	}
	if len(caName) > 0 {
		uri := httpReq.URL.Query()
		uri.Add("ca", caName)
		httpReq.URL.RawQuery = uri.Encode()
	}
	token, err := f.createToken(identity, nil, httpReq.Method, httpReq.URL.RequestURI())
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("authorization", token)

	httpClient := &http.Client{Transport: f.getTransport()}

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		result := new(caGetIdentity)
		if err := json.Unmarshal(body, result); err != nil {
			return nil, err
		}
		if !result.Success {
			return nil, concatErrors(result.Errors)
		}
		if len(result.Errors) > 0 {
			return nil, concatErrors(result.Errors)
		}
		return &result.Result, nil
	}
	return nil, fmt.Errorf("non 200 response: %v message is: %s", resp.StatusCode, string(body))
}

// ListAllIdentities get list of all identities from FabricCa server
func (f *FabricCAClient) GetIdentities(identity *Identity, caName string) (*CAListAllIdentitesResponse, error) {
	if identity == nil {
		return nil, ErrCertificateEmpty
	}

	httpReq, err := http.NewRequest("GET", fmt.Sprintf("%s/api/v1/identities", f.Url), bytes.NewBuffer(nil))
	if err != nil {
		return nil, err
	}
	if len(caName) > 0 {
		uri := httpReq.URL.Query()
		uri.Add("ca", caName)
		httpReq.URL.RawQuery = uri.Encode()
	}
	token, err := f.createToken(identity, nil, httpReq.Method, httpReq.RequestURI)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("authorization", token)

	httpClient := &http.Client{Transport: f.getTransport()}
	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		result := new(caListAllIdentities)
		if err := json.Unmarshal(body, result); err != nil {
			return nil, err
		}
		if !result.Success {
			return nil, concatErrors(result.Errors)
		}
		if len(result.Errors) > 0 {
			return nil, concatErrors(result.Errors)
		}
		return &result.Result, nil
	}
	return nil, fmt.Errorf("non 200 response: %v message is: %s", resp.StatusCode, string(body))
}

func concatErrors(errs []caResponseErr) error {
	errors := ""
	for _, e := range errs {
		errors += e.Message + ":"
	}
	return fmt.Errorf(errors)
}

// 获取证书吊销列表
func (f *FabricCAClient) Gencrl(identity *Identity) (out *pkix.CertificateList, err error) {
	if identity == nil {
		return nil, ErrCertificateEmpty
	}
	reqBody := map[string]string{
		"caname": f.ServerInfo.CAName,
	}
	reqJson, err := json.Marshal(reqBody)
	if err != nil {
		return
	}

	httpReq, err := http.NewRequest("POST", fmt.Sprintf("%s/api/v1/gencrl", f.Url), bytes.NewBuffer(reqJson))
	if err != nil {
		return nil, err
	}

	token, err := f.createToken(identity, reqJson, httpReq.Method, httpReq.URL.RequestURI())
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("authorization", token)

	httpClient := &http.Client{Transport: f.getTransport()}

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		result := new(crlResponse)
		if err := json.Unmarshal(body, result); err != nil {
			return nil, err
		}
		if !result.Success {
			return nil, err
		}
		crls, err := base64.StdEncoding.DecodeString(result.Result.CRL)
		if err != nil {
			return nil, err
		}
		out, err = x509.ParseCRL(crls)
		return out, err
	}
	return nil, errors.New("unknow error")
}

/**
 * 获取证书的 serial、aki
 */
func (f *FabricCAClient) GetCertSerialAki(pemCert []byte) (string, string, error) {
	cert, err := ParsePemCert(pemCert)
	if err != nil {
		return "", "", err
	}

	return fmt.Sprintf("%x", cert.SerialNumber), hex.EncodeToString(cert.AuthorityKeyId), nil
}
