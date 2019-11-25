package casdk

import (
	"fmt"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
)

type CAConfig struct {
	CryptoConfig      `yaml:"crypto"`
	Url               string `yaml:"url"`
	SkipTLSValidation bool   `yaml:"skiptlsvalidation"`
	MspId             string `yaml:"mspid"`
	FilePath          string `yaml:"filepath"`
	CaName			  string `yaml:"caname"`
}

type CryptoConfig struct {
	Family    string `yaml:"family"`
	Algorithm string `yaml:"algorithm"`
	Hash      string `yaml:"hash"`
}

func NewCAConfig(path string) (*CAConfig, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	config := new(CAConfig)
	err = yaml.Unmarshal([]byte(data), config)
	if err != nil {
		return nil, err
	}
	return config, nil
}

func IsPathExists(filepath string) (bool, error) {
	fi, err := os.Stat(filepath)
	if err != nil {
		return false, err
	}
	if !fi.IsDir() {
		return false, fmt.Errorf("The path: %s is not directory", filepath)
	}
	return true, nil
}
