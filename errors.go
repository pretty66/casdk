package casdk

import "errors"

var (
	ErrInvalidAlgorithmFamily = errors.New("invalid algorithm family")
	ErrInvalidAlgorithm       = errors.New("invalid algorithm for ECDSA")
	ErrInvalidHash            = errors.New("invalid hash algorithm")
	ErrInvalidKeyType         = errors.New("invalid key type is provided")
	ErrEnrollmentIdMissing    = errors.New("enrollment id is empty")
	ErrAffiliationMissing     = errors.New("affiliation is missing")
	ErrTypeMissing            = errors.New("type is missing")
	ErrCertificateEmpty       = errors.New("certificate cannot be nil")
	ErrIdentityNameMissing    = errors.New("identity must have  name")
)
