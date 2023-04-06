package comm

// a Wrapper reads data from a reader and wraps it in some process nessecary for the protocol (encryption/decryption/proof/verification)
type Wrapper interface {
	Wrap() ([]byte, error)
}
