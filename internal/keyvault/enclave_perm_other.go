//go:build !unix

package keyvault

import "errors"

const oNoFollow = 0

var errEnclaveUnsupported = errors.New("the Secure Enclave store requires a unix host")

func requireOwnedDir(string) error { return errEnclaveUnsupported }

func requireOwnedFile(string, bool) error { return errEnclaveUnsupported }
