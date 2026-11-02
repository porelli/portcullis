//go:build !testprovider

package main

import "log"

// startTestProvider: the production binary has no test provider.
func startTestProvider(*log.Logger) error { return nil }
