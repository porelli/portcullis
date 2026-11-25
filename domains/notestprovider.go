//go:build !testprovider

package main

import "log"

// startTestProvider: the production binary has no test provider.
func startTestProvider(*log.Logger) error { return nil }

// runTestCommand: the production binary has no test commands.
func runTestCommand([]string) (int, bool) { return 0, false }

// testProviderBuild: production publishes only truly public addresses.
const testProviderBuild = false
