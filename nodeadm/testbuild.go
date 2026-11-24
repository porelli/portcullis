//go:build testprovider

package main

// testProviderBuild: the CI-only build (go build -tags testprovider;
// Dockerfile build arg GO_TAGS=testprovider, e2e-ha-k3d) admits the
// documentation ranges (TEST-NET-1..3, 2001:db8::/32, 3fff::/20) as public
// node addresses, as the front door's testprovider build does: the k3d
// nodes' "public" addresses are TEST-NET-3. Never in the published image.
const testProviderBuild = true
