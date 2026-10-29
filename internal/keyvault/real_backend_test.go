package keyvault

import (
	"os"
	"testing"

	"github.com/relux-works/mac-infra/internal/keyvault/testguard"
)

func TestMain(m *testing.M) { os.Exit(testguard.Main(m)) }
