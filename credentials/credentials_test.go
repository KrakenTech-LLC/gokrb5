package credentials

import (
	"testing"

	"github.com/stretchr/testify/assert"
	goidentity "gopkg.in/jcmturner/goidentity.v3"
)

func TestImplementsInterface(t *testing.T) {
	t.Parallel()
	u := new(Credentials)
	i := new(goidentity.Identity)
	assert.Implements(t, i, u, "Credentials type does not implement the Identity interface")
}
