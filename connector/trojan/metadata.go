package trojan

import (
	md "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
	"time"
)

type metadata struct{ connectTimeout time.Duration }

func (c *trojanConnector) parseMetadata(md md.Metadata) error {
	c.md.connectTimeout = mdutil.GetDuration(md, "timeout")
	return nil
}
