package cataloger

import (
	"github.com/vela-ssoc/vela-sbom/detect/pkg/cataloger/java"
)

type Config struct {
	Search     SearchConfig
	Catalogers []string
}

func DefaultConfig() Config {
	return Config{
		Search: DefaultSearchConfig(),
	}
}

func (c Config) Java() java.Config {
	return java.Config{
		SearchUnindexedArchives: c.Search.IncludeUnindexedArchives,
		SearchIndexedArchives:   c.Search.IncludeIndexedArchives,
	}
}
