package model

import (
	"github.com/vela-ssoc/vela-sbom/detect/file"
	"github.com/vela-ssoc/vela-sbom/detect/source"
)

type Secrets struct {
	Location source.Coordinates  `json:"location"`
	Secrets  []file.SearchResult `json:"secrets"`
}
