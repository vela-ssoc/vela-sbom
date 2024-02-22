package spdx

import (
	"fmt"
	"github.com/vela-ssoc/vela-kit/lua"
	"github.com/vela-ssoc/vela-kit/vela"
)

var xEnv vela.Environment

func (sdx *Spdx) String() string                         { return fmt.Sprintf("%p", sdx) }
func (sdx *Spdx) Type() lua.LValueType                   { return lua.LTObject }
func (sdx *Spdx) AssertFloat64() (float64, bool)         { return 0, false }
func (sdx *Spdx) AssertString() (string, bool)           { return "", false }
func (sdx *Spdx) AssertFunction() (*lua.LFunction, bool) { return nil, false }
func (sdx *Spdx) Peek() lua.LValue                       { return sdx }

func WithEnv(env vela.Environment) {
	xEnv = env
}
