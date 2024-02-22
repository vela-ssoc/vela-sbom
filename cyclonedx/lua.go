package cyclonedx

import (
	"fmt"
	"github.com/vela-ssoc/vela-kit/audit"
	"github.com/vela-ssoc/vela-kit/lua"
	"github.com/vela-ssoc/vela-kit/pipe"
	"github.com/vela-ssoc/vela-kit/vela"
)

var xEnv vela.Environment

func (cdx *Cyclonedx) String() string                         { return fmt.Sprintf("%p", cdx) }
func (cdx *Cyclonedx) Type() lua.LValueType                   { return lua.LTObject }
func (cdx *Cyclonedx) AssertFloat64() (float64, bool)         { return 0, false }
func (cdx *Cyclonedx) AssertString() (string, bool)           { return "", false }
func (cdx *Cyclonedx) AssertFunction() (*lua.LFunction, bool) { return nil, false }
func (cdx *Cyclonedx) Peek() lua.LValue                       { return cdx }

func (cdx *Cyclonedx) pipeL(L *lua.LState) int {
	n := len(cdx.Components)
	if n == 0 {
		return 0
	}

	pip := pipe.NewByLua(L, pipe.Env(xEnv))
	if pip.Len() == 0 {
		return 0
	}

	co := xEnv.Clone(L)
	defer xEnv.Free(co)

	for i := 0; i < n; i++ {
		cmt := cdx.Components[i]
		ada := lua.NewAnyData(cmt, lua.Reflect(lua.ELEM))
		pip.Do(ada, co, func(err error) {
			audit.Errorf("spdx pipe call fail %v", err).From(co.CodeVM()).Put()
		})
	}

	return 0

}

func (cdx *Cyclonedx) Index(L *lua.LState, key string) lua.LValue {
	switch key {
	case "size":
		return lua.LInt(len(cdx.Components))

	case "pipe":
		return lua.NewFunction(cdx.pipeL)

	}

	return lua.LNil
}

func WithEnv(env vela.Environment) {
	xEnv = env
}
