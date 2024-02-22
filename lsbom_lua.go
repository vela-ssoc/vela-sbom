package sbom

import (
	"fmt"
	"github.com/vela-ssoc/vela-kit/lua"
)

func (lsb *LSbom) String() string                         { return fmt.Sprintf("%p", lsb) }
func (lsb *LSbom) Type() lua.LValueType                   { return lua.LTObject }
func (lsb *LSbom) AssertFloat64() (float64, bool)         { return 0, false }
func (lsb *LSbom) AssertString() (string, bool)           { return "", false }
func (lsb *LSbom) AssertFunction() (*lua.LFunction, bool) { return nil, false }
func (lsb *LSbom) Peek() lua.LValue                       { return lsb }

func (lsb *LSbom) reportL(L *lua.LState) int {
	err := xEnv.Push("/api/v1/broker/collect/agent/sbom", lsb.ToLCatalog())
	if err != nil {
		L.Push(lua.S2L(err.Error()))
		return 1
	}
	return 0
}

func (lsb *LSbom) reset(L *lua.LState) int {
	lsb.value = nil
	return 0
}

func (lsb *LSbom) Index(L *lua.LState, key string) lua.LValue {
	switch key {
	case "sdx":
		return lua.B2L(lsb.spdx())
	case "cdx":
		return lua.B2L(lsb.cyclonedx())
	case "catalog":
		return lsb.ToLCatalog()
	case "reset":
		return lua.NewFunction(lsb.reset)

	}

	return lua.LNil
}
