package sbom

import (
	"github.com/vela-ssoc/vela-kit/lua"
	"github.com/vela-ssoc/vela-kit/vela"
	"github.com/vela-ssoc/vela-sbom/cyclonedx"
	"github.com/vela-ssoc/vela-sbom/internal/log"
	"github.com/vela-ssoc/vela-sbom/spdx"
)

var xEnv vela.Environment

func newLuaScanFileSbom(L *lua.LState) int {
	lsb := newLSbom(L.CheckString(1), L.IsTrue(2))
	lsb.sha1()
	lsb.Scan()
	L.Push(lsb)
	return 1
}

func WithEnv(env vela.Environment) {
	xEnv = env
	log.WithEnv(env)
	spdx.WithEnv(env)
	cyclonedx.WithEnv(env)
	kv := lua.NewUserKV()
	kv.Set("client", lua.NewFunction(newLuaSbomClient))
	kv.Set("file", lua.NewFunction(newLuaScanFileSbom))
	xEnv.Set("sbom", kv)
}
