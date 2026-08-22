package deployment

// CheckCoreCompatibility validates only the compatibility contract of already
// frozen module packages. It uses the same module.yaml compilation path as the
// Core platform producer, but does not resolve module images or generate module
// runtime. A Core update therefore cannot accidentally mutate or re-plan a
// module while checking compatibility.
func (c *Compiler) CheckCoreCompatibility(coreContract string, modules []FrozenModuleSource) error {
	_, err := c.compileFrozenPlatformModules(coreContract, modules)
	return err
}
