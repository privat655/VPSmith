package deployment

import (
	"errors"
	"fmt"
	"strings"

	"github.com/privat655/VPSmith/internal/modulecontract"
)

// CheckCoreCompatibility validates only the compatibility contract of already
// frozen module packages. It does not resolve images or generate module
// runtime, so a Core update cannot accidentally mutate or re-plan modules.
func (c *Compiler) CheckCoreCompatibility(coreContract string, modules []FrozenModuleSource) error {
	if c == nil {
		return errors.New("deployment compiler is required")
	}
	if strings.TrimSpace(coreContract) == "" {
		return errors.New("Core candidate core_contract is required")
	}
	for _, source := range modules {
		if source.InstanceID == "" || source.SourceID == "" || source.PackageID == "" || source.PackageSHA256 == "" || source.PackageFS == nil {
			return fmt.Errorf("module %s frozen source identity is incomplete", source.InstanceID)
		}
		contract, err := c.modules.Compile(modulecontract.Package{FS: source.PackageFS})
		if err != nil {
			return fmt.Errorf("compile module %s for Core compatibility: %w", source.InstanceID, err)
		}
		if contract.CoreContract != coreContract {
			return fmt.Errorf("module %s requires core_contract %s, Core candidate provides %s", source.InstanceID, contract.CoreContract, coreContract)
		}
	}
	return nil
}
