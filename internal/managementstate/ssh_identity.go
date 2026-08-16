package managementstate

import (
	"fmt"
)

// SetSSHIdentity changes only the administrative SSH identity reference for a
// target. It does not establish a connection or alter the target VPS.
func (c *Change) SetSSHIdentity(targetID TargetID, secretID SecretID) error {
	if secretID == "" {
		return fmt.Errorf("ssh identity secret id is required")
	}
	if err := c.requireSecret(secretID); err != nil {
		return err
	}
	result, err := c.conn.ExecContext(c.ctx, `UPDATE targets SET ssh_identity_secret_id=? WHERE id=?`, secretID, targetID)
	if err != nil {
		return fmt.Errorf("set target ssh identity: %w", err)
	}
	return requireOne(result, "target")
}
