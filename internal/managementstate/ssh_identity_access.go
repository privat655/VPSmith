package managementstate

import (
	"database/sql"
	"errors"
	"fmt"
)

// SSHIdentitySecretID returns the administrative SSH identity reference inside
// an already-serialized management-state change. It exists so identity
// creation can be an atomic ensure operation rather than a read-then-write
// race across transactions.
func (c *Change) SSHIdentitySecretID(targetID TargetID) (SecretID, error) {
	var id SecretID
	if err := c.conn.QueryRowContext(c.ctx, `SELECT ssh_identity_secret_id FROM targets WHERE id=?`, targetID).Scan(&id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", fmt.Errorf("target does not exist")
		}
		return "", fmt.Errorf("read target ssh identity: %w", err)
	}
	return id, nil
}
