package managementstate

import (
	"errors"
	"fmt"
	"strings"
)

// CreatePendingTarget creates the canonical target record before the provider
// has assigned an address. This is enough to mint its per-target SSH identity.
func (c *Change) CreatePendingTarget(id TargetID, sshUser string) error {
	if id == "" || strings.TrimSpace(sshUser) == "" {
		return errors.New("target id and ssh user are required")
	}
	_, err := c.conn.ExecContext(c.ctx, `INSERT INTO targets(id,address,ssh_user,ssh_trust,desired_json,observed_json) VALUES(?, '', ?, ?, '{}', '{}')`, id, sshUser, TrustUnknown)
	if err != nil {
		return fmt.Errorf("create pending target %s: %w", id, err)
	}
	return nil
}

// SetTargetAddress records the administrator-provided address after provider boot.
// It does not observe or establish SSH trust.
func (c *Change) SetTargetAddress(id TargetID, address string) error {
	address = strings.TrimSpace(address)
	if address == "" {
		return errors.New("target address is required")
	}
	result, err := c.conn.ExecContext(c.ctx, `UPDATE targets SET address=? WHERE id=?`, address, id)
	if err != nil {
		return fmt.Errorf("set target address: %w", err)
	}
	return requireOne(result, "target")
}
