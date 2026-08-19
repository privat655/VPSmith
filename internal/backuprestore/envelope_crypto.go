package backuprestore

import (
	"errors"
	"fmt"
	"io"
	"os"

	"filippo.io/age"
)

func encryptAge(source, destination string, passphrase []byte) error {
	if len(passphrase) == 0 {
		return errors.New("recovery passphrase is required")
	}
	recipient, err := age.NewScryptRecipient(string(passphrase))
	if err != nil {
		return fmt.Errorf("create age recipient: %w", err)
	}
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = out.Close()
		if !ok {
			_ = os.Remove(destination)
		}
	}()
	writer, err := age.Encrypt(out, recipient)
	if err != nil {
		return fmt.Errorf("create age writer: %w", err)
	}
	if _, err := io.Copy(writer, in); err != nil {
		_ = writer.Close()
		return fmt.Errorf("encrypt backup envelope: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("finish age encryption: %w", err)
	}
	if err := out.Sync(); err != nil {
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}

func decryptAge(source, destination string, passphrase []byte) error {
	if len(passphrase) == 0 {
		return errors.New("recovery passphrase is required")
	}
	identity, err := age.NewScryptIdentity(string(passphrase))
	if err != nil {
		return fmt.Errorf("create age identity: %w", err)
	}
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	reader, err := age.Decrypt(in, identity)
	if err != nil {
		return fmt.Errorf("decrypt age backup: %w", err)
	}
	out, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = out.Close()
		if !ok {
			_ = os.Remove(destination)
		}
	}()
	if _, err := io.Copy(out, reader); err != nil {
		return fmt.Errorf("write decrypted backup envelope: %w", err)
	}
	if err := out.Sync(); err != nil {
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}
