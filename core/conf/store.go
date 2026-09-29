/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package conf

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/amnezia-vpn/amneziawg-windows/v3/conf/dpapi"
)

const configFileSuffix = ".conf.dpapi"
const configFileUnencryptedSuffix = ".conf"

func ListConfigNames() ([]string, error) {
	configFileDir, err := tunnelConfigurationsDirectory()
	if err != nil {
		return nil, err
	}
	files, err := os.ReadDir(configFileDir)
	if err != nil {
		return nil, err
	}
	configs := make([]string, len(files))
	i := 0
	for _, file := range files {
		if plainName, ok := plainConfigName(configFileDir, file); ok {
			// AwgChain: a plain config with no encrypted counterpart is a real tunnel
			// too, so the interface must see it in the list.
			configs[i] = plainName
			i++
			continue
		}
		name := filepath.Base(file.Name())
		if len(name) <= len(configFileSuffix) || !strings.HasSuffix(name, configFileSuffix) {
			continue
		}
		if !file.Type().IsRegular() {
			continue
		}
		info, err := file.Info()
		if err != nil {
			continue
		}
		if info.Mode().Perm()&0444 == 0 {
			continue
		}
		name = strings.TrimSuffix(name, configFileSuffix)
		if !TunnelNameIsValid(name) {
			continue
		}
		configs[i] = name
		i++
	}
	return configs[:i], nil
}

func LoadFromName(name string) (*Config, error) {
	configFileDir, err := tunnelConfigurationsDirectory()
	if err != nil {
		return nil, err
	}
	if plain, ok := chainPlainPath(configFileDir, name); ok {
		// AwgChain: a chain hop is owned by the chain tooling and lives in plain
		// text. Prefer it over any stale encrypted copy left by an earlier sweep.
		return LoadFromPath(plain)
	}
	if _, err := os.Stat(filepath.Join(configFileDir, name+configFileSuffix)); err != nil {
		plainPath := filepath.Join(configFileDir, name+configFileUnencryptedSuffix)
		if _, err := os.Stat(plainPath); err == nil {
			return LoadFromPath(plainPath)
		}
	}
	return LoadFromPath(filepath.Join(configFileDir, name+configFileSuffix))
}

func LoadFromPath(path string) (*Config, error) {
	name, err := NameFromPath(path)
	if err != nil {
		return nil, err
	}
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if strings.HasSuffix(path, configFileSuffix) {
		bytes, err = dpapi.Decrypt(bytes, name)
		if err != nil {
			return nil, err
		}
	}
	return FromWgQuickWithUnknownEncoding(string(bytes), name)
}

func PathIsEncrypted(path string) bool {
	return strings.HasSuffix(filepath.Base(path), configFileSuffix)
}

func NameFromPath(path string) (string, error) {
	name := filepath.Base(path)
	if !((len(name) > len(configFileSuffix) && strings.HasSuffix(name, configFileSuffix)) ||
		(len(name) > len(configFileUnencryptedSuffix) && strings.HasSuffix(name, configFileUnencryptedSuffix))) {
		return "", errors.New("Path must end in either " + configFileSuffix + " or " + configFileUnencryptedSuffix)
	}
	if strings.HasSuffix(path, configFileSuffix) {
		name = strings.TrimSuffix(name, configFileSuffix)
	} else {
		name = strings.TrimSuffix(name, configFileUnencryptedSuffix)
	}
	if !TunnelNameIsValid(name) {
		return "", errors.New("Tunnel name is not valid")
	}
	return name, nil
}

func (config *Config) Save(overwrite bool) error {
	if !TunnelNameIsValid(config.Name) {
		return errors.New("Tunnel name is not valid")
	}
	// AwgChain pack 92: one writer at a time. Writing a configuration is
	// two steps, the new file and the removal of the file of the other
	// kind, and a second writer that runs between them deletes the file
	// this one has just written. That is how a tunnel disappeared on 28
	// September without a single line in the log.
	ChainStoreHold()
	defer ChainStoreRelease()

	configFileDir, err := tunnelConfigurationsDirectory()
	if err != nil {
		return err
	}
	// AwgChain pack 86: there is no exception any more. A chain hop used to
	// be written in plain text so that awgchain.bat, the watchdog and the
	// tunnel service could all read one file, which meant the keys of every
	// hop lay on the disk as text. Every configuration is now treated the
	// same way, and the answer to "encrypted or not" comes from one box in
	// the settings. The file of the other kind is removed only after the new
	// one has been written, so a failure in the middle never leaves the
	// tunnel without a configuration.
	plainName := filepath.Join(configFileDir, config.Name+configFileUnencryptedSuffix)
	cryptName := filepath.Join(configFileDir, config.Name+configFileSuffix)
	bytes := []byte(config.ToWgQuick())
	if !chainEncryptWanted() {
		err = writeLockedDownFile(plainName, overwrite, bytes)
		if err != nil {
			return err
		}
		// Pack 91: the removal of the file of the other kind is checked.
		// Two files for one tunnel are not a cosmetic leftover: the loader
		// has to pick one of them, and the one it picks is not always the
		// one that was just written.
		err = chainDropOther(cryptName, plainName)
		if err != nil {
			return err
		}
		return nil
	}
	sealed, err := dpapi.Encrypt(bytes, config.Name)
	if err != nil {
		return err
	}
	err = writeLockedDownFile(cryptName, overwrite, sealed)
	if err != nil {
		return err
	}
	err = chainDropOther(plainName, cryptName)
	if err != nil {
		return err
	}
	return nil
}

func (config *Config) Path() (string, error) {
	if !TunnelNameIsValid(config.Name) {
		return "", errors.New("Tunnel name is not valid")
	}
	configFileDir, err := tunnelConfigurationsDirectory()
	if err != nil {
		return "", err
	}
	if plain, ok := chainPlainPath(configFileDir, config.Name); ok {
		// AwgChain: this is the path the tunnel service will be pointed at.
		return plain, nil
	}
	// AwgChain pack 90: and for every other tunnel the path is the file that
	// is really there. The encrypted name used to be returned whatever lay on
	// the disk, so a tunnel in plain text was handed to its service as
	// <name>.conf.dpapi, and the service died on its first line with "The
	// system cannot find the file specified". Nothing else changes: a name
	// with no file at all still gets the encrypted path, which is what a
	// configuration that is about to be written needs.
	if path, ok := chainExistingConfigPath(configFileDir, config.Name); ok {
		return path, nil
	}
	return filepath.Join(configFileDir, config.Name+configFileSuffix), nil
}

func DeleteName(name string) error {
	if !TunnelNameIsValid(name) {
		return errors.New("Tunnel name is not valid")
	}
	configFileDir, err := tunnelConfigurationsDirectory()
	if err != nil {
		return err
	}
	// Pack 92: the same lock as Save, and the removals are named in the
	// log. Deleting a tunnel is the one place where losing a file is the
	// point, which is exactly why it has to be told apart from losing one
	// by accident.
	ChainStoreHold()
	defer ChainStoreRelease()

	removedAny := false
	var lastErr error
	for _, suffix := range []string{configFileSuffix, configFileUnencryptedSuffix} {
		path := filepath.Join(configFileDir, name+suffix)
		if _, statErr := os.Stat(path); statErr != nil {
			continue
		}
		if rmErr := chainRemoveFile(path, "the tunnel "+name+" was deleted"); rmErr != nil {
			lastErr = rmErr
		} else {
			removedAny = true
		}
	}
	if lastErr != nil && !removedAny {
		return lastErr
	}
	return nil
}

func (config *Config) Delete() error {
	return DeleteName(config.Name)
}
