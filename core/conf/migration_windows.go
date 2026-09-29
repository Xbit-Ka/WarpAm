/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2021 WireGuard LLC. All Rights Reserved.
 */

package conf

// AwgChain pack 92: this file used to carry the migration inherited from
// WireGuard. It walked the configurations folder, encrypted every plain
// <name>.conf into <name>.conf.dpapi and removed the plain file, and the
// manager woke it through the folder watcher on every change of that
// folder.
//
// It had to go, for three reasons that all showed up in one afternoon.
//
// It fought the Configs section. Decrypting the configurations is an
// answer to a question the user asked; this pass encrypted them back a
// moment later, because writing the plain file is itself a change of the
// folder and the change woke the pass. The button looked broken.
//
// It raced with that section over single files. The pass reads
// <name>.conf, writes <name>.conf.dpapi and removes the plain file, while
// the decryption writes <name>.conf and removes <name>.conf.dpapi. Meet in
// the middle and each side removes the file the other has just written.
// On 28 September a tunnel disappeared exactly this way, and nothing in
// the log said a word.
//
// And it was pointless. A plain configuration dropped into the folder by
// hand is read, listed and raised by this program since pack 86, and how
// new configurations are written is decided by one box in the settings.
// There was nothing left for the pass to fix.
//
// The name stays so that a caller outside this package still compiles.

type MigrationCallback func(name, oldPath, newPath string)

// MigrateUnencryptedConfigs does nothing. See the note above.
func MigrateUnencryptedConfigs(migrated MigrationCallback) {}
