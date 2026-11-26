// SPDX-License-Identifier: MIT
package net.dighole.vault

internal fun canRenameProfile(originalName: String?, newName: String, active: Boolean): Boolean =
    !active || originalName == newName
