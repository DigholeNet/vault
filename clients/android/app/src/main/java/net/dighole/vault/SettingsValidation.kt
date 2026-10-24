package net.dighole.vault

/** Syntax checks only: editing settings never resolves hostnames on the network. */
internal object SettingsValidation {
    fun domain(value: String): Boolean {
        val host = value.removeSuffix(".")
        return host.isNotEmpty() && value.length <= 253 && host.split('.').all {
            it.length in 1..63 && it.first().isLetterOrDigit() && it.last().isLetterOrDigit() &&
                it.all { c -> c in 'a'..'z' || c in 'A'..'Z' || c in '0'..'9' || c == '-' }
        }
    }
    fun address(value: String): Boolean = if (':' in value) {
        value.all { it in "0123456789abcdefABCDEF:." } &&
            runCatching { java.net.InetAddress.getByName(value) }.isSuccess
    } else value.split('.').let { parts ->
        parts.size == 4 && parts.all { it.isNotEmpty() && it.all(Char::isDigit) && it.toIntOrNull() in 0..255 }
    }
    fun server(value: String): Boolean = address(value) || domain(value)
    fun dns(value: String): Boolean = value.isBlank() || value.split(',').all { address(it.trim()) }
    fun domains(value: String): Boolean = value.isBlank() || value.split(',').all { domain(it.trim()) }
}
