package net.dighole.vault

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SettingsValidationTest {
    @Test fun hostRejectsUrlsPathsAndWhitespace() {
        listOf("https://example.com", "example.com/path", "bad host", "-bad.example", "").forEach {
            assertFalse(it, SettingsValidation.server(it))
        }
        listOf("example.com", "192.0.2.1", "2001:db8::1").forEach {
            assertTrue(it, SettingsValidation.server(it))
        }
    }
    @Test fun dnsValidation() {
        assertTrue(SettingsValidation.dns(""))
        assertTrue(SettingsValidation.dns("1.1.1.1, 2606:4700:4700::1111"))
        listOf("example.com", "1.1.1.1,", "999.1.1.1", "1.2.3", "1.1.1.1,,8.8.8.8").forEach {
            assertFalse(it, SettingsValidation.dns(it))
        }
    }
    @Test fun probeDomainsRejectMalformedLists() {
        assertTrue(SettingsValidation.domains("github.com, www.google.com"))
        assertTrue(SettingsValidation.domains(""))
        listOf("https://example.com", "a..com", "example.com,", "bad_domain.com").forEach {
            assertFalse(it, SettingsValidation.domains(it))
        }
    }
}
