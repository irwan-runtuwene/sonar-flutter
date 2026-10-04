/*
 * SonarQube Flutter Plugin - Enables analysis of Dart and Flutter projects into SonarQube.
 * Copyright © 2020 inside|app (contact@insideapp.fr)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package fr.insideapp.sonarqube.dart.lang.security;

import java.util.List;

import static org.sonar.api.rules.RuleType.SECURITY_HOTSPOT;
import static org.sonar.api.rules.RuleType.VULNERABILITY;

/** Insecure-code patterns for Dart and Flutter. Hotspots are sinks that need a human to judge the data flow. */
public final class SecurityRules {

    /** Rule key of the pubspec.lock advisory rule (see {@link DartDependencySensor}). */
    public static final String VULNERABLE_DEPENDENCY = "vulnerable_dependency";

    public static final List<SecurityRule> ALL = List.of(
            new SecurityRule("accept_all_certificates", "TLS certificate validation must not be disabled",
                    VULNERABILITY, "CRITICAL", 295,
                    "<p>A <code>badCertificateCallback</code> that always returns <code>true</code> accepts any certificate, so a man-in-the-middle can read and alter traffic.</p>"
                            + "<p>Remove the callback, or pin the expected certificate or public key.</p>",
                    "\\bbadCertificateCallback\\s*=.*(=>\\s*true\\b|return\\s+true\\b)"),
            new SecurityRule("custom_certificate_callback", "Custom TLS certificate checks should be reviewed",
                    SECURITY_HOTSPOT, "MAJOR", 295,
                    "<p>A custom <code>badCertificateCallback</code> overrides certificate validation. Check that it only accepts a pinned certificate and never returns <code>true</code> unconditionally.</p>",
                    "\\bbadCertificateCallback\\s*=").unless("(=>\\s*(true|false)\\b|return\\s+(true|false)\\b)"),
            new SecurityRule("cleartext_http", "Clear-text HTTP should not be used",
                    SECURITY_HOTSPOT, "MAJOR", 319,
                    "<p>Traffic over <code>http://</code> can be read and modified on the network. Use <code>https://</code>.</p>",
                    "(['\"]http://(?!(localhost|127\\.0\\.0\\.1|10\\.0\\.2\\.2|0\\.0\\.0\\.0|\\[::1\\]|www\\.w3\\.org|schemas\\.|xmlns|example\\.(com|org|net)))[^'\"\\s$]+)|\\bUri\\.http\\(")
                    .unless("xmlns"),
            new SecurityRule("insecure_random", "Non-cryptographic random numbers must not be used for secrets",
                    SECURITY_HOTSPOT, "MAJOR", 338,
                    "<p><code>Random()</code> from <code>dart:math</code> is predictable. Use <code>Random.secure()</code> for tokens, keys, nonces, salts and one-time codes.</p>",
                    "\\bRandom\\s*\\(\\s*(\\d+\\s*)?\\)")
                    .near("(?i)(token|secret|password|passwd|nonce|salt|\\botp\\b|session|csrf|api_?key|\\bkey\\b|\\biv\\b)", 3),
            new SecurityRule("weak_hash", "Weak hash functions should not be used for security",
                    SECURITY_HOTSPOT, "MAJOR", 328,
                    "<p>MD5 and SHA-1 are broken for collision resistance. Use SHA-256 or stronger, and a password hashing function (Argon2, bcrypt, PBKDF2) for passwords.</p>",
                    "\\b(md5|sha1)\\s*\\.\\s*(convert|bind|startChunkedConversion)\\b|\\bHmac\\s*\\(\\s*(md5|sha1)\\b|\\bDigest\\s*\\(\\s*['\"](MD5|SHA-?1)['\"]"),
            new SecurityRule("ecb_mode", "ECB mode must not be used for encryption",
                    VULNERABILITY, "CRITICAL", 327,
                    "<p>ECB encrypts identical blocks identically and leaks structure. Use an authenticated mode such as AES-GCM.</p>",
                    "\\bAESMode\\.ecb\\b|\\bECBBlockCipher\\b|['\"]AES/ECB"),
            new SecurityRule("static_iv", "Initialization vectors must not be hard-coded or zero",
                    VULNERABILITY, "CRITICAL", 329,
                    "<p>A fixed IV makes encryption deterministic and breaks CBC and GCM. Generate a fresh random IV per message with <code>IV.fromSecureRandom</code>.</p>",
                    "\\bIV\\.from(Utf8|Base64|Base16)\\(\\s*['\"]|\\bIV\\.fromLength\\("),
            new SecurityRule("hardcoded_crypto_key", "Encryption keys must not be hard-coded",
                    VULNERABILITY, "CRITICAL", 321,
                    "<p>A key embedded in the app can be extracted from the binary. Derive it at runtime or keep it in the platform keystore.</p>",
                    "\\bKey\\.from(Utf8|Base64|Base16)\\(\\s*['\"]"),
            new SecurityRule("hardcoded_credentials", "Credentials should not be hard-coded",
                    SECURITY_HOTSPOT, "BLOCKER", 798,
                    "<p>Secrets committed to source control or shipped in the app can be extracted. Load them from the environment, a secret store or the platform keystore.</p>",
                    "(?i)\\b\\w*(password|passwd|pwd|secret|api_?key|access_?token|auth_?token|private_?key|client_?secret)\\w*\\s*[:=]\\s*(const\\s+)?['\"](?![^'\"]*\\$)[^'\"\\s]{8,}['\"]")
                    .unless("fromEnvironment"),
            new SecurityRule("sql_injection", "SQL queries must not be built with string interpolation",
                    VULNERABILITY, "CRITICAL", 89,
                    "<p>Interpolating or concatenating values into raw SQL allows injection. Pass values as bound arguments (<code>?</code> placeholders).</p>",
                    "\\b(rawQuery|rawInsert|rawUpdate|rawDelete|customSelect|customStatement|customUpdate|customInsert)\\s*\\(\\s*(?:'[^']*\\$[{a-zA-Z_][^']*'|\"[^\"]*\\$[{a-zA-Z_][^\"]*\"|['\"][^'\"]*['\"]\\s*\\+)|\\b(db|database|txn|batch)\\s*\\.\\s*execute\\s*\\(\\s*(?:'[^']*\\$[{a-zA-Z_][^']*'|\"[^\"]*\\$[{a-zA-Z_][^\"]*\")"),
            new SecurityRule("webview_unrestricted_javascript", "Unrestricted WebView JavaScript should be reviewed",
                    SECURITY_HOTSPOT, "MAJOR", 79,
                    "<p>Enabling JavaScript in a WebView that loads untrusted or remote content exposes the app to script injection. Enable it only for content you control.</p>",
                    "(?i)javascript(mode\\.unrestricted|enabled\\s*:\\s*true)"),
            new SecurityRule("unsafe_html_sink", "Unsanitized HTML must not be written to the DOM",
                    SECURITY_HOTSPOT, "MAJOR", 79,
                    "<p>Assigning to <code>innerHtml</code> or <code>outerHtml</code>, or using <code>setInnerHtml</code> without a validator, can execute attacker-supplied markup. Sanitize or use text nodes.</p>",
                    "\\.(innerHtml|outerHtml)\\s*=|\\bsetInnerHtml\\(|\\binsertAdjacentHtml\\(|\\.createFragment\\(|\\bDocumentFragment\\.html\\(")
                    .unless("validator\\s*:|treeSanitizer\\s*:"),
            new SecurityRule("shell_command_execution", "Running commands through a shell should be reviewed",
                    SECURITY_HOTSPOT, "MAJOR", 78,
                    "<p><code>runInShell: true</code> passes the command through the system shell, so any untrusted argument can inject commands. Run the executable directly with an argument list.</p>",
                    "\\bProcess\\.(run|start|runSync)\\s*\\(")
                    .near("runInShell\\s*:\\s*true", 3),
            new SecurityRule("sensitive_data_in_shared_preferences", "Secrets must not be stored in shared preferences",
                    SECURITY_HOTSPOT, "MAJOR", 312,
                    "<p>SharedPreferences is stored unencrypted. Keep tokens and passwords in the platform keystore (for example <code>flutter_secure_storage</code>).</p>",
                    "(?i)\\b\\w*(prefs|preferences)\\w*\\s*\\.\\s*set(String|StringList)\\s*\\(\\s*['\"][^'\"]*(password|passwd|secret|token|api_?key|private_?key)")
    );

    private SecurityRules() {
    }
}
