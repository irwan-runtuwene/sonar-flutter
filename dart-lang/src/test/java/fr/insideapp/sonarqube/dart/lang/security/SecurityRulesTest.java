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

import org.junit.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public class SecurityRulesTest {

    private static boolean hit(String key, String... lines) {
        SecurityRule rule = SecurityRules.ALL.stream().filter(r -> r.key().equals(key)).findFirst().orElseThrow();
        List<String> all = List.of(lines);
        return java.util.stream.IntStream.range(0, all.size()).anyMatch(i -> DartSecuritySensor.matches(rule, all, i));
    }

    @Test
    public void tls() {
        assertThat(hit("accept_all_certificates", "client.badCertificateCallback = (cert, host, port) => true;")).isTrue();
        assertThat(hit("accept_all_certificates", "client.badCertificateCallback = (c, h, p) { return true; };")).isTrue();
        assertThat(hit("accept_all_certificates", "client.badCertificateCallback = (c, h, p) => false;")).isFalse();
        assertThat(hit("custom_certificate_callback", "client.badCertificateCallback = (c, h, p) => pinned(c);")).isTrue();
        assertThat(hit("custom_certificate_callback", "client.badCertificateCallback = (c, h, p) => true;")).isFalse();
    }

    @Test
    public void cleartext() {
        assertThat(hit("cleartext_http", "final u = 'http://api.example-bank.io/v1';")).isTrue();
        assertThat(hit("cleartext_http", "final u = Uri.http(host, '/x');")).isTrue();
        assertThat(hit("cleartext_http", "final u = 'https://api.example-bank.io/v1';")).isFalse();
        assertThat(hit("cleartext_http", "final u = 'http://localhost:8080/x';")).isFalse();
        assertThat(hit("cleartext_http", "final u = 'http://10.0.2.2:8080/x';")).isFalse();
        assertThat(hit("cleartext_http", "const ns = 'http://www.w3.org/2000/svg';")).isFalse();
        assertThat(hit("cleartext_http", "// see http://old.example-bank.io")).isFalse();
    }

    @Test
    public void randomOnlyNearSecrets() {
        assertThat(hit("insecure_random", "final r = Random();", "final token = r.nextInt(99999);")).isTrue();
        assertThat(hit("insecure_random", "final r = Random();", "final dice = r.nextInt(6) + 1;")).isFalse();
        assertThat(hit("insecure_random", "final token = Random.secure().nextInt(9);")).isFalse();
    }

    @Test
    public void crypto() {
        assertThat(hit("weak_hash", "final d = md5.convert(bytes);")).isTrue();
        assertThat(hit("weak_hash", "final h = Hmac(sha1, key);")).isTrue();
        assertThat(hit("weak_hash", "final d = sha256.convert(bytes);")).isFalse();
        assertThat(hit("ecb_mode", "Encrypter(AES(key, mode: AESMode.ecb));")).isTrue();
        assertThat(hit("ecb_mode", "Encrypter(AES(key, mode: AESMode.gcm));")).isFalse();
        assertThat(hit("static_iv", "final iv = IV.fromUtf8('1234567890123456');")).isTrue();
        assertThat(hit("static_iv", "final iv = IV.fromLength(16);")).isTrue();
        assertThat(hit("static_iv", "final iv = IV.fromSecureRandom(16);")).isFalse();
        assertThat(hit("hardcoded_crypto_key", "final k = Key.fromUtf8('my32lengthsupersecretnooneknows1');")).isTrue();
        assertThat(hit("hardcoded_crypto_key", "final k = Key.fromSecureRandom(32);")).isFalse();
    }

    @Test
    public void hardcodedCredentials() {
        assertThat(hit("hardcoded_credentials", "const apiKey = 'sk_live_51H8abcdefgh';")).isTrue();
        assertThat(hit("hardcoded_credentials", "login(password: 'hunter2hunter2');")).isTrue();
        assertThat(hit("hardcoded_credentials", "final password = '';")).isFalse();
        assertThat(hit("hardcoded_credentials", "final password = 'short';")).isFalse();
        assertThat(hit("hardcoded_credentials", "final secret = '$fromEnv-and-more';")).isFalse();
        assertThat(hit("hardcoded_credentials", "const apiKey = String.fromEnvironment('API_KEY', defaultValue: 'dev-key-12345');")).isFalse();
    }

    @Test
    public void injectionAndWebview() {
        assertThat(hit("sql_injection", "db.rawQuery('SELECT * FROM u WHERE name = $name');")).isTrue();
        assertThat(hit("sql_injection", "db.rawQuery(\"SELECT * FROM u WHERE id = ${user.id}\");")).isTrue();
        assertThat(hit("sql_injection", "db.rawQuery('SELECT * FROM u WHERE name = ' + name);")).isTrue();
        assertThat(hit("sql_injection", "db.execute('DELETE FROM u WHERE id = $id');")).isTrue();
        assertThat(hit("sql_injection", "db.rawQuery('SELECT * FROM u WHERE name = ?', [name]);")).isFalse();
        assertThat(hit("sql_injection", "http.execute('GET $url');")).isFalse();
        assertThat(hit("webview_unrestricted_javascript", "..setJavaScriptMode(JavaScriptMode.unrestricted)")).isTrue();
        assertThat(hit("webview_unrestricted_javascript", "javascriptMode: JavascriptMode.unrestricted,")).isTrue();
        assertThat(hit("webview_unrestricted_javascript", "javaScriptEnabled: true,")).isTrue();
        assertThat(hit("webview_unrestricted_javascript", "..setJavaScriptMode(JavaScriptMode.disabled)")).isFalse();
        assertThat(hit("unsafe_html_sink", "element.innerHtml = userInput;")).isTrue();
        assertThat(hit("unsafe_html_sink", "element.setInnerHtml(s);")).isTrue();
        assertThat(hit("unsafe_html_sink", "element.setInnerHtml(s, validator: strict);")).isFalse();
        assertThat(hit("shell_command_execution", "Process.run('git', args,", "    runInShell: true);")).isTrue();
        assertThat(hit("shell_command_execution", "Process.run('git', args);")).isFalse();
        assertThat(hit("sensitive_data_in_shared_preferences", "await prefs.setString('auth_token', token);")).isTrue();
        assertThat(hit("sensitive_data_in_shared_preferences", "await prefs.setString('theme', 'dark');")).isFalse();
        assertThat(hit("sensitive_data_in_shared_preferences", "await storage.write(key: 'auth_token', value: t);")).isFalse();
    }

    @Test
    public void everyRuleHasACweAndIsExercised() {
        SecurityRules.ALL.forEach(r -> assertThat(r.cwe()).as(r.key()).isNotEmpty());
        assertThat(SecurityRules.ALL).hasSize(14);
    }
}
