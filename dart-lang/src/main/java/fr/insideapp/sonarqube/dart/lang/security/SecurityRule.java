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

import org.sonar.api.rules.RuleType;

import java.util.regex.Pattern;

/**
 * A line-based source pattern rule. {@code context}, when set, must also match somewhere in the
 * {@code window} lines around the hit (used to cut noise, e.g. Random() only near secret-looking words).
 */
public record SecurityRule(String key, String name, RuleType type, String severity, int[] cwe, String html,
                           Pattern pattern, Pattern unless, Pattern context, int window) {

    SecurityRule(String key, String name, RuleType type, String severity, int cwe, String html, String regex) {
        this(key, name, type, severity, new int[]{cwe}, html, Pattern.compile(regex), null, null, 0);
    }

    SecurityRule unless(String regex) {
        return new SecurityRule(key, name, type, severity, cwe, html, pattern, Pattern.compile(regex), context, window);
    }

    SecurityRule near(String regex, int window) {
        return new SecurityRule(key, name, type, severity, cwe, html, pattern, unless, Pattern.compile(regex), window);
    }
}
