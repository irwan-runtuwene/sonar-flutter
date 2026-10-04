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

import fr.insideapp.sonarqube.dart.lang.Dart;
import org.sonar.api.rules.RuleType;
import org.sonar.api.server.rule.RulesDefinition;

public class SecurityRulesDefinition implements RulesDefinition {

    public static final String REPOSITORY_KEY = "dartsecurity";

    @Override
    public void define(Context context) {
        NewRepository repository = context.createRepository(REPOSITORY_KEY, Dart.KEY).setName("dartsecurity");

        for (SecurityRule r : SecurityRules.ALL) {
            create(repository, r.key(), r.name(), r.type(), r.severity(), r.cwe(), r.html());
        }
        String snapshot;
        try {
            snapshot = DartDependencySensor.loadSnapshot().generatedAt();
        } catch (java.io.IOException e) {
            snapshot = "an unknown date";
        }
        create(repository, SecurityRules.VULNERABLE_DEPENDENCY, "Dependencies with known vulnerabilities must be updated",
                RuleType.VULNERABILITY, "CRITICAL", new int[]{1395},
                "<p>A package locked in <code>pubspec.lock</code> is affected by a published advisory (CVE or GHSA). "
                        + "Upgrade to a fixed version with <code>dart pub upgrade &lt;package&gt;</code>.</p>"
                        + "<p><strong>No finding means \"not in the advisory snapshot bundled with this plugin (fetched " + snapshot
                        + " from OSV, Pub ecosystem)\", not \"no known CVE\".</strong> "
                        + "Advisories published after that date, and packages OSV does not cover, are not checked. "
                        + "Keep scanning with a live tool such as <code>osv-scanner</code> for clearance.</p>");

        repository.done();
    }

    private static void create(NewRepository repository, String key, String name, RuleType type, String severity,
                               int[] cwe, String html) {
        NewRule rule = repository.createRule(key)
                .setName(name)
                .setType(type)
                .setSeverity(severity)
                .setActivatedByDefault(true)
                .setHtmlDescription(html)
                .addCwe(cwe);
        rule.setDebtRemediationFunction(rule.debtRemediationFunctions().constantPerIssue("30min"));
    }
}
