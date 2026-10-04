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
import org.sonar.api.batch.fs.InputFile;
import org.sonar.api.batch.sensor.Sensor;
import org.sonar.api.batch.sensor.SensorContext;
import org.sonar.api.batch.sensor.SensorDescriptor;
import org.sonar.api.batch.sensor.issue.NewIssue;
import org.sonar.api.rule.RuleKey;
import org.sonar.api.utils.log.Logger;
import org.sonar.api.utils.log.Loggers;

import java.io.IOException;
import java.util.List;

/** Applies {@link SecurityRules} to the lines of every main Dart source file. */
public class DartSecuritySensor implements Sensor {

    private static final Logger LOGGER = Loggers.get(DartSecuritySensor.class);

    @Override
    public void describe(SensorDescriptor descriptor) {
        descriptor.name("Dart security sensor")
                .onlyOnLanguage(Dart.KEY)
                .createIssuesForRuleRepositories(SecurityRulesDefinition.REPOSITORY_KEY);
    }

    @Override
    public void execute(SensorContext context) {
        var predicates = context.fileSystem().predicates();
        var files = context.fileSystem().inputFiles(predicates.and(
                predicates.hasLanguage(Dart.KEY), predicates.hasType(InputFile.Type.MAIN)));
        for (InputFile file : files) {
            try {
                scan(context, file);
            } catch (IOException e) {
                LOGGER.warn("Security scan skipped {}: {}", file, e.getMessage());
            }
        }
    }

    private void scan(SensorContext context, InputFile file) throws IOException {
        List<String> lines = file.contents().lines().toList();
        for (SecurityRule rule : SecurityRules.ALL) {
            if (context.activeRules().find(RuleKey.of(SecurityRulesDefinition.REPOSITORY_KEY, rule.key())) == null) {
                continue;
            }
            for (int i = 0; i < lines.size(); i++) {
                if (matches(rule, lines, i)) {
                    NewIssue issue = context.newIssue()
                            .forRule(RuleKey.of(SecurityRulesDefinition.REPOSITORY_KEY, rule.key()));
                    issue.at(issue.newLocation().on(file).at(file.selectLine(i + 1)).message(rule.name())).save();
                }
            }
        }
    }

    static boolean matches(SecurityRule rule, List<String> lines, int index) {
        String line = lines.get(index);
        String trimmed = line.trim();
        if (trimmed.startsWith("//") || trimmed.startsWith("*") || trimmed.startsWith("/*")) {
            return false;
        }
        if (!rule.pattern().matcher(line).find()) {
            return false;
        }
        if (rule.unless() != null && rule.unless().matcher(line).find()) {
            return false;
        }
        if (rule.context() == null) {
            return true;
        }
        int from = Math.max(0, index - rule.window());
        int to = Math.min(lines.size(), index + rule.window() + 1);
        return rule.context().matcher(String.join("\n", lines.subList(from, to))).find();
    }
}
