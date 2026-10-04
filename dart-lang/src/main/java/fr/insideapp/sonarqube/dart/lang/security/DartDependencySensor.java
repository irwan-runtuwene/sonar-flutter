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

import com.fasterxml.jackson.databind.ObjectMapper;
import fr.insideapp.sonarqube.dart.lang.Dart;
import org.sonar.api.batch.fs.InputFile;
import org.sonar.api.batch.rule.Severity;
import org.sonar.api.batch.sensor.Sensor;
import org.sonar.api.batch.sensor.SensorContext;
import org.sonar.api.batch.sensor.SensorDescriptor;
import org.sonar.api.batch.sensor.issue.NewIssue;
import org.sonar.api.rule.RuleKey;
import org.sonar.api.utils.log.Logger;
import org.sonar.api.utils.log.Loggers;
import org.yaml.snakeyaml.Yaml;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;
import java.util.Map;

/** Reports packages in pubspec.lock that match a bundled advisory snapshot. Fully offline. */
public class DartDependencySensor implements Sensor {

    private static final Logger LOGGER = Loggers.get(DartDependencySensor.class);
    static final String ADVISORIES = "/security/pub-advisories.json";

    @Override
    public void describe(SensorDescriptor descriptor) {
        descriptor.name("Dart dependency vulnerability sensor")
                .onlyOnLanguage(Dart.KEY)
                .createIssuesForRuleRepositories(SecurityRulesDefinition.REPOSITORY_KEY);
    }

    @Override
    public void execute(SensorContext context) {
        RuleKey rule = RuleKey.of(SecurityRulesDefinition.REPOSITORY_KEY, SecurityRules.VULNERABLE_DEPENDENCY);
        if (context.activeRules().find(rule) == null) {
            return;
        }
        List<PubAdvisory> advisories;
        try {
            advisories = loadAdvisories();
        } catch (IOException e) {
            LOGGER.error("Failed to load the bundled advisories", e);
            return;
        }
        var fs = context.fileSystem();
        var specs = fs.inputFiles(fs.predicates().matchesPathPattern("**/pubspec.yaml"));
        for (InputFile spec : specs) {
            check(context, rule, advisories, spec, new File(spec.file().getParentFile(), "pubspec.lock"));
        }
    }

    @SuppressWarnings("unchecked")
    private void check(SensorContext context, RuleKey rule, List<PubAdvisory> advisories, InputFile spec, File lock) {
        if (!lock.isFile()) {
            LOGGER.debug("No pubspec.lock next to {}", spec);
            return;
        }
        Map<String, Object> packages;
        try (Reader reader = Files.newBufferedReader(lock.toPath(), StandardCharsets.UTF_8)) {
            Object root = new Yaml().load(reader);
            packages = (Map<String, Object>) ((Map<String, Object>) root).get("packages");
        } catch (IOException | RuntimeException e) {
            LOGGER.warn("Cannot read {}: {}", lock, e.getMessage());
            return;
        }
        if (packages == null) {
            return;
        }
        packages.forEach((name, value) -> {
            Map<String, Object> entry = (Map<String, Object>) value;
            Object version = entry.get("version");
            if (version == null || !"hosted".equals(entry.get("source"))) {
                return;
            }
            for (PubAdvisory advisory : advisories) {
                if (advisory.pkg().equals(name) && advisory.affects(version.toString())) {
                    report(context, rule, spec, name, version.toString(), String.valueOf(entry.get("dependency")), advisory);
                }
            }
        });
    }

    private void report(SensorContext context, RuleKey rule, InputFile spec, String name, String version,
                        String kind, PubAdvisory advisory) {
        String fixed = advisory.fixedIn(version);
        String message = name + " " + version + " is affected by " + advisory.displayId()
                + (advisory.displayId().equals(advisory.id()) ? "" : " (" + advisory.id() + ")")
                + ": " + advisory.summary() + "."
                + (fixed == null ? "" : " Fixed in " + fixed + ".")
                + (kind.contains("dev") ? " (dev dependency)" : "");
        NewIssue issue = context.newIssue().forRule(rule).overrideSeverity(Severity.valueOf(advisory.severity()));
        issue.at(issue.newLocation().on(spec).message(message)).save();
    }

    static List<PubAdvisory> loadAdvisories() throws IOException {
        try (InputStream in = DartDependencySensor.class.getResourceAsStream(ADVISORIES)) {
            if (in == null) {
                throw new IOException("missing resource " + ADVISORIES);
            }
            return List.of(new ObjectMapper().readValue(in, PubAdvisory[].class));
        }
    }
}
