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

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.sonar.api.batch.fs.InputFile;
import org.sonar.api.batch.fs.internal.TestInputFileBuilder;
import org.sonar.api.batch.rule.internal.ActiveRulesBuilder;
import org.sonar.api.batch.rule.internal.NewActiveRule;
import org.sonar.api.batch.sensor.internal.SensorContextTester;
import org.sonar.api.batch.sensor.issue.Issue;
import org.sonar.api.rule.RuleKey;

import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public class DartDependencySensorTest {

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    private static final String LOCK = "packages:\n"
            + "  http:\n    dependency: \"direct main\"\n    source: hosted\n    version: \"0.13.0\"\n"
            + "  dio:\n    dependency: \"direct main\"\n    source: hosted\n    version: \"5.4.0\"\n"
            + "  archive:\n    dependency: transitive\n    source: hosted\n    version: \"3.3.7\"\n"
            + "  jose:\n    dependency: \"direct dev\"\n    source: hosted\n    version: \"0.3.4\"\n"
            + "  http_forked:\n    dependency: \"direct main\"\n    source: git\n    version: \"0.1.0\"\n";

    private SensorContextTester context(boolean ruleActive) throws Exception {
        File base = tmp.newFolder();
        Files.writeString(new File(base, "pubspec.lock").toPath(), LOCK);
        Files.writeString(new File(base, "pubspec.yaml").toPath(), "name: app\n");
        SensorContextTester ctx = SensorContextTester.create(base.toPath());
        ctx.fileSystem().add(new TestInputFileBuilder("p", base, new File(base, "pubspec.yaml"))
                .setLanguage("dart").setType(InputFile.Type.MAIN).setContents("name: app\n").build());
        ActiveRulesBuilder rules = new ActiveRulesBuilder();
        if (ruleActive) {
            rules.addRule(new NewActiveRule.Builder()
                    .setRuleKey(RuleKey.of(SecurityRulesDefinition.REPOSITORY_KEY, SecurityRules.VULNERABLE_DEPENDENCY)).build());
        }
        ctx.setActiveRules(rules.build());
        return ctx;
    }

    @Test
    public void reportsOnlyHostedPackagesInsideAffectedRanges() throws Exception {
        SensorContextTester ctx = context(true);
        new DartDependencySensor().execute(ctx);

        List<String> messages = new ArrayList<>();
        for (Issue i : ctx.allIssues()) {
            messages.add(i.primaryLocation().message());
        }
        assertThat(messages).hasSize(4);
        assertThat(messages).anyMatch(m -> m.startsWith("http 0.13.0 is affected by CVE-2020-35669") && m.contains("Fixed in 0.13.3."));
        assertThat(messages).anyMatch(m -> m.startsWith("archive 3.3.7") && m.contains("CVE-2023-39137"));
        assertThat(messages).anyMatch(m -> m.startsWith("archive 3.3.7") && m.contains("CVE-2023-39139"));
        assertThat(messages).anyMatch(m -> m.startsWith("jose 0.3.4") && m.endsWith("(dev dependency)"));
        // dio 5.4.0 is past the fix; the git package is not a pub.dev release
        assertThat(messages).noneMatch(m -> m.startsWith("dio") || m.startsWith("http_forked"));
    }

    @Test
    public void fallsBackToProjectWhenPubspecIsNotIndexed() throws Exception {
        File base = tmp.newFolder();
        Files.writeString(new File(base, "pubspec.lock").toPath(), LOCK);
        SensorContextTester ctx = SensorContextTester.create(base.toPath());
        ctx.setActiveRules(new ActiveRulesBuilder().addRule(new NewActiveRule.Builder()
                .setRuleKey(RuleKey.of(SecurityRulesDefinition.REPOSITORY_KEY, SecurityRules.VULNERABLE_DEPENDENCY)).build()).build());

        new DartDependencySensor().execute(ctx);

        assertThat(ctx.allIssues()).hasSize(4);
    }

    @Test
    public void silentWhenRuleInactive() throws Exception {
        SensorContextTester ctx = context(false);
        new DartDependencySensor().execute(ctx);
        assertThat(ctx.allIssues()).isEmpty();
    }

    @Test
    public void snapshotLoads() throws Exception {
        assertThat(DartDependencySensor.loadAdvisories()).hasSizeGreaterThanOrEqualTo(10)
                .allSatisfy(a -> assertThat(a.pkg()).isNotBlank());
    }
}
