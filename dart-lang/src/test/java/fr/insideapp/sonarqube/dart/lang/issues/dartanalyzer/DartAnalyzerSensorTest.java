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
package fr.insideapp.sonarqube.dart.lang.issues.dartanalyzer;

import org.junit.Test;
import org.sonar.api.batch.fs.InputFile;
import org.sonar.api.batch.fs.internal.TestInputFileBuilder;
import org.sonar.api.batch.sensor.internal.SensorContextTester;
import org.sonar.api.batch.sensor.issue.Issue;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public class DartAnalyzerSensorTest {

    private static final String CODE = "import 'dart:io';\nvoid main() {}\n";

    @Test
    public void recordsKnownRuleAsIsAndUnknownCodeOnCatchAllRule() throws Exception {
        Path base = Paths.get("").toAbsolutePath();
        SensorContextTester ctx = SensorContextTester.create(base);
        ctx.fileSystem().add(new TestInputFileBuilder("p", base.toFile(), base.resolve("lib/m.dart").toFile())
                .setLanguage("dart").setType(InputFile.Type.MAIN).setContents(CODE).build());

        List<DartAnalyzerReportIssue> reported = Arrays.asList(
                new DartAnalyzerReportIssue("unused_import", "Unused import: 'dart:io'.", base.resolve("lib/m.dart").toString(), 1, 8, 9),
                new DartAnalyzerReportIssue("avoid_print", "Don't invoke 'print'.", base.resolve("lib/m.dart").toString(), 2, 1, 4));

        new DartAnalyzerSensor().recordIssues(ctx, reported);

        List<Issue> issues = Arrays.asList(ctx.allIssues().toArray(new Issue[0]));
        assertThat(issues).hasSize(2);
        assertThat(issues.get(0).ruleKey().rule()).isEqualTo("dart_diagnostic");
        assertThat(issues.get(0).primaryLocation().message()).isEqualTo("[unused_import] Unused import: 'dart:io'.");
        assertThat(issues.get(1).ruleKey().rule()).isEqualTo("avoid_print");
    }
}
