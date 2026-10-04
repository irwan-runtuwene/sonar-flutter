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
package fr.insideapp.sonarqube.flutter.tests;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.sonar.api.batch.fs.internal.TestInputFileBuilder;
import org.sonar.api.batch.sensor.internal.SensorContextTester;
import org.sonar.api.measures.CoreMetrics;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.assertj.core.api.Assertions.assertThat;

public class FlutterTestSensorTest {

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    /**
     * Runner 1.32 (Flutter 3.44) reports suite paths relative to the project root,
     * not absolute as older runners did.
     */
    @Test
    public void relativeSuitePathIsResolved() throws Exception {
        File base = tmp.newFolder();
        Path report = Paths.get("src/test/resources/tests/dart-test-1.32.output").toAbsolutePath();
        SensorContextTester ctx = SensorContextTester.create(base.toPath());
        ctx.settings().setProperty(FlutterTestSensor.REPORT_PATH_KEY, report.toString());
        ctx.fileSystem().add(new TestInputFileBuilder("p", "test/a_test.dart").setLanguage("dart").setType(org.sonar.api.batch.fs.InputFile.Type.TEST).build());

        new FlutterTestSensor().execute(ctx);

        String key = "p:test/a_test.dart";
        assertThat(ctx.measure(key, CoreMetrics.TESTS).value()).isEqualTo(2);
        assertThat(ctx.measure(key, CoreMetrics.SKIPPED_TESTS).value()).isEqualTo(1);
        assertThat(ctx.measure(key, CoreMetrics.TEST_FAILURES).value()).isEqualTo(1);
    }
}
