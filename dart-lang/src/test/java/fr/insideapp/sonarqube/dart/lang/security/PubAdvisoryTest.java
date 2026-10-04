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
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

public class PubAdvisoryTest {

    private final PubAdvisory http = new PubAdvisory("GHSA-4rgh-jx4f-qfcq", List.of("CVE-2020-35669"), "http header injection",
            "MAJOR", "http", List.of(Map.of("introduced", "0", "fixed", "0.13.3")), List.of());

    @Test
    public void fixedBoundaryIsExclusive() {
        assertThat(http.affects("0.12.2")).isTrue();
        assertThat(http.affects("0.13.2")).isTrue();
        assertThat(http.affects("0.13.3")).isFalse();
        assertThat(http.affects("1.2.0")).isFalse();
        assertThat(http.fixedIn("0.13.0")).isEqualTo("0.13.3");
        assertThat(http.displayId()).isEqualTo("CVE-2020-35669");
    }

    @Test
    public void preReleaseAndBuildMetadata() {
        PubAdvisory agent = new PubAdvisory("GHSA-fmj7-7gfw-64pg", List.of(), "x", "CRITICAL", "agent_dart",
                List.of(Map.of("introduced", "0", "fixed", "1.0.0-dev.29")), List.of());
        assertThat(agent.affects("1.0.0-dev.28")).isTrue();
        assertThat(agent.affects("1.0.0-dev.29")).isFalse();
        assertThat(agent.affects("1.0.0+3")).isFalse();
        assertThat(agent.displayId()).isEqualTo("GHSA-fmj7-7gfw-64pg");
    }

    @Test
    public void introducedLowerBoundAndLastAffected() {
        PubAdvisory a = new PubAdvisory("X", List.of(), "x", "MAJOR", "p",
                List.of(Map.of("introduced", "2.3.3", "last_affected", "2.4.0")), List.of());
        assertThat(a.affects("2.3.2")).isFalse();
        assertThat(a.affects("2.3.3")).isTrue();
        assertThat(a.affects("2.4.0")).isTrue();
        assertThat(a.affects("2.4.1")).isFalse();
    }

    @Test
    public void unparseableVersionNeverMatchesRanges() {
        assertThat(http.affects("not-a-version")).isFalse();
    }
}
