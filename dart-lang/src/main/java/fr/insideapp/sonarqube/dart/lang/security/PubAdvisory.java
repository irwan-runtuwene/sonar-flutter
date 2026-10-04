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

import com.fasterxml.jackson.annotation.JsonProperty;
import com.vdurmont.semver4j.Semver;

import java.util.List;
import java.util.Map;

/** One OSV advisory for one pub package; see scripts/update_pub_advisories.py. */
public record PubAdvisory(String id, List<String> aliases, String summary, String severity,
                          @JsonProperty("package") String pkg,
                          List<Map<String, String>> ranges, List<String> versions) {

    /** The advisory id people recognise: the CVE when there is one, else the GHSA. */
    public String displayId() {
        return aliases == null ? id : aliases.stream().filter(a -> a.startsWith("CVE-")).findFirst().orElse(id);
    }

    public boolean affects(String version) {
        if (versions != null && versions.contains(version)) {
            return true;
        }
        for (Map<String, String> range : ranges == null ? List.<Map<String, String>>of() : ranges) {
            if (inRange(range, version)) {
                return true;
            }
        }
        return false;
    }

    /** First fixed version of the range that contains {@code version}, or null. */
    public String fixedIn(String version) {
        return ranges == null ? null : ranges.stream().filter(r -> inRange(r, version)).map(r -> r.get("fixed"))
                .filter(f -> f != null).findFirst().orElse(null);
    }

    private static boolean inRange(Map<String, String> range, String version) {
        try {
            Semver v = semver(version);
            String introduced = range.getOrDefault("introduced", "0");
            if (v.isLowerThan(semver(introduced))) {
                return false;
            }
            if (range.containsKey("fixed")) {
                return v.isLowerThan(semver(range.get("fixed")));
            }
            if (range.containsKey("last_affected")) {
                return !v.isGreaterThan(semver(range.get("last_affected")));
            }
            return true;
        } catch (RuntimeException e) {
            return false; // unparseable version: only the explicit versions list can match
        }
    }

    private static Semver semver(String version) {
        return new Semver(version.replaceFirst("\\+.*$", ""), Semver.SemverType.LOOSE);
    }
}
