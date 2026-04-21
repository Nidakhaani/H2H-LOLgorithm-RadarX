"""
Security Scorecard Module
Grades devices A-F and generates remediation plans.
"""

from collections import Counter


class SecurityScorecard:
    """Class to compute security scores for discovered devices."""

    REMEDIATION_MAP = {
        "telnet_open": "URGENT: Log into device admin panel → Disable Telnet → Enable SSH instead",
        "ftp_open": "Disable FTP service. Use SFTP (port 22) for any file transfer needs",
        "default_creds": "URGENT: Change the default admin password immediately. Use 12+ characters",
        "http_no_https": "Enable HTTPS in device admin settings. If unavailable, isolate to an IoT VLAN",
        "rtsp_camera": "Enable RTSP over TLS in camera settings, or restrict access to trusted IPs only",
        "upnp_enabled": "Disable UPnP in device settings to stop it from auto-opening firewall ports",
        "unknown_device": "Identify this device — if unrecognized, isolate it from the main network immediately",
        "mqtt_open": "Enable TLS on MQTT broker, or restrict port 1883 to localhost only",
    }

    THREAT_KEYWORDS = {
        "Telnet port 23 is open": "telnet_open",
        "FTP port 21 is open": "ftp_open",
        "Unknown device with Telnet": "default_creds",
        "Web interface is HTTP-only": "http_no_https",
        "Camera RTSP stream is unencrypted": "rtsp_camera",
        "UPnP is enabled": "upnp_enabled",
        "Manufacturer is unidentified": "unknown_device",
        "MQTT is running without TLS": "mqtt_open",
        "SMB port 445 is open": "smb_open",
    }

    def grade_device(self, device: dict) -> dict:
        """Grades one device with score, letter, findings, and remediation plan."""
        scored_device = dict(device)
        score, findings = self._calculate_risk_score(scored_device)
        grade = self._score_to_grade(score)
        label = self._score_to_label(score)
        remediation = self._generate_remediation(scored_device, findings)

        scored_device["risk_score"] = score
        scored_device["score"] = score
        scored_device["grade"] = grade
        scored_device["grade_label"] = label
        scored_device["risk_findings"] = findings
        scored_device["remediation_plan"] = remediation
        return scored_device

    def grade_all(self, devices: list[dict]) -> list[dict]:
        """Grades all discovered devices."""
        return [self.grade_device(device) for device in devices]

    def _calculate_risk_score(self, device: dict) -> tuple[int, list]:
        score = 0
        findings = []
        ports = device.get("open_ports", {})
        mfr = device.get("manufacturer", "").lower()

        # CRITICAL penalties
        if 23 in ports:
            score += 40
            findings.append(
                {
                    "level": "CRITICAL",
                    "msg": "Telnet port 23 is open — passwords are sent in plaintext",
                }
            )
        if 21 in ports:
            score += 30
            findings.append(
                {
                    "level": "HIGH",
                    "msg": "FTP port 21 is open — file transfers are completely unencrypted",
                }
            )
        if mfr in ["unknown", ""] and 23 in ports:
            score += 15
            findings.append(
                {
                    "level": "CRITICAL",
                    "msg": "Unknown device with Telnet = highly likely default credentials",
                }
            )

        # HIGH penalties
        if 80 in ports and 443 not in ports:
            score += 25
            findings.append(
                {
                    "level": "HIGH",
                    "msg": "Web interface is HTTP-only — all traffic including passwords is unencrypted",
                }
            )

        # MEDIUM penalties
        if 554 in ports:
            score += 15
            findings.append(
                {
                    "level": "MEDIUM",
                    "msg": "Camera RTSP stream is unencrypted — anyone on this LAN can view it",
                }
            )
        if 1900 in ports:
            score += 10
            findings.append(
                {
                    "level": "MEDIUM",
                    "msg": "UPnP is enabled — device may automatically open firewall ports",
                }
            )
        if 1883 in ports:
            score += 10
            findings.append(
                {
                    "level": "MEDIUM",
                    "msg": "MQTT is running without TLS — IoT device commands are unencrypted",
                }
            )
        if 445 in ports:
            score += 10
            findings.append(
                {
                    "level": "MEDIUM",
                    "msg": "SMB port 445 is open — potential file share exposure",
                }
            )
        if mfr in ["unknown", ""]:
            score += 10
            findings.append(
                {
                    "level": "MEDIUM",
                    "msg": "Manufacturer is unidentified — firmware trustworthiness cannot be verified",
                }
            )

        if score == 0:
            findings.append({"level": "INFO", "msg": "No obvious risks detected on this device"})

        return min(score, 100), findings

    def _score_to_grade(self, score: int) -> str:
        if score <= 15:
            return "A"
        if score <= 30:
            return "B"
        if score <= 50:
            return "C"
        if score <= 70:
            return "D"
        return "F"

    def _score_to_label(self, score: int) -> str:
        if score <= 15:
            return "SECURE"
        if score <= 30:
            return "LOW RISK"
        if score <= 50:
            return "MODERATE"
        if score <= 70:
            return "HIGH RISK"
        return "CRITICAL"

    def _generate_remediation(self, device: dict, findings: list) -> list[str]:
        del device
        ordered_levels = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3}
        sorted_findings = sorted(findings, key=lambda finding: ordered_levels.get(finding.get("level"), 99))

        actions = []
        for finding in sorted_findings:
            message = finding.get("msg", "")

            if "Telnet port 23 is open" in message:
                actions.append(self.REMEDIATION_MAP["telnet_open"])
            if "FTP port 21 is open" in message:
                actions.append(self.REMEDIATION_MAP["ftp_open"])
            if "Unknown device with Telnet" in message:
                actions.append(self.REMEDIATION_MAP["default_creds"])
            if "Web interface is HTTP-only" in message:
                actions.append(self.REMEDIATION_MAP["http_no_https"])
            if "Camera RTSP stream is unencrypted" in message:
                actions.append(self.REMEDIATION_MAP["rtsp_camera"])
            if "UPnP is enabled" in message:
                actions.append(self.REMEDIATION_MAP["upnp_enabled"])
            if "Manufacturer is unidentified" in message:
                actions.append(self.REMEDIATION_MAP["unknown_device"])
            if "MQTT is running without TLS" in message:
                actions.append(self.REMEDIATION_MAP["mqtt_open"])

        if not actions:
            return ["No immediate action required. Continue routine monitoring and firmware updates."]

        deduped_actions = []
        seen = set()
        for action in actions:
            if action not in seen:
                deduped_actions.append(action)
                seen.add(action)
        return deduped_actions

    def network_summary(self, devices: list[dict]) -> dict:
        grade_distribution = {"A": 0, "B": 0, "C": 0, "D": 0, "F": 0}
        devices_needing_action = []
        threat_counter = Counter()
        worst_grade = "A"
        grade_rank = {"A": 0, "B": 1, "C": 2, "D": 3, "F": 4}

        for device in devices:
            grade = device.get("grade", "A")
            if grade in grade_distribution:
                grade_distribution[grade] += 1
            if grade in {"D", "F"}:
                devices_needing_action.append(device.get("ip", "Unknown"))

            if grade_rank.get(grade, 0) > grade_rank[worst_grade]:
                worst_grade = grade

            for finding in device.get("risk_findings", []):
                message = finding.get("msg", "")
                for marker, threat_key in self.THREAT_KEYWORDS.items():
                    if marker in message:
                        threat_counter[threat_key] += 1
                        break

        top_threats = [name for name, _count in threat_counter.most_common(3)]

        return {
            "total_devices": len(devices),
            "grade_distribution": grade_distribution,
            "critical_count": grade_distribution["F"],
            "high_risk_count": grade_distribution["D"],
            "network_grade": worst_grade,
            "top_threats": top_threats,
            "devices_needing_action": devices_needing_action,
        }
