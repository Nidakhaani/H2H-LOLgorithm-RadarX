"""
Security Scorecard Module
Grades devices A-F and generates remediation plans.
"""

from collections import Counter


class SecurityScorecard:
    """Class to compute security scores for discovered devices."""

    # Thresholds for threat classification
    THREAT_MARKERS = {
        "Telnet": "telnet_open",
        "FTP": "ftp_open",
        "HTTP": "http_no_https",
        "RTSP": "rtsp_camera",
        "UPnP": "upnp_enabled",
        "Manufacturer": "unknown_device",
        "MQTT": "mqtt_open",
        "SMB": "smb_open",
        "RDP": "rdp_open",
    }

    def grade_device(self, device: dict) -> dict:
        """Grades one device with score, letter, findings, and remediation plan."""
        scored_device = dict(device)
        score, findings = self._calculate_risk_score(scored_device)
        grade = self._score_to_grade(score)
        label = self._score_to_label(score)
        remediation = self._generate_remediation(scored_device, score, findings)

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
        if 3389 in ports:
            score += 25
            findings.append(
                {
                    "level": "HIGH",
                    "msg": "RDP port 3389 is open — potential remote desktop hijacking risk",
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
        if 22 in ports:
            score += 5
            findings.append(
                {
                    "level": "MEDIUM",
                    "msg": "SSH port 22 is open — ensure strong keys are used",
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

    def _generate_remediation(self, device: dict, score: int, findings: list) -> list[str]:
        actions = []
        ports = device.get("open_ports", {})
        status = device.get("status", "").upper() or device.get("device_status", "").upper()
        # Fallback to manufacturer if status not explicitly set
        if not status and device.get("manufacturer", "").lower() in ["unknown", ""]:
            status = "UNKNOWN"

        # Port-specific remediations
        if 445 in ports:
            actions.append("SMB (445): Patch EternalBlue vulnerabilities or disable if service is unused")
        if 3389 in ports:
            actions.append("RDP (3389): Restrict RDP access to VPN only and enforce MFA")
        if 22 in ports:
            actions.append("SSH (22): Disable password authentication and use SSH keys for login")
        if 23 in ports:
            actions.append("Telnet (23): Disable Telnet service immediately; it is highly insecure")
        if 21 in ports:
            actions.append("FTP (21): Replace FTP with SFTP or HTTPS for secure file transfers")
        if 80 in ports or 8080 in ports:
            actions.append("HTTP (80/8080): Enforce HTTPS/TLS to encrypt web administration traffic")

        # Risk score logic
        if score >= 75:
            actions.append("Critical Risk: Isolate this device from the network and perform a deep forensic scan")
        elif score >= 40:
            actions.append("Moderate Risk: Apply latest security patches and conduct a configuration audit")
        else:
            actions.append("Low Risk: Continue routine monitoring and automated security audits")

        # Device status logic
        if status == "UNKNOWN":
            actions.append("Identity Check: Perform manual identity verification to confirm device ownership")

        # No critical issues fallback
        if not any(p in ports for p in [21, 23, 445, 3389]) and score < 40:
            if not actions or all("Low Risk" in a for a in actions):
                return ["No critical issues detected — continue routine monitoring"]

        # De-duplicate while preserving order
        deduped = []
        for a in actions:
            if a not in deduped:
                deduped.append(a)
        
        return deduped if deduped else ["No critical issues detected — continue routine monitoring"]

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
                for marker, threat_key in self.THREAT_MARKERS.items():
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
