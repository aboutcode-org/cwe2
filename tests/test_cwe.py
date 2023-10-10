#
# Copyright (c) Julian-Nash, Ziad Hany, nexB. Inc. and others. All rights reserved.
# SPDX-License-Identifier: MIT
# See https://github.com/nexB/cwe2/blob/main/mit.LICENSE for the license text.
# See https://github.com/nexB/cwe2 for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
from unittest import TestCase

from cwe2.database import Database
from cwe2.database import InvalidCWEError


class TestDatabase(TestCase):
    def setUp(self):
        self.db = Database()

    def test_cwe_get(self):
        cwe1 = self.db.get(15)
        assert cwe1.cwe_id == "15"
        assert cwe1.name == "External Control of System or Configuration Setting"
        assert cwe1.weakness_abstraction == "Base"
        assert cwe1.status == "Incomplete"
        assert (
            cwe1.description
            == "One or more system settings or configuration elements can be externally controlled"
            " by a user."
        )
        assert (
            cwe1.extended_description
            == "Allowing external control of system settings can disrupt service "
            "or cause an application to behave in unexpected, and potentially "
            "malicious ways."
        )

        assert (
            cwe1.related_weaknesses == "::NATURE:ChildOf:CWE ID:642:VIEW "
            "ID:1000:ORDINAL:Primary::NATURE:ChildOf:CWE ID:610:VIEW "
            "ID:1000::NATURE:ChildOf:CWE ID:20:VIEW ID:700:ORDINAL:Primary::"
        )

        assert cwe1.related_attack_patterns == "::13::146::176::203::270::271::69::76::77::"

        assert (
            cwe1.potential_mitigations == "::PHASE:Architecture and Design:STRATEGY:Separation of "
            "Privilege:DESCRIPTION:Compartmentalize the system to have safe "
            "areas where trust boundaries can be unambiguously drawn. Do not "
            "allow sensitive data to go outside of the trust boundary and "
            "always be careful when interfacing with a compartment outside of "
            "the safe area. Ensure that appropriate compartmentalization is "
            "built into the system design, and the compartmentalization "
            "allows for and reinforces privilege separation functionality. "
            "Architects and designers should rely on the principle of least "
            "privilege to decide the appropriate time to use privileges and "
            "the time to drop privileges.::PHASE:Implementation Architecture "
            "and Design:DESCRIPTION:Because setting manipulation covers a "
            "diverse set of functions, any attempt at illustrating it will "
            "inevitably be incomplete. Rather than searching for a tight-knit "
            "relationship between the functions addressed in the setting "
            "manipulation category, take a step back and consider the sorts "
            "of system values that an attacker should not be allowed to "
            "control.::PHASE:Implementation Architecture and "
            "Design:DESCRIPTION:In general, do not allow user-provided or "
            "otherwise untrusted data to control sensitive values. The "
            "leverage that an attacker gains by controlling these values is "
            "not always immediately obvious, but do not underestimate the "
            "creativity of the attacker.::"
        )

        assert (
            cwe1.taxonomy_mappings == "::TAXONOMY NAME:7 Pernicious Kingdoms:ENTRY NAME:Setting "
            "Manipulation::TAXONOMY NAME:Software Fault Patterns:ENTRY "
            "ID:SFP25:ENTRY NAME:Tainted input to variable::"
        )

        cwe2 = self.db.get(264)
        assert cwe2.cwe_id == "264"
        assert cwe2.name == "Permissions, Privileges, and Access Controls"
        assert cwe2.status == "Obsolete"

        cwe3 = self.db.get("3")
        assert cwe3.cwe_id == "3"
        assert cwe3.name == "DEPRECATED: Technology-specific Environment Issues"
        assert cwe3.status == "Deprecated"

        cwe4 = self.db.get("1008")
        assert cwe4.cwe_id == "1008"
        assert cwe4.name == "Architectural Concepts"
        assert cwe4.status == "Incomplete"

    def test_cwe_error(self):
        with self.assertRaises(InvalidCWEError) as e:
            self.db.get(1000000)
        self.assertEqual(str(e.exception), "Invalid CWE ID 1000000")

    def test_is_top_25_cwe(self):
        assert self.db.is_cwe_top_25(20)
        assert self.db.is_cwe_top_25("20")
        assert not self.db.is_cwe_top_25(0)
        assert not self.db.is_cwe_top_25("0")

    def test_is_owasp_top_ten_2021(self):
        assert self.db.is_owasp_top_ten_2021(11)
        assert self.db.is_owasp_top_ten_2021("11")
        assert not self.db.is_owasp_top_ten_2021(0)
        assert not self.db.is_owasp_top_ten_2021("0")

    def test_get_top_25_cwe(self):
        assert len(self.db.get_top_25_cwe()) == 25

    def test_get_owasp_top_ten_2021(self):
        assert len(self.db.get_owasp_top_ten_2021()) == 182

    def test_get_weaknesses_used_by_nvd(self):
        assert len(self.db.get_weaknesses_used_by_nvd()) == 13

    def test_is_weaknesses_used_by_nvd(self):
        assert self.db.is_weaknesses_used_by_nvd(352)

    def test_get_by_tag(self):
        assert self.db.get_by_tag(399) == [
            "399",
            "Resource Management Errors",
            None,
            "Draft",
            "Weaknesses in this category are related to improper management of system resources.",
        ]

        assert self.db.get_by_tag(399) == [
            "399",
            "Resource Management Errors",
            None,
            "Draft",
            "Weaknesses in this category are related to improper management of system resources.",
        ]
