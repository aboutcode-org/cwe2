#
# Copyright (c) Julian-Nash, Ziad Hany, nexB. Inc. and others. All rights reserved.
# SPDX-License-Identifier: MIT
# See https://github.com/nexB/cwe2/blob/main/mit.LICENSE for the license text.
# See https://github.com/nexB/cwe2 for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import enum


@enum.unique
class CWECategory(enum.Enum):
    HARDWARE_DESIGN: str = "hardware_design"
    RESEARCH_CONCEPTS: str = "research_concepts"
    SOFTWARE_DEVELOPMENT: str = "software_development"
