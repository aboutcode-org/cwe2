#
# Copyright (c) Julian-Nash, Ziad Hany, nexB. Inc. and others. All rights reserved.
# SPDX-License-Identifier: MIT
# See https://github.com/nexB/cwe2/blob/main/mit.LICENSE for the license text.
# See https://github.com/nexB/cwe2 for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import csv
import xml.etree.ElementTree as ET
from typing import List
from typing import Union

from cwe2.mappings import external_mapping
from cwe2.mappings import helpful_view
from cwe2.mappings import navigate_cwe
from cwe2.mappings import obsolete_views
from cwe2.mappings import xml_database_path
from cwe2.weakness import Weakness


def is_in_category(path, cwe_id):
    with open(path, encoding="utf-8") as f:
        f.seek(0)
        reader = csv.DictReader(f)
        for row in reader:
            if row.get("CWE-ID") == str(cwe_id):
                return True
        return False


def get_by_category(path):
    with open(path, encoding="utf-8") as f:
        f.seek(0)
        weakness_list = []
        reader = csv.DictReader(f)
        for row in reader:
            weakness_list.append(Weakness(*list(row.values())[0:-1]))
        return weakness_list


class InvalidCWEError(Exception):
    def __init__(self, cwe_id):
        self.message = f"Invalid CWE ID {cwe_id}"

    def __str__(self):
        return self.message


class Database:
    database_paths = (
        [navigate_cwe.get(key).get("csv_file") for key in navigate_cwe.keys()]
        + [external_mapping.get(key).get("csv_file") for key in external_mapping.keys()]
        + [helpful_view.get(key).get("csv_file") for key in helpful_view.keys()]
        + [obsolete_views.get(key).get("csv_file") for key in obsolete_views.keys()]
    )

    cwe_files = {open(path, encoding="utf-8") for path in database_paths}

    def get(self, cwe_id: Union[int, str]) -> Weakness:
        """Returns a CWE Weakness object"""
        cwe_obj = None
        for cwe_category in self.cwe_files:
            cwe_category.seek(0)
            reader = csv.DictReader(cwe_category)
            for row in reader:
                if row.get("CWE-ID") == str(cwe_id):
                    cwe_obj = list(row.values())[0:-1]
                    break

        if not cwe_obj:
            cwe_obj = self.get_by_tag(cwe_id)

        if not cwe_obj:
            raise InvalidCWEError(cwe_id)

        return Weakness(*cwe_obj)

    def get_by_tag(self, cwe_id) -> List:
        """Returns a list of cwe_obj by parse xml database"""
        tree = ET.parse(xml_database_path)
        root = tree.getroot()
        for tag_num in [1, 2]:  # Categories , Views
            tag = root[tag_num]
            for child in tag:
                if child.attrib["ID"] == str(cwe_id):
                    return [
                        str(cwe_id),
                        child.attrib.get("Name"),
                        None,
                        child.attrib.get("Status"),
                        child[0].text,
                    ]

    def get_top_25_cwe(self) -> List[Weakness]:
        """Returns a list of all CWE Top 25 (2023) Weakness objects"""
        return get_by_category(external_mapping["cwe_top_25_2023"]["csv_file"])

    def get_owasp_top_ten_2021(self) -> List[Weakness]:
        """Returns a list of a Top OWASP Ten (2021) Weakness objects"""
        return get_by_category(external_mapping["owasp_top_ten_2021"]["csv_file"])

    def get_weaknesses_used_by_nvd(self) -> List[Weakness]:
        """Returns a list of Weaknesses objects Used by NVD"""
        return get_by_category(obsolete_views["weaknesses_used_by_nvd"]["csv_file"])

    def is_cwe_top_25(self, cwe_id: Union[int, str]) -> bool:
        """Returns True if Weakness object in a Top 25 CWE else False"""
        return is_in_category(external_mapping["cwe_top_25_2023"]["csv_file"], cwe_id)

    def is_owasp_top_ten_2021(self, cwe_id: Union[int, str]) -> bool:
        """Returns True if Weakness object in a Top OWASP Ten (2021) else False"""
        return is_in_category(external_mapping["owasp_top_ten_2021"]["csv_file"], cwe_id)

    def is_weaknesses_used_by_nvd(self, cwe_id: Union[int, str]) -> bool:
        """Returns True if Weakness object in a Weaknesses Used by NVD else False"""
        return is_in_category(obsolete_views["weaknesses_used_by_nvd"]["csv_file"], cwe_id)
