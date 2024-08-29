#
# Copyright (c) Julian-Nash, Ziad Hany, nexB. Inc. and others. All rights reserved.
# SPDX-License-Identifier: MIT
# See https://github.com/aboutcode-org/cwe2/blob/main/mit.LICENSE for the license text.
# See https://github.com/aboutcode-org/cwe2 for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
import os

import importlib_resources


def get_data_file_path(package: str, resource: str) -> str:
    """
    Returns the filesystem path of a resource marked as package
    data of a Python package installed.

    :param package: string of the Python package the resource is
                    located in, e.g. "mypackage.module"
    :param resource: string of the filename of the resource (do not
                     include directory names), e.g. "myfile.png"
    :return: string of the full (absolute) filesystem path to the
             resource if it exists.
    :raises ModuleNotFoundError: In case the package `package` is not found.
    :raises FileNotFoundError: In case the file in `resource` is not
                               found in the package.
    """
    # Guard against non-existing files, or else importlib_resources.path
    # may raise a confusing TypeError.
    if not importlib_resources.is_resource(package, resource):
        raise FileNotFoundError(f"Python package '{package}' resource '{resource}' not found.")

    with importlib_resources.path(package, resource) as resource_path:
        return os.fspath(resource_path)


navigate_cwe: dict = {
    "software_development": {
        "csv_url": "https://cwe.mitre.org/data/csv/699.csv.zip",
        "csv_file": get_data_file_path("cwe2.database_v49.navigate_cwe", "699.csv"),
    },
    "hardware_design": {
        "csv_url": "https://cwe.mitre.org/data/csv/1194.csv.zip",
        "csv_file": get_data_file_path("cwe2.database_v49.navigate_cwe", "1194.csv"),
    },
    "research_concepts": {
        "csv_url": "https://cwe.mitre.org/data/csv/1000.csv.zip",
        "csv_file": get_data_file_path("cwe2.database_v49.navigate_cwe", "1000.csv"),
    },
}

external_mapping: dict = {
    "cwe_top_25_2023": {
        "csv_url": "https://cwe.mitre.org/data/csv/1425.csv.zip",
        "csv_file": get_data_file_path("cwe2.database_v49.external_mappings", "1425.csv"),
    },
    "most_important_hardware_weaknesses_2021": {
        "csv_url": "https://cwe.mitre.org/data/csv/1343.csv.zip",
        "csv_file": get_data_file_path("cwe2.database_v49.external_mappings", "1343.csv"),
    },
    "owasp_top_ten_2021": {
        "csv_url": "https://cwe.mitre.org/data/csv/1344.csv.zip",
        "csv_file": get_data_file_path("cwe2.database_v49.external_mappings", "1344.csv"),
    },
    "seven_pernicious_kingdoms": {
        "csv_url": "https://cwe.mitre.org/data/csv/700.csv.zip",
        "csv_file": get_data_file_path("cwe2.database_v49.external_mappings", "700.csv"),
    },
    "software_fault_pattern_clusters": {
        "csv_url": "https://cwe.mitre.org/data/csv/888.csv.zip",
        "csv_file": get_data_file_path("cwe2.database_v49.external_mappings", "888.csv"),
    },
    "sei_cert_oracle_coding_standard_for_java": {
        "csv_url": "https://cwe.mitre.org/data/csv/1133.csv.zip",
        "csv_file": get_data_file_path("cwe2.database_v49.external_mappings", "1133.csv"),
    },
    "sei_cert_c_coding_standard": {
        "csv_url": "https://cwe.mitre.org/data/csv/1154.csv.zip",
        "csv_file": get_data_file_path("cwe2.database_v49.external_mappings", "1154.csv"),
    },
    "sei_cert_perl_coding_standard": {
        "csv_url": "https://cwe.mitre.org/data/csv/1178.csv.zip",
        "csv_file": get_data_file_path("cwe2.database_v49.external_mappings", "1178.csv"),
    },
    "addressed_by_ISA/IEC_62443_requirements": {
        "csv_url": "https://cwe.mitre.org/data/csv/1424.csv.zip",
        "csv_file": get_data_file_path("cwe2.database_v49.external_mappings", "1424.csv"),
    },
    "cisq_quality_measures_2020": {
        "csv_url": "https://cwe.mitre.org/data/csv/1305.csv.zip",
        "csv_file": get_data_file_path("cwe2.database_v49.external_mappings", "1305.csv"),
    },
    "cisq_data_protection_measures": {
        "csv_url": "https://cwe.mitre.org/data/csv/1340.csv.zip",
        "csv_file": get_data_file_path("cwe2.database_v49.external_mappings", "1340.csv"),
    },
    "sei_etf_security_vulnerabilities_in ICS": {
        "csv_url": "https://cwe.mitre.org/data/csv/1358.csv.zip",
        "csv_file": get_data_file_path("cwe2.database_v49.external_mappings", "1358.csv"),
    },
    "architectural_concepts": {
        "csv_url": "https://cwe.mitre.org/data/csv/1008.csv.zip",
        "csv_file": get_data_file_path("cwe2.database_v49.external_mappings", "1008.csv"),
    },
}

helpful_view: dict = {
    "introduced_during_design": {
        "csv_url": "https://cwe.mitre.org/data/csv/701.csv.zip",
        "csv_file": get_data_file_path("cwe2.database_v49.helpful_views", "701.csv"),
    },
    "introduced_during_implementation": {
        "csv_url": "https://cwe.mitre.org/data/csv/702.csv.zip",
        "csv_file": get_data_file_path("cwe2.database_v49.helpful_views", "702.csv"),
    },
    "software_assurance_trends_categorization": {
        "csv_url": "https://cwe.mitre.org/data/csv/1400.csv.zip",
        "csv_file": get_data_file_path("cwe2.database_v49.helpful_views", "1400.csv"),
    },
    "quality_weaknesses_with_indirect_security_impacts": {
        "csv_url": "https://cwe.mitre.org/data/csv/1040.csv.zip",
        "csv_file": get_data_file_path("cwe2.database_v49.helpful_views", "1040.csv"),
    },
    "software_written_in_c": {
        "csv_url": "https://cwe.mitre.org/data/csv/658.csv.zip",
        "csv_file": get_data_file_path("cwe2.database_v49.helpful_views", "658.csv"),
    },
    "software_written_in_c++": {
        "csv_url": "https://cwe.mitre.org/data/csv/659.csv.zip",
        "csv_file": get_data_file_path("cwe2.database_v49.helpful_views", "659.csv"),
    },
    "software_written_in_java": {
        "csv_url": "https://cwe.mitre.org/data/csv/660.csv.zip",
        "csv_file": get_data_file_path("cwe2.database_v49.helpful_views", "660.csv"),
    },
    "software_written_in_php": {
        "csv_url": "https://cwe.mitre.org/data/csv/661.csv.zip",
        "csv_file": get_data_file_path("cwe2.database_v49.helpful_views", "661.csv"),
    },
    "weaknesses_in_mobile_applications": {
        "csv_url": "https://cwe.mitre.org/data/csv/919.csv.zip",
        "csv_file": get_data_file_path("cwe2.database_v49.helpful_views", "919.csv"),
    },
    "cwe_composites": {
        "csv_url": "https://cwe.mitre.org/data/csv/678.csv.zip",
        "csv_file": get_data_file_path("cwe2.database_v49.helpful_views", "678.csv"),
    },
    "cwe_named_chains": {
        "csv_url": "https://cwe.mitre.org/data/csv/709.csv.zip",
        "csv_file": get_data_file_path("cwe2.database_v49.helpful_views", "709.csv"),
    },
    "cwe_cross_section": {
        "csv_url": "https://cwe.mitre.org/data/csv/884.csv.zip",
        "csv_file": get_data_file_path("cwe2.database_v49.helpful_views", "884.csv"),
    },
    "cwe_simplified_mapping": {
        "csv_url": "https://cwe.mitre.org/data/csv/1003.csv.zip",
        "csv_file": get_data_file_path("cwe2.database_v49.helpful_views", "1003.csv"),
    },
    "cwe_entries_with_maintenance_notes": {
        "csv_url": "https://cwe.mitre.org/data/csv/1081.csv.zip",
        "csv_file": get_data_file_path("cwe2.database_v49.helpful_views", "1081.csv"),
    },
    "cwe_deprecated_entries": {
        "csv_url": "https://cwe.mitre.org/data/csv/604.csv.zip",
        "csv_file": get_data_file_path("cwe2.database_v49.helpful_views", "604.csv"),
    },
    "cwe_comprehensive_view": {
        "csv_url": "https://cwe.mitre.org/data/csv/2000.csv.zip",
        "csv_file": get_data_file_path("cwe2.database_v49.helpful_views", "2000.csv"),
    },
    "weakness_base_elements": {
        "csv_url": "https://cwe.mitre.org/data/csv/677.csv.zip",
        "csv_file": get_data_file_path("cwe2.database_v49.helpful_views", "677.csv"),
    },
}

obsolete_views: dict = {
    "cwe_top_25_2022": {
        "csv_url": "https://cwe.mitre.org/data/csv/1387.csv.zip",
        "csv_file": get_data_file_path("cwe2.database_v49.obsolete_views", "1387.csv"),
    },
    "cwe_top_25_2021": {
        "csv_url": "https://cwe.mitre.org/data/csv/1337.csv.zip",
        "csv_file": get_data_file_path("cwe2.database_v49.obsolete_views", "1337.csv"),
    },
    "cwe_top_25_2020": {
        "csv_url": "https://cwe.mitre.org/data/csv/1350.csv.zip",
        "csv_file": get_data_file_path("cwe2.database_v49.obsolete_views", "1350.csv"),
    },
    "cwe_top_25_2019": {
        "csv_url": "https://cwe.mitre.org/data/csv/1200.csv.zip",
        "csv_file": get_data_file_path("cwe2.database_v49.obsolete_views", "1200.csv"),
    },
    "cwe/sans_top_25_2011": {
        "csv_url": "https://cwe.mitre.org/data/csv/900.csv.zip",
        "csv_file": get_data_file_path("cwe2.database_v49.obsolete_views", "900.csv"),
    },
    "cwe/sans_top_25_2010": {
        "csv_url": "https://cwe.mitre.org/data/csv/800.csv.zip",
        "csv_file": get_data_file_path("cwe2.database_v49.obsolete_views", "800.csv"),
    },
    "cwe/sans_top_25_2009": {
        "csv_url": "https://cwe.mitre.org/data/csv/750.csv.zip",
        "csv_file": get_data_file_path("cwe2.database_v49.obsolete_views", "750.csv"),
    },
    "weaknesses_used_by_nvd": {
        "csv_url": "https://cwe.mitre.org/data/csv/635.csv.zip",
        "csv_file": get_data_file_path("cwe2.database_v49.obsolete_views", "635.csv"),
    },
    "owasp_top_ten_2017": {
        "csv_url": "https://cwe.mitre.org/data/csv/1026.csv.zip",
        "csv_file": get_data_file_path("cwe2.database_v49.obsolete_views", "1026.csv"),
    },
    "owasp_top_ten_2013": {
        "csv_url": "https://cwe.mitre.org/data/csv/928.csv.zip",
        "csv_file": get_data_file_path("cwe2.database_v49.obsolete_views", "928.csv"),
    },
    "owasp_top_10_2010": {
        "csv_url": "https://cwe.mitre.org/data/csv/809.csv.zip",
        "csv_file": get_data_file_path("cwe2.database_v49.obsolete_views", "809.csv"),
    },
    "owasp_top_10_2007": {
        "csv_url": "https://cwe.mitre.org/data/csv/629.csv.zip",
        "csv_file": get_data_file_path("cwe2.database_v49.obsolete_views", "629.csv"),
    },
    "owasp_top_10_2004": {
        "csv_url": "https://cwe.mitre.org/data/csv/711.csv.zip",
        "csv_file": get_data_file_path("cwe2.database_v49.obsolete_views", "711.csv"),
    },
    "the_cert_c_secure_coding_standard_2008": {
        "csv_url": "https://cwe.mitre.org/data/csv/734.csv.zip",
        "csv_file": get_data_file_path("cwe2.database_v49.obsolete_views", "734.csv"),
    },
    "the_cert_oracle_secure_coding_standard_for_java_2011": {
        "csv_url": "https://cwe.mitre.org/data/csv/844.csv.zip",
        "csv_file": get_data_file_path("cwe2.database_v49.obsolete_views", "844.csv"),
    },
    "sei_cert_c++_coding_standard_2016": {
        "csv_url": "https://cwe.mitre.org/data/csv/868.csv.zip",
        "csv_file": get_data_file_path("cwe2.database_v49.obsolete_views", "868.csv"),
    },
    "cisq_quality_measures_2016": {
        "csv_url": "https://cwe.mitre.org/data/csv/1128.csv.zip",
        "csv_file": get_data_file_path("cwe2.database_v49.obsolete_views", "1128.csv"),
    },
}

xml_database_path = get_data_file_path("cwe2.database_v49", "cwec_v4.14.xml")
