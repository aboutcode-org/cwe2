Changelog
=========

v3.0.0
------

- Add cwec_v4.9.xml file to the database
- Add support for the cwe category ( add a get_by_tag function to parse xml database if the cwe is not found in csv files)
- Reorganize and Add all missing csv files
- Add ( is_in_category and get_by_category ) functions and make the code more reusable
- Add some extra functions ( get_weaknesses_used_by_nvd , is_weaknesses_used_by_nvd )
- Update requirements.


v2.0.0
------

Initial release as a fork of https://github.com/Julian-Nash/cwe
Adopt and merge skeleton from  https://github.com/nexB/skeleton

