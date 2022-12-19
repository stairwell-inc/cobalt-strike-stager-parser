# cobalt-strike-stager-parser
Python parser for Cobalt Strike stagers

## Description
Use `parse_stager_config.py` to search a file for Cobalt Strike stager shellcode. If shellcode is found, it will be extracted in JSON format.

## Usage

``` shell
usage: parse_stager_config.py [-h] file

Parses CobaltStrike Stager Shellcode.

positional arguments:
  file        File path to stager shellcode

optional arguments:
  -h, --help  show this help message and exit
```
