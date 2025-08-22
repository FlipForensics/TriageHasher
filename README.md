
# TriageHasher
[![GPLv3 License](https://img.shields.io/badge/License-GPL%20v3-yellow.svg)](https://opensource.org/licenses/)

TriageHasher is a command-line tool for fast and flexible hashing of files on Windows, Linux and macOS.
It walks the paths you specify, filters by extension/size, computes one or more cryptographic hashes, and writes the results to a CSV file together with basic file-system metadata.

## Goal 
Incident responders often need a quick way to collect file hashes when the target or client environment lacks an EDR platform. During triage collection with tools such as KAPE, TriageHasher provides an easy-to-use, flexible hashing utility that:

- runs standalone (no installer, no external libraries)
- respects evidence integrity (no unwanted atime updates)
- produces investigator-friendly CSV output ready for correlation or deduplication
- Use it to verify binaries, script files, driver loads, or any artefact set you copy during first-hour response.

## Features
- Flexible and standalone 
- Choose which files to hash based on file size, file location and extension filters.
- Separate log levels for console and file.


## Quick start
```
bash
# clone & enter
git clone https://github.com/FlipForensics/TriageHasher.git
cd TriageHasher

Options: 
# run with the default config
python TriageHasher.py

# run the binary file with the default config
TriageHasher.exe

# run with custom config and output location
python TriageHasher.py -c config.ini -o C:\Output\


```
The script will:

Read config.ini for settings (hash list, chunk size, etc.).

Read locations.txt (path patterns) referenced from the config.

Write FileHashes_<computer>_<timestamp>.csv and a log file in the chosen output directory.

## Releases / Windows binaries
See the releases section for the latest release. This will contain a prebuild Windows .exe binary. 
You can also build it yourself by using pyinstaller
```
pyinstaller --onefile TriageHasher.py 
```

## Configuration
Everything lives in an INI file. A trimmed example:
```
; File containing glob search patterns:
;   - Provide a text file with one file/directory pattern per line
;   - Use wildcards (*) or (**) for pattern matching
;   - Example patterns:
;       C:\Windows\System32\**
;       C:\Users\**\AppData\**\*.exe
locations_file = locations.txt

; File extensions to process:
;   - Comma-separated list of extensions to include
extensions = .exe, .dll, .ps1, .vbs, .js, .bat, .jar

; Maximum file size to hash:
;   - Files larger than this will be skipped
max_file_size = 250MB

; CSV file delimiter:
;   - Character to separate columns in output CSV
csv_delimiter = ,

; Hash algorithms to compute:
;   - Comma-separated list of supported algorithms
;   - Supported: md5, sha1, sha224, sha256, sha384, sha512
hash_algorithms = md5, sha1

; Timestamp format specification:
time_format = %d-%m-%Y %H:%M:%S.%f

; Log file verbosity:
;   - 0 = No logging to file
;   - 1 = Errors only
;   - 2 = Errors + Warnings
;   - 3 = Errors + Warnings + Info (recommended)
;   - 4 = All messages (debug mode)
log_file_level = 4

; Console output verbosity:
log_console_level = 3

; Hashing chunk size:
chunk_size = 65536

```
## KAPE integration
This tool can be integrated with KAPE by using the attached module. Add a folder named 'TriageHasher' containing TriageHasher.exe, the config file and locations file to KAPE's bin folder ('\Modules\bin') and add the module file to the Module folder ('Modules\Apps\GitHub'). Now you can use TriageHasher in combination with KAPE. 

## Forensic notes
Windows: Since Vista the default NTFS behaviour is to defer atime updates, so normal reads leave metadata untouched.

Linux/macOS: The code tries O_NOATIME; if unavailable or if the kernel still updates atime, the original value is restored with os.utime().

Run with administrative or root privileges to access protected files.


## Contributing

Contributions are always welcome!

## Disclaimer
TriageHasher is provided “as is” with no warranty. Always validate output against your lab procedures before relying on it in a legal context.
