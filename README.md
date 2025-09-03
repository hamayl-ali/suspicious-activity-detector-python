# Suspicious file detector

This small project is only to find any suspicious processes, files, connections, and to clear the concept of usage

of ***psutil*** . It generates a JSON report summarizing the results.

# Features

Process scanning: Detects processes with suspicious names like keylogger, logger, monitor, and spy.

File scanning: Searches your home and temporary directories for files with keywords like log, record, key, and keys.

Network scanning: Lists established network connections along with the local and remote IPs and the process IDs.

JSON report: Generates a detector_report.json file containing all flagged items and their timestamps.

# Installations

Make sure you have python3 and psutil library 

# IMPO. Note

Keywords for processes and files are currently hardcoded in the script.

This is a student project for learning purposes and may not detect all threats.
