#!/usr/bin/env python3
VERSION = "1.0.0"

"""
TriageHasher - DFIR File Hashing Tool
This script processes files from specified locations, computes hashes,
and outputs results in CSV format for forensic analysis.
"""

import os
import sys
import glob
import logging
import argparse
import hashlib
import csv
import configparser
from datetime import datetime, timezone
import socket
import time


# These will be set later. 
LOGGER = None


def format_runtime(seconds):
    """Format runtime into human-readable string"""
    # Convert seconds to integer for clean division
    total_seconds = int(seconds)
    
    # Calculate time components
    hours = total_seconds // 3600
    minutes = (total_seconds % 3600) // 60
    seconds_remainder = total_seconds % 60
    
    # Format based on duration
    if hours > 0:
        return f"{hours}h {minutes}m {seconds_remainder}s"
    elif minutes > 0:
        return f"{minutes}m {seconds_remainder}s"
    else:
        return f"{seconds_remainder}s"

def get_safe_computer_name():
    """Get sanitized computer name for use in filenames"""
    try:
        name = socket.gethostname()
        # Replace problematic characters
        return "".join(c if c.isalnum() or c in '_-' else '_' for c in name)
    except Exception:
        return "UnknownComputer"

def format_timestamp(timestamp, fmt):
    """
    Convert timestamp to UTC and format as string.
    :param timestamp: Floating-point seconds since epoch
    :param fmt: Format string for datetime
    :return: Formatted UTC timestamp string
    """
    # Convert to UTC datetime object
    dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
    
    # Format according to user specification
    return dt.strftime(fmt)

def parse_size(size_str):
    """
    Convert human-readable size string to bytes.
    Supports units: B, KB, MB, GB, TB (case-insensitive)
    Example: '100MB' -> 104857600
    """
    size_str = size_str.upper().strip()
    
    # If input is digit-only, return as bytes
    if size_str.isdigit():
        return int(size_str)
    
    # Define unit multipliers in descending order of length
    units = [
        ('TB', 1024**4),
        ('GB', 1024**3),
        ('MB', 1024**2),
        ('KB', 1024),
        ('B', 1)
    ]
    
    # Find matching unit (check longest units first)
    for unit, multiplier in units:
        if size_str.endswith(unit):
            num_part = size_str[:-len(unit)].strip()
            try:
                return int(float(num_part) * multiplier)
            except ValueError:
                raise ValueError(f"Invalid numeric format: '{num_part}'")
    
    # Try to parse without explicit unit (assume bytes)
    try:
        return int(size_str)
    except ValueError:
        raise ValueError(f"Invalid size format: '{size_str}'")
    
def format_size(size_bytes):
    """
    Convert bytes to human-readable format.
    Example: 1048576 -> '1.00MB'
    """
    if size_bytes == 0:
        return "0B"
    
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    unit_idx = 0
    size = float(size_bytes)
    
    # Find appropriate unit
    while size >= 1024 and unit_idx < len(units)-1:
        size /= 1024
        unit_idx += 1
        
    return f"{size:.2f}{units[unit_idx]}"

def compute_hashes(file_path, algorithms, chunk_size):
    """
    Compute file hashes. 
    Returns hashes.
    """
    hashers = {alg: hashlib.new(alg) for alg in algorithms}
    
    try:
        with open(file_path, 'rb', buffering=0) as f:
            LOGGER.debug(f"Trying to hash file: {file_path}")

            # Read and hash in chunks
            while chunk := f.read(chunk_size):
                for hasher in hashers.values():
                    hasher.update(chunk)
    except Exception as e:
        if "[Errno 22]" in str(e): 
            LOGGER.warning(f"Failed to hash a protected file: {file_path}")
            return None, 'protected_file'
        else: 
            LOGGER.error(f"Hashing failed for {file_path}: {str(e)}")
        return None, 'error'
    
    return {alg: hasher.hexdigest() for alg, hasher in hashers.items()}, ''

def setup_logging(log_file, file_level, console_level):
    """
    Configure dual logging system (file + console)
    with independent verbosity levels.
    """
    global LOGGER
    logger = logging.getLogger('TriageHasher')
    logger.setLevel(logging.DEBUG)  # Capture all messages
    
    # Clear any existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # Validate log levels
    if not 0 <= file_level <= 4:
        raise ValueError("Invalid log_file_level (must be 0-4)")
    if not 0 <= console_level <= 4:
        raise ValueError("Invalid log_console_level (must be 0-4)")

    # Map numeric levels to logging constants
    level_map = {
        0: logging.NOTSET,
        1: logging.ERROR,
        2: logging.WARNING,
        3: logging.INFO,
        4: logging.DEBUG
    }
    
    # Configure file logging if enabled
    if file_level > 0:
        fh = logging.FileHandler(log_file)
        fh.setLevel(level_map[file_level])
        fh_formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s', 
                                         datefmt='%Y-%m-%d %H:%M:%S')
        fh.setFormatter(fh_formatter)
        logger.addHandler(fh)
    
    # Configure console logging if enabled
    if console_level > 0:
        ch = logging.StreamHandler()
        ch.setLevel(level_map[console_level])
        ch_formatter = logging.Formatter('[%(levelname)s] %(message)s')
        ch.setFormatter(ch_formatter)
        logger.addHandler(ch)
    
    LOGGER = logger

def main():
    #print the logo
    print(f'''
████████╗██████╗ ██╗ █████╗  ██████╗ ███████╗   
╚══██╔══╝██╔══██╗██║██╔══██╗██╔════╝ ██╔════╝   
   ██║   ██████╔╝██║███████║██║  ███╗█████╗     
   ██║   ██╔══██╗██║██╔══██║██║   ██║██╔══╝     
   ██║   ██║  ██║██║██║  ██║╚██████╔╝███████╗   
   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝   
██╗  ██╗ █████╗ ███████╗██╗  ██╗███████╗██████╗ 
██║  ██║██╔══██╗██╔════╝██║  ██║██╔════╝██╔══██╗
███████║███████║███████╗███████║█████╗  ██████╔╝
██╔══██║██╔══██║╚════██║██╔══██║██╔══╝  ██╔══██╗
██║  ██║██║  ██║███████║██║  ██║███████╗██║  ██║
╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝                                              
        DFIR Forensic Hashing Tool
==================V{VERSION}=====================
https://github.com/FlipForensics/TriageHasher
Note: This tool should always be ran with admin rights. 
          ''')

    # Configure argument parser with detailed help
    parser = argparse.ArgumentParser(
        prog='TriageHasher',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=f'''
TriageHasher V{VERSION}
Collects file hashes from specified locations while.
Generates CSV output with file metadata and hashes.''',
        epilog='''Examples:
  Basic usage: 
    python TriageHasher.py -c config.ini -o ./output
  
  Use default config (config.ini) and output to current directory:
    python TriageHasher.py
  
  Specify custom config and output:
    python TriageHasher.py --config custom.ini --output /forensic/output'''
    )
    
    # Add arguments with proper help documentation
    parser.add_argument('-c', '--config',
                        dest='config_file',
                        default='config.ini',
                        help='Configuration file (default: config.ini)',
                        metavar='FILE')
    
    parser.add_argument('-o', '--output',
                        dest='output_location',
                        default=os.getcwd(),
                        help='Output directory (default: current working directory)',
                        metavar='DIR')
    
    args = parser.parse_args()
    
    # Record start time immediately after argument parsing
    start_time_utc = datetime.now(timezone.utc)
    start_time = time.time()
    start_time_utc_str = start_time_utc.strftime("%Y%m%d_%H%M%S")
    
    # Get sanitized computer name
    computer_name = get_safe_computer_name()

    # Validate config file exists
    if not os.path.exists(args.config_file):
        print(f"Error: Config file not found at {args.config_file}")
        print("Please specify a valid configuration file with -c or create config.ini")
        sys.exit(1)
    
    config = configparser.ConfigParser(interpolation=None)
    
    # Read the config file
    try:
        config.read(args.config_file)
        cfg = config['DEFAULT']
        
        # Mandatory configuration parameters (no defaults)
        locations_file = cfg['locations_file']
        extensions = [ext.strip().lower() for ext in cfg['extensions'].split(',')]
        max_file_size = parse_size(cfg['max_file_size'])
        chunk_size = int(cfg['chunk_size'])
        log_file_level = int(cfg['log_file_level'])
        log_console_level = int(cfg['log_console_level'])
        csv_delimiter = cfg['csv_delimiter']
        hash_algorithms = [alg.strip().lower() for alg in cfg['hash_algorithms'].split(',')]
        time_format = cfg.get('time_format', '%d-%m-%Y %H:%M:%S.%f')
        time_format = time_format.replace('\\n', '\n').replace('\\t', '\t')
        
        # Validate hash algorithms
        valid_algorithms = hashlib.algorithms_available
        for alg in hash_algorithms:
            if alg not in valid_algorithms:
                raise ValueError(f"Unsupported hash algorithm: {alg}")
        
        # Normalize extensions
        extensions = [ext if ext.startswith('.') else f'.{ext}' for ext in extensions]
        
    except KeyError as e:
        print(f"Missing required configuration: {str(e)}")
        sys.exit(1)
    except ValueError as e:
        print(f"Invalid configuration value: {str(e)}")
        sys.exit(1)
    except Exception as e:
        print(f"Configuration error: {str(e)}")
        sys.exit(1)
    
    # Create output directory if needed
    output_dir = args.output_location
    os.makedirs(output_dir, exist_ok=True)
    
     # Generate dynamic filenames
    csv_filename = f"FileHashes_{computer_name}_{start_time_utc_str}.csv"
    log_filename = f"TriageHasherLog_{computer_name}_{start_time_utc_str}.txt"
    
    csv_path = os.path.join(args.output_location, csv_filename)
    log_file = os.path.join(args.output_location, log_filename)


    # Initialize logging system
    setup_logging(log_file, log_file_level, log_console_level)
    LOGGER.info(f"TriageHasher V{VERSION} started")
    LOGGER.info(f"Using configuration: {args.config_file}")
    LOGGER.info(f"Output directory: {output_dir}")
    
    # Read file location patterns
    try:
        with open(locations_file, 'r') as f:
            patterns = [line.strip() for line in f if line.strip()]
        LOGGER.info(f"Loaded {len(patterns)} file patterns from {locations_file}")
    except Exception as e:
        LOGGER.error(f"Could not read locations file: {str(e)}")
        sys.exit(1)
    
    # Prepare CSV output file
    fieldnames = [
        'full_path', 
        'filename', 
        'creation_time_utc', 
        'modification_time_utc', 
        'access_time_utc',
        *hash_algorithms,  # Dynamic hash algorithm columns
        'size'
    ]
    
    # Initialize counters
    processed_files = 0
    hashing_errors = 0
    protected_file_skips = 0

    try:
        with open(csv_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames, delimiter=csv_delimiter)
            writer.writeheader()
            
            # Process each file pattern
            for pattern in patterns:
                LOGGER.info(f"Processing pattern: {pattern}")
                
                # Expand pattern with recursive glob
                for file_path in glob.glob(pattern, recursive=True):
                    basename = str(os.path.basename(file_path))
                    
                    # Skip directories
                    if not os.path.isfile(file_path):
                        continue
                    
                    # Check file extension
                    file_ext = os.path.splitext(file_path)[1].lower()
                    if file_ext not in extensions:
                        LOGGER.debug(f"Skipping non-target extension: {file_path}")
                        continue                
                    
                    # Get the file metadata
                    try: 
                        stat = os.stat(file_path)
                        original_stat_atime = stat.st_atime
                        original_stat_mtime  = stat.st_mtime 
                        original_stat_ctime  = stat.st_ctime
                        file_size  = stat.st_size                   
                    except Exception as e:
                        LOGGER.debug(f"Metadata access failed: {file_path} - {str(e)}")    

                    # Skip files exceeding size limit
                    if file_size > max_file_size:
                        LOGGER.debug(f"Skipping large file ({format_size(file_size)}): {file_path}")
                        continue
                    
                    # Prepare metadata dictionary
                    metadata = {
                        'full_path': file_path,
                        'filename': basename,
                        'creation_time_utc': format_timestamp(original_stat_ctime, time_format),
                        'modification_time_utc': format_timestamp(original_stat_mtime, time_format),
                        'access_time_utc': format_timestamp(original_stat_atime, time_format),
                        'size': format_size(file_size)
                    }
                    
                    hashes, error_string = compute_hashes(
                            file_path,
                            hash_algorithms,
                            chunk_size
                    )                  

                    # Track different error types
                    if error_string == 'error':
                        hashing_errors += 1
                        continue
                    elif error_string == 'protected_file':
                        protected_file_skips +=1

                    # Combine metadata and hashes for CSV row
                    row = {**metadata, **hashes}
                    writer.writerow(row)
                    processed_files += 1
                    
                    # Periodic progress updates
                    if processed_files % 1000 == 0:
                        LOGGER.info(f"Processed {processed_files} files...")
    
    except Exception as e:
        LOGGER.error(f"Fatal error: {str(e)}", exc_info=True)
        sys.exit(1)
    
    end_time = time.time()
    total_seconds = end_time - start_time
    runtime_str = format_runtime(total_seconds)

    # Final report 
    LOGGER.info(
        f"Processing completed in {runtime_str}. "
        f"Files: {processed_files}, "
        f"Hashing Errors: {hashing_errors}, "
        f"Files not hashed because they were protected: {protected_file_skips}. "
    )
    LOGGER.info(f"CSV output: {csv_path}")
    LOGGER.info(f"Log file: {log_file}")
    print(f"Operation complete. Results saved to: {output_dir}")

if __name__ == "__main__":
    main()