#!/usr/bin/env python3
VERSION = "1.0"

"""
TriageHasher - DFIR File Hashing Tool
This script processes files from specified locations, computes hashes,
preserves original timestamps, and outputs results in CSV format for forensic analysis.
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

def restore_timestamps(file_path, original_atime, original_mtime, logger):
    """
    Restore original timestamps and return error category if failed.
    Returns: 'success', 'permission_error', or 'restoration_error'
    """
    try:
        # Attempt to restore timestamps
        os.utime(file_path, (original_atime, original_mtime))
        
        # Verify restoration was successful
        new_stat = os.stat(file_path)
        timestamp_diff = abs(new_stat.st_atime - original_atime)
        
        # Check if restoration failed (more than 1-second difference)
        if timestamp_diff > 1.0:
            logger.warning(
                f"Access time restoration failed for {file_path}: "
                f"Difference: {timestamp_diff:.2f} seconds"
            )
            return 'restoration_error'
            
        return 'success'
    except PermissionError:
        # Permission errors are expected for protected files
        return 'permission_error'
    except Exception as e:
        if "[WinError 1920]" in str(e): 
            return 'permission_error'
        logger.warning(f"Error restoring timestamps for {file_path}: {str(e)}")
        return 'restoration_error'

def compute_hashes(file_path, algorithms, chunk_size, original_stat, logger):
    """
    Compute file hashes while preserving original access time.
    Returns hashes and a flag indicating if timestamps were preserved.
    """
    hashers = {alg: hashlib.new(alg) for alg in algorithms}
    restoration_success = False
    
    try:
        # Open file with minimal access to reduce timestamp changes
        with open(file_path, 'rb', buffering=0) as f:
            logger.debug(f"Trying to hash file: {file_path}")

            # Read and hash in chunks
            while chunk := f.read(chunk_size):
                for hasher in hashers.values():
                    hasher.update(chunk)
            
            # Attempt to restore timestamps while file is still open
            try:
                os.futimes(f.fileno(), (original_stat.st_atime, original_stat.st_mtime))
                restoration_success = True
            except (AttributeError, OSError):
                # Fallback to path-based restoration
                pass
    
    except Exception as e:
        if "[Errno 22]" in str(e): 
            logger.warning(f"Failed to hash a protected file: {file_path}")
            return None, False, 'protected_file'
        else: 
            logger.error(f"Hashing failed for {file_path}: {str(e)}")
        return None, False, 'error'
    
    return {alg: hasher.hexdigest() for alg, hasher in hashers.items()}, restoration_success, ''
def setup_logging(log_file, file_level, console_level):
    """
    Configure dual logging system (file + console)
    with independent verbosity levels.
    """
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
    
    return logger

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
          ''')

    # Configure argument parser with detailed help
    parser = argparse.ArgumentParser(
        prog='TriageHasher',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=f'''
TriageHasher V{VERSION}
Collects file hashes from specified locations while preserving file metadata.
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
    logger = setup_logging(log_file, log_file_level, log_console_level)
    logger.info("TriageHasher started")
    logger.info(f"Using configuration: {args.config_file}")
    logger.info(f"Output directory: {output_dir}")
    
    # Read file location patterns
    try:
        with open(locations_file, 'r') as f:
            patterns = [line.strip() for line in f if line.strip()]
        logger.info(f"Loaded {len(patterns)} file patterns from {locations_file}")
    except Exception as e:
        logger.error(f"Could not read locations file: {str(e)}")
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
    restoration_errors = 0
    protected_file_skips = 0

    try:
        with open(csv_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames, delimiter=csv_delimiter)
            writer.writeheader()
            
            # Process each file pattern
            for pattern in patterns:
                logger.info(f"Processing pattern: {pattern}")
                
                # Expand pattern with recursive glob
                for file_path in glob.glob(pattern, recursive=True):
                    
                    try:
                        # Get file metadata
                        original_stat = os.stat(file_path)
                        file_size = os.path.getsize(file_path)
                    except Exception as e:
                        logger.debug(f"Metadata access failed: {file_path} - {str(e)}")

                    # Skip directories
                    if not os.path.isfile(file_path):
                        continue
                    
                    # Check file extension
                    file_ext = os.path.splitext(file_path)[1].lower()
                    if file_ext not in extensions:
                        logger.debug(f"Skipping non-target extension: {file_path}")
                        continue

                    # Skip files exceeding size limit
                    if file_size > max_file_size:
                        logger.debug(f"Skipping large file ({format_size(file_size)}): {file_path}")
                        continue
                    
                    # Prepare metadata dictionary
                    metadata = {
                        'full_path': file_path,
                        'filename': os.path.basename(file_path),
                        'creation_time_utc': format_timestamp(original_stat.st_ctime, time_format),
                        'modification_time_utc': format_timestamp(original_stat.st_mtime, time_format),
                        'access_time_utc': format_timestamp(original_stat.st_atime, time_format),
                        'size': format_size(file_size)
                    }
                    
                    # Compute hashes and attempt in-place timestamp preservation
                    hashes, in_place_success, error_string = compute_hashes(
                        file_path,
                        hash_algorithms,
                        chunk_size,
                        original_stat,
                        logger
                    )
                                        
                    # Fallback to external restoration if needed
                    if not in_place_success:
                        restoration_result = restore_timestamps(
                            file_path,
                            original_stat.st_atime,
                            original_stat.st_mtime,
                            logger
                        )
                        if restoration_result == 'restoration_error':
                            restoration_errors += 1

                    if in_place_success or restoration_result == 'success':
                        # Verify restoration
                        new_stat = os.stat(file_path)
                        if abs(new_stat.st_atime - original_stat.st_atime) > 0.01:  # 10ms threshold
                            logger.warning(f"Timestamp drift detected: {file_path} "
                                        f"({new_stat.st_atime - original_stat.st_atime:.6f}s)")

                    # Track different error types
                    if error_string == 'error':
                        hashing_errors += 1
                        continue
                    elif error_string == 'protected_file':
                        protected_file_skips +=1
                        continue
                    elif restoration_result == 'restoration_error':
                        restoration_errors += 1
                    elif restoration_result == 'permission_error':
                        # Only log at debug level for protected files
                        logger.debug(f"Permission error restoring timestamps for {file_path}")


                    # Combine metadata and hashes for CSV row
                    row = {**metadata, **hashes}
                    writer.writerow(row)
                    processed_files += 1
                    
                    # Periodic progress updates
                    if processed_files % 1000 == 0:
                        logger.info(f"Processed {processed_files} files...")
    
    except Exception as e:
        logger.error(f"Fatal error: {str(e)}", exc_info=True)
        sys.exit(1)
    
    end_time = time.time()
    total_seconds = end_time - start_time
    runtime_str = format_runtime(total_seconds)

    # Final report
    logger.info(
        f"Processing completed in {runtime_str}. "
        f"Files: {processed_files}, "
        f"Hashing Errors: {hashing_errors}, "
        f"Files not hashed because they were protected: {protected_file_skips}, "
        f"Restoration Errors: {restoration_errors}, "
    )
    logger.info(f"CSV output: {csv_path}")
    logger.info(f"Log file: {log_file}")
    print(f"Operation complete. Results saved to: {output_dir}")

if __name__ == "__main__":
    main()