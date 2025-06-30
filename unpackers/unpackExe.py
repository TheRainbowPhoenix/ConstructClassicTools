#!/usr/bin/env python3
"""
Advanced PE Resource Extractor

Extracts resources from PE files (executables/DLLs) with flexible filtering options.
Creates organized output structure with type-based folders and automatic file extension detection.

Features:
- Extract all resources or filter by type/case
- Batch processing for multiple PE files
- Smart file extension detection
- Duplicate handling with language IDs
- Detailed logging and statistics

Requires: pip install pefile
"""

import os
import sys
import argparse
import pefile
from pathlib import Path
import logging
from typing import List, Optional, Dict, Tuple
from collections import defaultdict
import glob

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

class ResourceExtractor:
    """Handles extraction of resources from PE files."""
    
    def __init__(self, output_dir: str = "extracted_resources", 
                 uppercase_only: bool = True, custom_extensions: Optional[Dict[str, str]] = None):
        self.output_dir = Path(output_dir)
        self.uppercase_only = uppercase_only
        self.custom_extensions = custom_extensions or {}
        self.stats = defaultdict(int)
        
        # Default extension mappings
        self.default_extensions = {
            "DLLBLOCK": ".dll",
            "FILES": self._detect_files_extension,
            "IMAGEBLOCK": ".bin",
            "MANIFEST": ".xml",
            "VERSION": ".version",
            "CURSOR": ".cur",
            "BITMAP": ".bmp",
            "ICON": ".ico",
            "DIALOG": ".dlg",
            "STRING": ".txt",
            "ACCELERATOR": ".acc",
            "RCDATA": ".bin",
            "MESSAGETABLE": ".msg",
            "GROUP_CURSOR": ".cur",
            "GROUP_ICON": ".ico",
            "MENU": ".menu",
            "FONTDIR": ".fnt",
            "FONT": ".fnt",
            "TYPELIB": ".tlb"
        }
    
    def _detect_files_extension(self, data: bytes) -> str:
        """Detect file extension for FILES resource type based on content."""
        if len(data) >= 4:
            if data[:4] == b"RIFF":
                return ".wav"
            elif data[:4] == b"MThd":
                return ".mid"
            elif data[:2] == b"PK":
                return ".zip"
            elif data[:4] == b"\x89PNG":
                return ".png"
            elif data[:2] == b"\xFF\xD8":
                return ".jpg"
            elif data[:4] == b"GIF8":
                return ".gif"
        return ".bin"
    
    def _is_all_upper(self, name: str) -> bool:
        """Check if name contains only uppercase letters (no lowercase a-z)."""
        return not any(c.islower() for c in name)
    
    def _get_extension(self, type_name: str, data: bytes) -> str:
        """Get appropriate file extension for resource type and data."""
        # Check custom extensions first
        if type_name in self.custom_extensions:
            ext_or_func = self.custom_extensions[type_name]
            if callable(ext_or_func):
                return ext_or_func(data)
            return ext_or_func
        
        # Check default extensions
        if type_name in self.default_extensions:
            ext_or_func = self.default_extensions[type_name]
            if callable(ext_or_func):
                return ext_or_func(data)
            return ext_or_func
        
        # Default to .bin
        return ".bin"
    
    def _create_safe_filename(self, base_name: str, ext: str, output_dir: Path, lang_id: int = None) -> Path:
        """Create a safe filename, handling duplicates with language IDs."""
        filename = f"{base_name}{ext}"
        filepath = output_dir / filename
        
        if not filepath.exists():
            return filepath
        
        # File exists, add language ID
        if lang_id is not None:
            filename = f"{base_name}_lang{lang_id}{ext}"
            filepath = output_dir / filename
        
        # If still exists, add counter
        counter = 1
        while filepath.exists():
            if lang_id is not None:
                filename = f"{base_name}_lang{lang_id}_{counter}{ext}"
            else:
                filename = f"{base_name}_{counter}{ext}"
            filepath = output_dir / filename
            counter += 1
        
        return filepath
    
    def extract_from_pe(self, pe_path: Path) -> bool:
        """Extract resources from a single PE file."""
        try:
            logger.info(f"Processing: {pe_path}")
            
            if not pe_path.exists():
                logger.error(f"File not found: {pe_path}")
                return False
            
            pe = pefile.PE(str(pe_path))
            
            # Check for resource section
            if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                logger.warning(f"No resource section found in {pe_path}")
                pe.close()
                return False
            
            resources_found = 0
            
            # Process each resource type
            for type_entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                # Skip unnamed types
                if not type_entry.name:
                    logger.debug(f"Skipping unnamed resource type (ID: {type_entry.id})")
                    continue
                
                type_name = str(type_entry.name)
                
                # Filter by case if requested
                if self.uppercase_only and not self._is_all_upper(type_name):
                    logger.debug(f"Skipping mixed-case type: {type_name}")
                    continue
                
                # Create output directory for this type
                type_output_dir = self.output_dir / pe_path.stem / type_name
                type_output_dir.mkdir(parents=True, exist_ok=True)
                
                logger.info(f"Extracting {type_name} resources...")
                
                # Process each resource in this type
                for res_entry in type_entry.directory.entries:
                    res_name = str(res_entry.name) if res_entry.name else f"id_{res_entry.id}"
                    
                    # Process each language variant
                    for lang_entry in res_entry.directory.entries:
                        try:
                            # Get resource data
                            rva = lang_entry.data.struct.OffsetToData
                            size = lang_entry.data.struct.Size
                            data = pe.get_data(rva, size)
                            
                            # Determine file extension
                            ext = self._get_extension(type_name, data)
                            
                            # Create safe filename
                            output_file = self._create_safe_filename(
                                res_name, ext, type_output_dir, lang_entry.id
                            )
                            
                            # Write file
                            output_file.write_bytes(data)
                            
                            logger.info(f"  → {output_file.relative_to(self.output_dir)} ({size:,} bytes)")
                            
                            resources_found += 1
                            self.stats[type_name] += 1
                            self.stats['total_files'] += 1
                            self.stats['total_bytes'] += size
                            
                        except Exception as e:
                            logger.error(f"Error extracting resource {res_name}: {e}")
            
            pe.close()
            
            if resources_found > 0:
                logger.info(f"Successfully extracted {resources_found} resources from {pe_path}")
            else:
                logger.warning(f"No matching resources found in {pe_path}")
            
            return resources_found > 0
            
        except Exception as e:
            logger.error(f"Error processing {pe_path}: {e}")
            return False
    
    def extract_batch(self, input_paths: List[Path]) -> None:
        """Extract resources from multiple PE files."""
        successful = 0
        failed = 0
        
        logger.info(f"Starting batch extraction of {len(input_paths)} files")
        
        for pe_path in input_paths:
            if self.extract_from_pe(pe_path):
                successful += 1
            else:
                failed += 1
        
        self._print_summary(successful, failed)
    
    def _print_summary(self, successful: int, failed: int) -> None:
        """Print extraction summary."""
        print("\n" + "="*60)
        print("EXTRACTION SUMMARY")
        print("="*60)
        print(f"Files processed: {successful + failed}")
        print(f"Successful: {successful}")
        print(f"Failed: {failed}")
        print(f"Total resources extracted: {self.stats['total_files']:,}")
        print(f"Total bytes extracted: {self.stats['total_bytes']:,}")
        
        if self.stats['total_files'] > 0:
            print("\nResources by type:")
            for res_type, count in sorted(self.stats.items()):
                if res_type not in ('total_files', 'total_bytes'):
                    print(f"  {res_type}: {count:,}")
        
        print("="*60)

def find_pe_files(search_path: Path, recursive: bool = False) -> List[Path]:
    """Find PE files in the given path."""
    patterns = ['*.exe', '*.dll', '*.ocx', '*.sys', '*.scr']
    files = []
    
    if search_path.is_file():
        return [search_path]
    
    if not search_path.is_dir():
        logger.error(f"Path not found: {search_path}")
        return []
    
    for pattern in patterns:
        if recursive:
            files.extend(search_path.rglob(pattern))
        else:
            files.extend(search_path.glob(pattern))
    
    return sorted(files)

def main():
    parser = argparse.ArgumentParser(
        description="Extract resources from PE files (EXE/DLL) with advanced filtering",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Extract from single file (uppercase types only)
  python resource_extractor.py game.exe
  
  # Extract all resource types (including mixed-case)
  python resource_extractor.py game.exe --all-types
  
  # Extract to specific output directory
  python resource_extractor.py game.exe -o extracted_resources
  
  # Batch process all PE files in a directory
  python resource_extractor.py -b /path/to/games --recursive
  
  # Extract only specific resource types
  python resource_extractor.py game.exe --types IMAGEBLOCK DLLBLOCK FILES
  
  # Add custom file extensions
  python resource_extractor.py game.exe --ext CUSTOMTYPE:.dat MYRES:.bin
        """
    )
    
    # Input options
    parser.add_argument(
        'input',
        nargs='?',
        help='PE file to extract resources from'
    )
    
    parser.add_argument(
        '-b', '--batch',
        help='Process all PE files in the specified directory'
    )
    
    parser.add_argument(
        '--recursive',
        action='store_true',
        help='Search for PE files recursively in batch mode'
    )
    
    # Output options
    parser.add_argument(
        '-o', '--output',
        default='extracted_resources',
        help='Output directory (default: extracted_resources)'
    )
    
    # Filtering options
    parser.add_argument(
        '--all-types',
        action='store_true',
        help='Extract all resource types (not just uppercase)'
    )
    
    parser.add_argument(
        '--types',
        nargs='+',
        help='Extract only specified resource types'
    )
    
    # Extension customization
    parser.add_argument(
        '--ext',
        nargs='+',
        help='Custom extensions in format TYPE:extension (e.g., IMAGEBLOCK:.img)'
    )
    
    # Verbosity
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Suppress most output'
    )
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.input and not args.batch:
        parser.error("Must specify either an input file or --batch directory")
    
    if args.input and args.batch:
        parser.error("Cannot specify both input file and batch directory")
    
    # Configure logging level
    if args.quiet:
        logging.getLogger().setLevel(logging.ERROR)
    elif args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Parse custom extensions
    custom_extensions = {}
    if args.ext:
        for ext_spec in args.ext:
            if ':' not in ext_spec:
                parser.error(f"Invalid extension format: {ext_spec}. Use TYPE:extension")
            type_name, extension = ext_spec.split(':', 1)
            if not extension.startswith('.'):
                extension = '.' + extension
            custom_extensions[type_name] = extension
    
    try:
        # Create extractor
        extractor = ResourceExtractor(
            output_dir=args.output,
            uppercase_only=not args.all_types,
            custom_extensions=custom_extensions
        )
        
        if args.batch:
            # Batch processing
            search_path = Path(args.batch)
            pe_files = find_pe_files(search_path, args.recursive)
            
            if not pe_files:
                logger.error(f"No PE files found in {search_path}")
                return 1
            
            logger.info(f"Found {len(pe_files)} PE files to process")
            extractor.extract_batch(pe_files)
            
        else:
            # Single file processing
            pe_path = Path(args.input)
            success = extractor.extract_from_pe(pe_path)
            
            if success:
                extractor._print_summary(1, 0)
            else:
                logger.error("Extraction failed")
                return 1
    
    except KeyboardInterrupt:
        logger.info("Operation cancelled by user")
        return 1
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())