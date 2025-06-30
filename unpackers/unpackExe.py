#!/usr/bin/env python3
"""
Advanced PE Resource Extractor with Integrated DLL Renaming

Extracts resources from PE files (executables/DLLs) with flexible filtering options.
Automatically renames extracted DLL files to their OriginalFilename from VersionInfo.

Features:
- Extract all resources or filter by type/case
- Automatic DLL renaming using VersionInfo->OriginalFilename
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
import re

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
                 uppercase_only: bool = True, custom_extensions: Optional[Dict[str, str]] = None,
                 auto_rename_dlls: bool = True):
        self.output_dir = Path(output_dir)
        self.uppercase_only = uppercase_only
        self.custom_extensions = custom_extensions or {}
        self.auto_rename_dlls = auto_rename_dlls
        self.stats = defaultdict(int)
        self.dll_rename_stats = {'renamed': 0, 'failed': 0, 'skipped': 0}
        
        # Characters that are illegal on Windows/Unix filenames
        self.bad_chars = re.compile(r'[<>:"/\\|?*\x00-\x1F]')
        
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
    
    def _safe_filename(self, name: str) -> str:
        """Strip any path, control chars, or invalid filename chars from VersionInfo field."""
        name = os.path.basename(name)  # remove any supplied path
        name = self.bad_chars.sub("_", name)  # replace bad chars with underscore
        return name.strip()
    
    def _get_original_filename(self, dll_path: Path) -> Optional[str]:
        """
        Return the VersionInfo->OriginalFilename string from dll_path (or None).
        Handles the fact that pe.FileInfo can be a list of lists.
        """
        try:
            pe = pefile.PE(str(dll_path), fast_load=True)
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]]
            )
        except (pefile.PEFormatError, Exception) as e:
            logger.debug(f"Failed to parse PE file {dll_path}: {e}")
            return None

        def iter_fileinfo(fi):
            """Depth-first flatten of nested FileInfo lists."""
            if isinstance(fi, list):
                for item in fi:
                    yield from iter_fileinfo(item)
            else:
                yield fi

        try:
            for fi in iter_fileinfo(getattr(pe, "FileInfo", [])):
                # We only care about StringFileInfo blocks (they have .StringTable)
                if not hasattr(fi, "StringTable"):
                    continue

                for st in fi.StringTable:
                    for k, v in st.entries.items():
                        if k.decode(errors="ignore") == "OriginalFilename":
                            original_name = v.decode(errors="ignore").rstrip("\x00")
                            pe.close()
                            return original_name
        except Exception as e:
            logger.debug(f"Error reading VersionInfo from {dll_path}: {e}")
        
        pe.close()
        return None
    
    def _rename_dll_to_original(self, dll_path: Path) -> bool:
        """Rename a DLL file to its OriginalFilename from VersionInfo."""
        original_name = self._get_original_filename(dll_path)
        
        if not original_name:
            logger.debug(f"No OriginalFilename found for {dll_path.name}")
            self.dll_rename_stats['skipped'] += 1
            return False
        
        # Clean the original filename
        new_name = self._safe_filename(original_name)
        base, ext = os.path.splitext(new_name)
        if not ext:  # OriginalFilename had no extension
            new_name = base + ".dll"
        
        new_path = dll_path.parent / new_name
        
        # Check if it's already the correct name
        if dll_path.resolve() == new_path.resolve():
            logger.debug(f"{dll_path.name} already matches OriginalFilename")
            self.dll_rename_stats['skipped'] += 1
            return False
        
        # Handle name conflicts by adding _1, _2, etc.
        if new_path.exists():
            stem, ext = os.path.splitext(new_name)
            counter = 1
            while True:
                candidate_name = f"{stem}_{counter}{ext}"
                candidate_path = dll_path.parent / candidate_name
                if not candidate_path.exists():
                    new_path = candidate_path
                    new_name = candidate_name
                    break
                counter += 1
        
        try:
            dll_path.rename(new_path)
            logger.info(f"  DLL renamed: {dll_path.name} → {new_name}")
            self.dll_rename_stats['renamed'] += 1
            return True
        except Exception as e:
            logger.error(f"Failed to rename {dll_path.name}: {e}")
            self.dll_rename_stats['failed'] += 1
            return False
    
    def _rename_dlls_in_directory(self, directory: Path) -> None:
        """Rename all DLL files in a directory to their OriginalFilename."""
        if not directory.exists():
            return
        
        dll_files = list(directory.glob("*.dll"))
        if not dll_files:
            return
        
        logger.info(f"Renaming {len(dll_files)} DLL files in {directory.relative_to(self.output_dir)}...")
        
        for dll_file in dll_files:
            self._rename_dll_to_original(dll_file)
    
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
            dllblock_dir = None
            
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
                
                # Remember DLLBLOCK directory for later renaming
                if type_name == "DLLBLOCK":
                    dllblock_dir = type_output_dir
                
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
            
            # Auto-rename DLLs if enabled and DLLBLOCK was extracted
            if self.auto_rename_dlls and dllblock_dir:
                self._rename_dlls_in_directory(dllblock_dir)
            
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
        
        # Print DLL renaming summary if auto-rename was enabled
        if self.auto_rename_dlls and any(self.dll_rename_stats.values()):
            print("\nDLL Renaming Summary:")
            print(f"  Renamed: {self.dll_rename_stats['renamed']}")
            print(f"  Skipped: {self.dll_rename_stats['skipped']}")
            print(f"  Failed: {self.dll_rename_stats['failed']}")
        
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
        description="Extract resources from PE files (EXE/DLL) with automatic DLL renaming",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Extract from single file (uppercase types only, auto-rename DLLs)
  python unpackExe.py game.exe
  
  # Extract all resource types (including mixed-case)
  python unpackExe.py game.exe --all-types
  
  # Extract without auto-renaming DLLs
  python unpackExe.py game.exe --no-rename-dlls
  
  # Extract to specific output directory
  python unpackExe.py game.exe -o extracted_resources
  
  # Batch process all PE files in a directory
  python unpackExe.py -b /path/to/games --recursive
  
  # Extract only specific resource types
  python unpackExe.py game.exe --types IMAGEBLOCK DLLBLOCK FILES
  
  # Add custom file extensions
  python unpackExe.py game.exe --ext CUSTOMTYPE:.dat MYRES:.bin
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
    
    # DLL renaming options
    parser.add_argument(
        '--no-rename-dlls',
        action='store_true',
        help='Disable automatic DLL renaming to OriginalFilename'
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
            custom_extensions=custom_extensions,
            auto_rename_dlls=not args.no_rename_dlls
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