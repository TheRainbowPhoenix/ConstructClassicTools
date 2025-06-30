#!/usr/bin/env python3
"""
Imageblock Binary Unpacker
Extracts PNG images from Imageblock binary files.
"""

import struct
import os
import sys
import argparse
from pathlib import Path
import glob

class ImageblockUnpacker:
    def __init__(self, data):
        self.data = data
        self.cursor = 0
        self.length = len(data)
    
    def read_int(self):
        """Read a 32-bit integer and advance cursor"""
        if self.cursor + 4 > self.length:
            raise ValueError(f"Unexpected end of data at position {self.cursor}")
        value = struct.unpack('<I', self.data[self.cursor:self.cursor + 4])[0]
        self.cursor += 4
        return value
    
    def read_bytes(self, count):
        """Read specified number of bytes and advance cursor"""
        if self.cursor + count > self.length:
            raise ValueError(f"Unexpected end of data at position {self.cursor}")
        value = self.data[self.cursor:self.cursor + count]
        self.cursor += count
        return value
    
    def read_string(self, length):
        """Read a null-terminated string of specified length"""
        data = self.read_bytes(length)
        # Find null terminator
        null_pos = data.find(b'\x00')
        if null_pos != -1:
            return data[:null_pos].decode('utf-8', errors='ignore')
        return data.decode('utf-8', errors='ignore')
    
    def unpack(self, output_dir="extracted_images"):
        """Unpack all images from the imageblock"""
        print(f"Starting to unpack imageblock (size: {self.length} bytes)")
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
        # Read number of images
        num_images = self.read_int()
        print(f"Found {num_images} images")
        
        extracted_count = 0
        
        for i in range(num_images):
            try:
                print(f"\nProcessing image {i + 1}/{num_images}")
                
                # Read image handle
                image_handle = self.read_int()
                print(f"  Image handle: {image_handle}")
                
                # Read hotspot coordinates
                hotspot_x = self.read_int()
                hotspot_y = self.read_int()
                print(f"  Hotspot: ({hotspot_x}, {hotspot_y})")
                
                # Read action points
                action_count = self.read_int()
                print(f"  Action points: {action_count}")
                
                action_points = []
                for a in range(action_count):
                    ap_x = self.read_int()
                    ap_y = self.read_int()
                    name_length = self.read_int()
                    name = self.read_string(name_length)
                    action_points.append({
                        'x': ap_x,
                        'y': ap_y,
                        'name': name
                    })
                    print(f"    Action point {a + 1}: ({ap_x}, {ap_y}) '{name}'")
                
                # Read PNG image data
                image_data_size = self.read_int()
                print(f"  PNG size: {image_data_size} bytes")
                
                if image_data_size > 0:
                    png_data = self.read_bytes(image_data_size)
                    
                    # Verify PNG signature
                    if png_data[:8] == b'\x89PNG\r\n\x1a\n':
                        # Save PNG file
                        filename = f"image_{image_handle:04d}.png"
                        filepath = os.path.join(output_dir, filename)
                        
                        with open(filepath, 'wb') as f:
                            f.write(png_data)
                        
                        print(f"  Saved: {filename}")
                        extracted_count += 1
                        
                        # Save metadata
                        metadata_filename = f"image_{image_handle:04d}_metadata.txt"
                        metadata_filepath = os.path.join(output_dir, metadata_filename)
                        
                        with open(metadata_filepath, 'w') as f:
                            f.write(f"Image Handle: {image_handle}\n")
                            f.write(f"Hotspot: ({hotspot_x}, {hotspot_y})\n")
                            f.write(f"PNG Size: {image_data_size} bytes\n")
                            f.write(f"Action Points ({action_count}):\n")
                            for j, ap in enumerate(action_points):
                                f.write(f"  {j + 1}. ({ap['x']}, {ap['y']}) '{ap['name']}'\n")
                    else:
                        print(f"  Warning: Invalid PNG signature for image {image_handle}")
                
                # Read collision mask data
                mask_width = self.read_int()
                mask_height = self.read_int()
                mask_pitch = self.read_int()
                
                print(f"  Collision mask: {mask_width}x{mask_height}, pitch: {mask_pitch}")
                
                # Skip collision mask data
                mask_data_size = mask_pitch * mask_height
                if mask_data_size > 0:
                    self.read_bytes(mask_data_size)
                    print(f"  Skipped {mask_data_size} bytes of collision mask data")
                
            except Exception as e:
                print(f"Error processing image {i + 1}: {e}")
                break
        
        print(f"\nExtraction complete!")
        print(f"Successfully extracted {extracted_count} PNG images to '{output_dir}'")
        print(f"Processed {self.cursor} bytes of {self.length} total bytes")

def process_single_file(input_file, output_dir=None):
    """Process a single imageblock file"""
    if not os.path.exists(input_file):
        print(f"Error: File '{input_file}' not found")
        return False
    
    try:
        with open(input_file, 'rb') as f:
            data = f.read()
        
        unpacker = ImageblockUnpacker(data)
        
        # Determine output directory
        if output_dir is None:
            output_dir = Path(input_file).stem + "_extracted"
        else:
            # If output_dir is specified, create subdirectory with filename
            output_dir = os.path.join(output_dir, Path(input_file).stem + "_extracted")
        
        unpacker.unpack(output_dir)
        return True
        
    except Exception as e:
        print(f"Error processing '{input_file}': {e}")
        return False

def process_batch_folder(batch_folder, output_dir=None, extensions=None):
    """Process all imageblock files in a folder"""
    if extensions is None:
        extensions = ['*.bin', '*.dat', '*']  # Default extensions to search for
    
    if not os.path.exists(batch_folder):
        print(f"Error: Batch folder '{batch_folder}' not found")
        return
    
    print(f"Scanning folder: {batch_folder}")
    
    # Find all files matching the extensions
    files_found = []
    for ext in extensions:
        pattern = os.path.join(batch_folder, ext)
        files_found.extend(glob.glob(pattern))
    
    # Remove duplicates and filter out directories
    files_found = [f for f in set(files_found) if os.path.isfile(f)]
    
    if not files_found:
        print(f"No files found in '{batch_folder}' matching extensions: {extensions}")
        return
    
    print(f"Found {len(files_found)} files to process")
    
    successful = 0
    failed = 0
    
    for file_path in sorted(files_found):
        print(f"\n{'='*60}")
        print(f"Processing: {os.path.basename(file_path)}")
        print(f"{'='*60}")
        
        if process_single_file(file_path, output_dir):
            successful += 1
        else:
            failed += 1
    
    print(f"\n{'='*60}")
    print(f"Batch processing complete!")
    print(f"Successfully processed: {successful} files")
    print(f"Failed: {failed} files")
    print(f"{'='*60}")

def main():
    parser = argparse.ArgumentParser(
        description="Extract PNG images from Imageblock binary files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Extract single file to default location
  python imageblock_unpacker.py input.bin
  
  # Extract single file to specific output directory
  python imageblock_unpacker.py input.bin -o /path/to/output
  
  # Batch process all files in a folder
  python imageblock_unpacker.py -b /path/to/imageblocks
  
  # Batch process with custom output directory
  python imageblock_unpacker.py -b /path/to/imageblocks -o /path/to/output
  
  # Batch process with specific file extensions
  python imageblock_unpacker.py -b /path/to/imageblocks -e "*.imageblock" "*.data"
        """
    )
    
    # Main input argument (optional when using batch mode)
    parser.add_argument(
        'input_file',
        nargs='?',
        help='Path to the imageblock binary file to extract'
    )
    
    # Output directory option
    parser.add_argument(
        '-o', '--output',
        help='Output directory (default: creates directory based on input filename)'
    )
    
    # Batch processing option
    parser.add_argument(
        '-b', '--batch',
        help='Process all files in the specified folder'
    )
    
    # File extensions for batch processing
    parser.add_argument(
        '-e', '--extensions',
        nargs='+',
        default=['*.bin', '*.dat', '*'],
        help='File extensions to search for in batch mode (default: *.bin *.dat *)'
    )
    
    # Verbose option
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.batch and not args.input_file:
        parser.error("Either specify an input file or use --batch to process a folder")
    
    if args.batch and args.input_file:
        parser.error("Cannot specify both input file and batch folder")
    
    try:
        if args.batch:
            # Batch processing mode
            process_batch_folder(args.batch, args.output, args.extensions)
        else:
            # Single file processing mode
            process_single_file(args.input_file, args.output)
            
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()