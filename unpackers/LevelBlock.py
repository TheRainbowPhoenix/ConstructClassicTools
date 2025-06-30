#!/usr/bin/env python3
"""
Levelblock Binary Unpacker
Parses Construct Classic LEVELBLOCK data and exports it to JSON.
"""

import struct
import os
import sys
import argparse
from pathlib import Path
import glob
import json

class LevelblockUnpacker:
    def __init__(self, data):
        self.data = data
        self.cursor = 0
        self.length = len(data)

    def _read(self, fmt, size):
        """Generic read method."""
        if self.cursor + size > self.length:
            raise ValueError(f"Unexpected end of data at position {self.cursor}")
        val = struct.unpack(f'< {fmt}', self.data[self.cursor : self.cursor + size])[0]
        self.cursor += size
        return val

    def read_u32(self): return self._read('I', 4)
    def read_s32(self): return self._read('i', 4)
    def read_float(self): return self._read('f', 4)
    def read_u8(self): return self._read('B', 1)
    
    def read_bytes(self, count):
        """Read specified number of bytes and advance cursor."""
        if self.cursor + count > self.length:
            raise ValueError(f"Unexpected end of data at position {self.cursor}")
        value = self.data[self.cursor : self.cursor + count]
        self.cursor += count
        return value

    def read_string(self):
        """Reads a length-prefixed CString."""
        length = self.read_u32()
        # The string is often null-terminated within its length, so we strip that.
        return self.read_bytes(length).rstrip(b'\x00').decode('utf-8', errors='ignore')

    def parse_py_functions(self):
        """Parses a list of Python function definitions."""
        count = self.read_u32()
        funcs = []
        for _ in range(count):
            funcs.append({
                'name': self.read_string(),
                'param_count': self.read_u32()
            })
        return funcs

    def unpack(self):
        """Unpack the entire levelblock and return as a dictionary."""
        print(f"Starting to unpack levelblock (size: {self.length} bytes)")
        
        level_data = {}

        # OBJECT TYPES
        num_object_types = self.read_u32()
        level_data['object_types'] = []
        for _ in range(num_object_types):
            obj = {
                'type_id': self.read_u32(),
                'name': self.read_string(),
                'type_identifier': self.read_u32(),
                'is_global': bool(self.read_u8()),
                'destroy_when': self.read_u32(),
            }
            num_private_vars = self.read_u32()
            obj['private_vars'] = [{'name': self.read_string(), 'type': self.read_u32()} for _ in range(num_private_vars)]
            obj['unknown_data'] = self.read_bytes(16).hex()
            if self.read_u8() == 1:
                obj['python_info'] = {
                    'actions': self.parse_py_functions(),
                    'conditions': self.parse_py_functions(),
                    'expressions': self.parse_py_functions(),
                }
            level_data['object_types'].append(obj)
        print(f"Parsed {num_object_types} object types.")

        # MOVEMENT TYPES
        num_movements = self.read_u32()
        level_data['movements'] = []
        for _ in range(num_movements):
            mov = {
                'object_oid': self.read_u32(),
                'assoc_dll': self.read_u32(),
                'mov_index': self.read_u32(),
                'aux_name': self.read_string(),
            }
            mov_data_size = self.read_u32()
            mov['mov_data'] = self.read_bytes(mov_data_size).hex()
            if self.read_u8() == 1:
                mov['python_info'] = {
                    'actions': self.parse_py_functions(),
                    'conditions': self.parse_py_functions(),
                    'expressions': self.parse_py_functions(),
                }
            level_data['movements'].append(mov)
        print(f"Parsed {num_movements} movement types.")
        
        # TRAITS
        num_traits = self.read_u32()
        level_data['traits'] = []
        for _ in range(num_traits):
            trait = {'name': self.read_string()}
            num_objs = self.read_u32()
            trait['oids'] = [self.read_u32() for _ in range(num_objs)]
            level_data['traits'].append(trait)
        print(f"Parsed {num_traits} traits.")
        
        # FAMILIES
        num_families = self.read_u32()
        level_data['families'] = []
        for _ in range(num_families):
            family = {'name': self.read_string()}
            num_children = self.read_u32()
            family['children_oids'] = [self.read_u32() for _ in range(num_children)]
            num_private_vars = self.read_u32()
            family['private_vars'] = [{'name': self.read_string(), 'type': self.read_u32()} for _ in range(num_private_vars)]
            level_data['families'].append(family)
        print(f"Parsed {num_families} families.")
        
        # CONTAINERS
        num_containers = self.read_u32()
        level_data['containers'] = []
        for _ in range(num_containers):
            num_objs = self.read_u32()
            level_data['containers'].append({'object_oids': [self.read_u32() for _ in range(num_objs)]})
        print(f"Parsed {num_containers} containers.")

        # FRAMES / LAYOUTS
        num_frames = self.read_u32()
        level_data['frames'] = []
        print(f"Found {num_frames} frames/layouts to parse.")
        for i in range(num_frames):
            frame = {
                'width': self.read_u32(), 'height': self.read_u32(), 'name': self.read_string(),
                'bg_color_ref': self.read_u32(), 'unbounded_scrolling': bool(self.read_u8()),
                'use_app_background': bool(self.read_u8()), 'keys': [], 'layers': []
            }
            
            # Frame Keys
            num_keys = self.read_u32()
            for _ in range(num_keys):
                key = {'key': self.read_string(), 'type': self.read_u32()}
                if key['type'] == 0: key['value'] = self.read_u32()
                else: key['value'] = self.read_string()
                frame['keys'].append(key)
            
            # Layers
            num_layers = self.read_u32()
            for _ in range(num_layers):
                layer = {
                    'layer_id': self.read_u32(), 'name': self.read_string(), 'layer_type': self.read_u8(),
                    'color_filter': self.read_u32(), 'opacity_factor': self.read_float(), 'angle': self.read_float(),
                    'scroll_x_factor': self.read_float(), 'scroll_y_factor': self.read_float(),
                    'scroll_x_offset': self.read_float(), 'scroll_y_offset': self.read_float(),
                    'zoom_x_factor': self.read_float(), 'zoom_y_factor': self.read_float(),
                    'zoom_x_offset': self.read_float(), 'zoom_y_offset': self.read_float(),
                    'clear_background': bool(self.read_u8()), 'background_color': self.read_u32(),
                    'force_own_texture': bool(self.read_u8()), 'sampler_mode': self.read_u32(),
                    'enable_3d': bool(self.read_u8()), 'clear_depth_buffer': bool(self.read_u8()),
                    'instances': []
                }
                # Object Instances
                instance_count = self.read_u32()
                for _ in range(instance_count):
                    inst = {'ignored_identifier': self.read_u32(), 'x': self.read_s32(), 'y': self.read_s32(),
                            'width': self.read_u32(), 'height': self.read_u32(), 'angle': self.read_float(),
                            'color_filter': self.read_u32(), 'plugin_id': self.read_u32(), 'instance_id': self.read_u32(),
                            'object_type_id': self.read_u32()}
                    num_vars = self.read_u32()
                    inst['initial_vars'] = [self.read_string() for _ in range(num_vars)]
                    extra_data_size = self.read_u32()
                    inst['extra_data'] = self.read_bytes(extra_data_size).hex()
                    layer['instances'].append(inst)
                frame['layers'].append(layer)

            # Post-layer frame data
            num_img_handles = self.read_u32()
            frame['used_image_handles'] = [self.read_u32() for _ in range(num_img_handles)]
            frame['texture_loading_mode'] = self.read_u32()
            level_data['frames'].append(frame)
            print(f"  Parsed frame {i+1}/{num_frames}: '{frame['name']}' ({len(frame['layers'])} layers)")

        print(f"\nParsing complete!")
        print(f"Processed {self.cursor} bytes of {self.length} total bytes")
        return level_data

def process_single_file(input_file, output_dir=None):
    """Process a single levelblock file."""
    if not os.path.exists(input_file):
        print(f"Error: File '{input_file}' not found", file=sys.stderr)
        return False
    
    try:
        with open(input_file, 'rb') as f:
            data = f.read()
        
        unpacker = LevelblockUnpacker(data)
        parsed_data = unpacker.unpack()
        
        # Determine output directory
        if output_dir is None:
            output_dir = Path(input_file).stem + "_unpacked"
        else:
            output_dir = os.path.join(output_dir, Path(input_file).stem + "_unpacked")

        os.makedirs(output_dir, exist_ok=True)
        
        # Save JSON file
        json_filename = "level_data.json"
        json_filepath = os.path.join(output_dir, json_filename)
        
        with open(json_filepath, 'w', encoding='utf-8') as f:
            json.dump(parsed_data, f, indent=4)
        
        print(f"Successfully saved parsed data to '{json_filepath}'")
        return True
        
    except Exception as e:
        print(f"Error processing '{input_file}': {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return False

def process_batch_folder(batch_folder, output_dir=None, extensions=None):
    """Process all levelblock files in a folder."""
    if extensions is None:
        extensions = ['*.bin', '*.dat', '*']
    
    if not os.path.isdir(batch_folder):
        print(f"Error: Batch folder '{batch_folder}' not found or is not a directory", file=sys.stderr)
        return
    
    print(f"Scanning folder: {batch_folder}")
    
    files_found = [p for ext in extensions for p in Path(batch_folder).glob(ext) if p.is_file()]
    files_found = sorted(list(set(files_found))) # remove duplicates and sort
    
    if not files_found:
        print(f"No files found in '{batch_folder}' matching extensions: {extensions}")
        return
    
    print(f"Found {len(files_found)} files to process.")
    successful, failed = 0, 0
    
    for file_path in files_found:
        print(f"\n{'='*60}\nProcessing: {file_path.name}\n{'='*60}")
        if process_single_file(str(file_path), output_dir):
            successful += 1
        else:
            failed += 1
    
    print(f"\n{'='*60}\nBatch processing complete!")
    print(f"Successfully processed: {successful} files\nFailed: {failed} files\n{'='*60}")

def main():
    parser = argparse.ArgumentParser(
        description="Parse Construct Classic LEVELBLOCK binary files into JSON.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  # Parse a single file to a default location (e.g., 'level1.bin_unpacked/level_data.json')
  python levelblock_unpacker.py level1.bin
  
  # Parse a single file to a specific output directory
  python levelblock_unpacker.py level1.bin -o /path/to/output
  
  # Batch process all files in a folder
  python levelblock_unpacker.py -b /path/to/levels
  
  # Batch process with specific file extensions
  python levelblock_unpacker.py -b /path/to/levels -e "*.level" "*.dat"
        """
    )
    
    parser.add_argument('input_file', nargs='?', help='Path to the LEVELBLOCK binary file to parse.')
    parser.add_argument('-o', '--output', help='Output directory for parsed data.')
    parser.add_argument('-b', '--batch', help='Process all files in the specified folder.')
    parser.add_argument('-e', '--extensions', nargs='+', default=['*.bin', '*.dat', '*'], help='File extensions for batch mode.')
    
    args = parser.parse_args()
    
    if not args.batch and not args.input_file:
        parser.error("Either specify an input file or use --batch to process a folder.")
    if args.batch and args.input_file:
        parser.error("Cannot specify both an input file and a batch folder.")
    
    try:
        if args.batch:
            process_batch_folder(args.batch, args.output, args.extensions)
        else:
            process_single_file(args.input_file, args.output)
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()