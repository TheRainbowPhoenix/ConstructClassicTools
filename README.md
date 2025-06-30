# Construct Classic Extraction Tools

Quick toolkit for extracting and analyzing Construct Classic resources from executables.

## Quick Start

### Prerequisites
```bash
pip install pefile
```
- **Python 3.6+** required
- **ImHex** (optional, for binary analysis)

### Basic Usage

#### Extract All Resources from EXE
```bash
python unpackers/unpackExe.py game.exe
```

#### Extract PNG Images from Imageblock
```bash
python unpackers/ImageBlock.py extracted_resources/game/IMAGEBLOCK/id_999.bin
```


## Tools Overview

### Game Resource Extractor (`unpackExe.py`)
Extracts all resources from Windows executables/DLLs.

**Quick Examples:**
```bash
# Basic extraction (uppercase types only)
python unpackers/unpackExe.py game.exe

# Extract everything to custom folder
python unpackers/unpackExe.py game.exe -o my_resources

# Batch process all EXEs in folder
python unpackers/unpackExe.py -b /path/to/games --recursive

# Extract specific resource types
python unpackers/unpackExe.py game.exe --types IMAGEBLOCK DLLBLOCK FILES

# Include mixed-case resource types
python unpackers/unpackExe.py game.exe --all-types
```

**Output Structure:**
```
extracted_resources/
└─ game_exe/
   ├─ IMAGEBLOCK/     # Binary image data
   ├─ DLLBLOCK/       # DLL files
   ├─ FILES/          # WAV/audio files
   └─ OTHER_TYPES/    # Various resource types
```

### Imageblock Unpacker (`ImageBlock.py`)
Extracts PNG images from imageblock binary files.

**Quick Examples:**
```bash
# Extract single imageblock
python unpackers/ImageBlock.py imageblock.bin

# Extract to custom folder
python unpackers/ImageBlock.py imageblock.bin -o extracted_images

# Batch process all imageblocks in folder
python unpackers/ImageBlock.py -b /path/to/imageblocks

# Process specific file extensions
python unpackers/ImageBlock.py -b /folder -e "*.img" "*.data"
```

**Output:**
```
imageblock_extracted/
├─ image_0001.png          # Extracted PNG files
├─ image_0001_metadata.txt # Hotspot/action point data
├─ image_0002.png
└─ image_0002_metadata.txt
```

### ImHex Pattern
For manual binary analysis in ImHex hex editor.

Supports:
- `ImageBlock`
- `LevelBlock`

**Usage:**
1. Open block file in ImHex (imageblock/id_998.bin)
2. Load pattern: `File → Import → Pattern File`
3. Select your pattern (`patterns/ImageBlock.hexpat`)
4. Analyze binary structure visually

## Typical Workflow

### Complete Game Resource Extraction
```bash
# 1. Extract all resources from game executable
python unpackers/unpackExe.py game.exe -o game_resources

# 2. Find and extract imageblocks
python unpackers/ImageBlock.py -b game_resources/game_exe/IMAGEBLOCK -o game_images

```

### Batch Processing Multiple Games
```bash
# Extract from all games in directory
python unpackers/unpackExe.py -b /path/to/games --recursive -o all_game_resources

# Process all found imageblocks
python unpackers/ImageBlock.py -b all_game_resources --recursive -o all_images
```

## Tips

- Use `-v` for verbose output when debugging
- Use `-q` for quiet mode in automation scripts
- Check the generated metadata files for image positioning data
- ImHex patterns help understand the binary format structure
- Batch processing is much faster than individual file processing