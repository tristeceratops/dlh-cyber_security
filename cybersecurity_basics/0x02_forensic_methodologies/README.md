# Explanations

This folder contains short-answer files for forensic exercises. The commands below show common `exiftool` usage to inspect and manipulate file metadata during investigations.

Examples:

- Print all metadata for a file:

	`exiftool image.jpg`

- Show short tag names and group names:

	`exiftool -s -G image.jpg`

- Recursively list metadata for all JPEGs in a directory:

	`exiftool -r -ext jpg /path/to/dir`

- Extract a specific tag (e.g., DateTimeOriginal):

	`exiftool -DateTimeOriginal image.jpg`

- Copy metadata from one file to another:

	`exiftool -tagsFromFile src.jpg -all:all dest.jpg`

- Remove all metadata from a file (write changes to a new file):

	`exiftool -all= -o cleaned.jpg image.jpg`

- Overwrite original file when removing metadata (use with caution):

	`exiftool -overwrite_original -all= image.jpg`

- Write or modify a tag (set GPS, date, etc.):

	`exiftool -GPSLatitude=12.34 -GPSLongitude=56.78 image.jpg`

- Batch modify files (change DateTime on all JPGs, recursively):

	`exiftool -r -ext jpg -DateTimeOriginal="2020:01:01 00:00:00" /path/to/dir`

Notes:

- Use `-overwrite_original` to avoid creating `_original` backup files.
- `-r` processes directories recursively; `-ext` filters by extension.
- Always work on copies when altering evidence files to preserve originals.