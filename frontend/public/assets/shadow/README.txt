SHADOW Companion Assets V2 - CLEANED
Bleed/crop artifacts removed from original asset pack (81 files had stray edge
content from neighboring sprite-sheet cells or leftover label-plate slivers).

Cleaning applied:
1. Trimmed ~7% margin from each edge (removes thin neighbor-cell bleed)
2. Kept only the largest connected non-transparent region per image (removes any
   remaining disconnected fragments, e.g. leftover label-plate corners)
3. Cropped tightly to content bounding box (+2px padding)

Folders: full_body, face, body_parts, face_parts, effects_ui
Master sheet included for visual reference only (not cleaned, since it's the full
composite reference sheet, not individual crops).

Use these cleaned assets to replace the original (uncleaned) asset folders in the
project.
