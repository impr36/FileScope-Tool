from Imports import*  
from magic_db import magic_db

# ----------- CONDITIONAL ANALYSIS LOGIC PER FILE TYPE -------------

def magic_number_check(file_path):
        try:
            mime = magic.Magic(mime=True)
            file_type = mime.from_file(file_path)
        except Exception:
            file_type = "UNKNOWN"

        extension = os.path.splitext(file_path)[1].lower() or "None"
        with open(file_path, "rb") as f:
            file_header = f.read(2048)
            detected_type = "Unknown"

            # Check known BOMs/text first
            if file_header.startswith(b"\xEF\xBB\xBF"):
                detected_type = "UTF-8 BOM (Text)"
            elif file_header.startswith(b"\xFF\xFE"):
                detected_type = "UTF-16LE BOM (Text)"
            elif file_header.startswith(b"\xFE\xFF"):
                detected_type = "UTF-16BE BOM (Text)"
            elif file_header.startswith(b"\x52\x49\x46\x46") and file_header[8:12] == b"WEBP":
                detected_type = "WebP"
            elif file_header.endswith(b"\x49\x45\x4E\x44\xAE\x42\x60\x82"):
                detected_type = "PNG (Confirmed by IEND)"
            else:
                sorted_magic_db = sorted(magic_db.items(), key=lambda x: len(x[0]), reverse=True)
                for signature, filetype in sorted_magic_db:
                    if file_header.startswith(signature):
                        detected_type = filetype
                        break

        declared_type = file_type.split("/")[-1].upper() if file_type != "UNKNOWN" else "UNKNOWN"
        status = "SPOOFED" if detected_type != declared_type and detected_type != "Unknown" else "Valid"

        embedded_objects = {}
        metadata = {}

        if detected_type == "PDF":
            try:
                with open(file_path, "rb") as f:
                    pdf = PdfReader(f)
                    for page in pdf.pages:
                        if "/XObject" in page["/Resources"]:
                            for obj in page["/Resources"]["/XObject"].values():
                                if obj.get("/Subtype") == "/Image":
                                    embedded_objects["Images"] = embedded_objects.get("Images", 0) + 1
                                elif "/JavaScript" in obj:
                                    embedded_objects["JavaScript"] = True
                        if "/EmbeddedFile" in page:
                            embedded_objects["Executables"] = any("exe" in str(obj) for obj in page["/EmbeddedFile"].values())
            except Exception as e:
                embedded_objects["Error"] = f"Failed to parse PDF: {str(e)}"

        elif detected_type.startswith("ZIP"):
            try:
                import zipfile
                with zipfile.ZipFile(file_path, 'r') as z:
                    file_list = z.namelist()
                    embedded_objects["Files in ZIP"] = file_list
                    embedded_objects["Count"] = len(file_list)
            except Exception as e:
                embedded_objects["Error"] = f"Failed to read ZIP: {str(e)}"

        elif detected_type.startswith("MP3"):
            try:
                import mutagen
                from mutagen.mp3 import MP3
                audio = MP3(file_path)
                metadata = {
                    "Length": round(audio.info.length, 2),
                    "Bitrate": audio.info.bitrate,
                    "SampleRate": audio.info.sample_rate,
                    "Mode": audio.info.mode,
                }
            except Exception as e:
                metadata["Error"] = f"MP3 parsing failed: {str(e)}"

        elif detected_type == "JPEG (JFIF/Exif)":
            try:
                from PIL import Image
                from PIL.ExifTags import TAGS
                image = Image.open(file_path)
                exif_data = image._getexif()
                if exif_data:
                    metadata["EXIF"] = {
                        TAGS.get(tag): value for tag, value in exif_data.items() if tag in TAGS
                    }
            except Exception as e:
                metadata["Error"] = f"JPEG EXIF parsing failed: {str(e)}"

        elif detected_type in ["ELF", "DOS MZ (EXE)"]:
            try:
                with open(file_path, "rb") as f:
                    raw = f.read(64)
                    metadata["Header (Hex)"] = raw.hex()
            except Exception as e:
                metadata["Error"] = str(e)

        elif detected_type == "SQLite":
            try:
                import sqlite3
                conn = sqlite3.connect(file_path)
                cursor = conn.cursor()
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
                tables = cursor.fetchall()
                metadata["Tables"] = [t[0] for t in tables]
                conn.close()
            except Exception as e:
                metadata["Error"] = f"SQLite parsing failed: {str(e)}"

        elif detected_type == "JSON":
            try:
                import json
                with open(file_path, 'r', encoding='utf-8') as f:
                    parsed = json.load(f)
                    metadata["Keys"] = list(parsed.keys()) if isinstance(parsed, dict) else "Non-dict JSON"
            except Exception as e:
                metadata["Error"] = f"JSON parsing failed: {str(e)}"

        elif detected_type == "Java Class":
            try:
                metadata["Java Class"] = "Bytecode file - requires decompilation for details"
            except:
                pass

        elif detected_type == "DICOM":
            try:
                import pydicom
                dcm = pydicom.dcmread(file_path)
                metadata = {
                    "PatientID": getattr(dcm, "PatientID", "N/A"),
                    "StudyDate": getattr(dcm, "StudyDate", "N/A"),
                    "Modality": getattr(dcm, "Modality", "N/A"),
                    "Rows": getattr(dcm, "Rows", "N/A"),
                    "Columns": getattr(dcm, "Columns", "N/A")
                }
            except Exception as e:
                metadata["Error"] = f"DICOM parsing failed: {str(e)}"

        elif detected_type == "MIDI":
            try:
                from mido import MidiFile
                midi = MidiFile(file_path)
                metadata = {
                    "Tracks": len(midi.tracks),
                    "TicksPerBeat": midi.ticks_per_beat,
                    "Length": midi.length
                }
            except Exception as e:
                metadata["Error"] = f"MIDI parsing failed: {str(e)}"

        elif detected_type.startswith("TAR") or detected_type == "Z/TGZ":
            try:
                import tarfile
                with tarfile.open(file_path, 'r:*') as t:
                    file_list = t.getnames()
                    embedded_objects["Files in TAR"] = file_list
                    embedded_objects["Count"] = len(file_list)
            except Exception as e:
                embedded_objects["Error"] = f"TAR parsing failed: {str(e)}"

        elif detected_type == "7-Zip":
            try:
                from py7zr import SevenZipFile
                with SevenZipFile(file_path, 'r') as z:
                    file_list = z.getnames()
                    embedded_objects["Files in 7z"] = file_list
                    embedded_objects["Count"] = len(file_list)
            except Exception as e:
                embedded_objects["Error"] = f"7z parsing failed: {str(e)}"

        elif detected_type == "XML":
            try:
                import xml.etree.ElementTree as ET
                tree = ET.parse(file_path)
                root = tree.getroot()
                metadata = {
                    "Root Tag": root.tag,
                    "Attributes": root.attrib,
                    "Child Elements": len(root)
                }
            except Exception as e:
                metadata["Error"] = f"XML parsing failed: {str(e)}"

        elif detected_type.startswith("RAR"):
            try:
                from rarfile import RarFile
                with RarFile(file_path, 'r') as r:
                    file_list = r.namelist()
                    embedded_objects["Files in RAR"] = file_list
                    embedded_objects["Count"] = len(file_list)
            except Exception as e:
                embedded_objects["Error"] = f"RAR parsing failed: {str(e)}"

        elif detected_type == "ISO9660":
            try:
                from pycdlib import PyCdlib
                iso = PyCdlib()
                iso.open(file_path)
                files = []
                for child in iso.list_children(iso_path='/'):
                    if child.is_file():
                        files.append(child.file_identifier.decode())
                embedded_objects["Files in ISO"] = files
                embedded_objects["Count"] = len(files)
                iso.close()
            except Exception as e:
                embedded_objects["Error"] = f"ISO parsing failed: {str(e)}"

        elif detected_type == "GIF87a" or detected_type == "GIF89a":
            try:
                from PIL import Image
                gif = Image.open(file_path)
                metadata = {
                    "Frame Count": gif.n_frames,
                    "Mode": gif.mode,
                    "Size": gif.size
                }
            except Exception as e:
                metadata["Error"] = f"GIF parsing failed: {str(e)}"

        elif detected_type == "BMP":
            try:
                from PIL import Image
                bmp = Image.open(file_path)
                metadata = {
                    "Size": bmp.size,
                    "Mode": bmp.mode,
                    "Format": bmp.format
                }
            except Exception as e:
                metadata["Error"] = f"BMP parsing failed: {str(e)}"

        elif detected_type == "FLAC":
            try:
                import mutagen
                from mutagen.flac import FLAC
                audio = FLAC(file_path)
                metadata = {
                    "Length": round(audio.info.length, 2),
                    "SampleRate": audio.info.sample_rate,
                    "Channels": audio.info.channels
                }
            except Exception as e:
                metadata["Error"] = f"FLAC parsing failed: {str(e)}"

        elif detected_type == "Ogg":
            try:
                import mutagen
                from mutagen.oggvorbis import OggVorbis
                ogg = OggVorbis(file_path)
                metadata = {
                    "Length": round(ogg.info.length, 2),
                    "Bitrate": ogg.info.bitrate,
                    "Channels": ogg.info.channels
                }
            except Exception as e:
                metadata["Error"] = f"Ogg parsing failed: {str(e)}"

        elif detected_type in ["TTF Font", "OTF Font"]:
            try:
                from fontTools.ttLib import TTFont
                font = TTFont(file_path)
                metadata = {
                    "Font Name": font["name"].getName(1, 3, 1).toUnicode() if font.get("name") else "N/A",
                    "Font Family": font["name"].getName(4, 3, 1).toUnicode() if font.get("name") else "N/A"
                }
            except Exception as e:
                metadata["Error"] = f"Font parsing failed: {str(e)}"

        elif detected_type == "WEBM/MKV/MKA":
            try:
                import pymediainfo
                media_info = pymediainfo.MediaInfo.parse(file_path)
                for track in media_info.tracks:
                    if track.track_type == "Video":
                        metadata["Video"] = {
                            "Duration": track.duration,
                            "Format": track.format,
                            "Resolution": f"{track.width}x{track.height}"
                        }
                    elif track.track_type == "Audio":
                        metadata["Audio"] = {
                            "Format": track.format,
                            "Channels": track.channel_s
                        }
            except Exception as e:
                metadata["Error"] = f"WEBM/MKV/MKA parsing failed: {str(e)}"

        elif detected_type in ["MP4/M4A/M4V"]:
            try:
                import pymediainfo
                media_info = pymediainfo.MediaInfo.parse(file_path)
                for track in media_info.tracks:
                    if track.track_type == "Video":
                        metadata["Video"] = {
                            "Duration": track.duration,
                            "Format": track.format,
                            "Resolution": f"{track.width}x{track.height}"
                        }
                    elif track.track_type == "Audio":
                        metadata["Audio"] = {
                            "Format": track.format,
                            "Channels": track.channel_s
                        }
            except Exception as e:
                metadata["Error"] = f"MP4/M4A/M4V parsing failed: {str(e)}"

        elif detected_type == "RTF":
            try:
                from striprtf.striprtf import rtf_to_text
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    rtf_content = f.read()
                    text = rtf_to_text(rtf_content)
                    metadata = {
                        "Text Length": len(text),
                        "First 100 Chars": text[:100]
                    }
            except Exception as e:
                metadata["Error"] = f"RTF parsing failed: {str(e)}"

        elif detected_type == "Windows Registry":
            try:
                import winreg
                metadata["Note"] = "Windows Registry file - requires specialized tools for detailed parsing"
            except Exception as e:
                metadata["Error"] = f"Registry parsing failed: {str(e)}"

        elif detected_type == "DEB":
            try:
                import tarfile
                with tarfile.open(file_path, 'r:*') as deb:
                    file_list = deb.getnames()
                    embedded_objects["Files in DEB"] = file_list
                    embedded_objects["Count"] = len(file_list)
            except Exception as e:
                embedded_objects["Error"] = f"DEB parsing failed: {str(e)}"

        elif detected_type == "RPM":
            try:
                import rpm # type: ignore
                ts = rpm.TransactionSet()
                with open(file_path, 'rb') as f:
                    hdr = ts.hdrFromFdno(f.fileno())
                    metadata = {
                        "Name": hdr[rpm.RPMTAG_NAME],
                        "Version": hdr[rpm.RPMTAG_VERSION],
                        "Release": hdr[rpm.RPMTAG_RELEASE]
                    }
            except Exception as e:
                metadata["Error"] = f"RPM parsing failed: {str(e)}"

        elif detected_type == "GZIP":
            try:
                import gzip
                with gzip.open(file_path, 'rb') as g:
                    content = g.read(2048)  # Read first 2048 bytes
                    metadata["Compressed Size"] = len(content)
            except Exception as e:
                embedded_objects["Error"] = f"GZIP parsing failed: {str(e)}"

 # ----------- END CONDITIONAL ANALYSIS LOGIC -------------