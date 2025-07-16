import matplotlib.pyplot as plt
import magic
import math
import os
import datetime
import numpy as np
from collections import Counter
import struct
from io import BytesIO
from PyPDF2 import PdfReader
import exiftool
import yara
import hashlib
from magic_db import magic_db

class FileAnalyzer:
    def __init__(self):
        self.analysis_results = {}
        self.magic_db ={
            b"\xEF\xBB\xBF": "UTF-8 BOM (Text)", 
            b"\xFF\xFE": "UTF-16LE BOM (Text)",
            b"\xFE\xFF": "UTF-16BE BOM (Text)",
            b"\x23\x21": "Shebang Script",
            b"\xFF\xD8\xFF\xDB": "JPEG (JFIF/Exif)",
            b"\x89\x50\x4E\x47\x0D\x0A\x1A\x0A": "PNG",
            b"\x42\x4D": "BMP",
            b"\x47\x49\x46\x38\x37\x61": "GIF87a",
            b"\x47\x49\x46\x38\x39\x61": "GIF89a",
            b"\x25\x50\x44\x46\x2D": "PDF",
            b"\x50\x4B\x03\x04": "ZIP/OOXML",
            b"\x50\x4B\x05\x06": "ZIP (empty)",
            b"\x50\x4B\x07\x08": "ZIP (spanned)",
            b"\x7F\x45\x4C\x46": "ELF",
            b"\x4D\x5A": "DOS MZ (EXE)",
            b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1": "MS Office (DOC/XLS/PPT old)",
            b"\x52\x49\x46\x46": "RIFF (WAV/AVI)",
            b"\xFF\xFB": "MP3 (No ID3)",
            b"\xFF\xF3": "MP3 (No ID3)",
            b"\xFF\xF2": "MP3 (No ID3)",
            b"\x49\x44\x33": "MP3 (ID3v2)",
            b"\x4D\x54\x68\x64": "MIDI",
            b"\x52\x61\x72\x21\x1A\x07\x00": "RAR v1.5",
            b"\x52\x61\x72\x21\x1A\x07\x01\x00": "RAR v5.0",
            b"\x1F\x8B": "GZIP",
            b"\x37\x7A\xBC\xAF\x27\x1C": "7-Zip",
            b"\x4D\x53\x43\x46": "CAB",
            b"\xEF\xBB\xBF": "UTF-8 BOM (Text)",
            b"\xFF\xFE": "UTF-16LE BOM (Text)",
            b"\xFE\xFF": "UTF-16BE BOM (Text)",
            b"\x3C\x3F\x78\x6D\x6C\x20": "XML",
            b"\x7B\x5C\x72\x74\x66\x31": "RTF",
            b"\x4F\x67\x67\x53": "Ogg",
            b"\x41\x56\x49\x20": "AVI",
            b"\x46\x4C\x56": "FLV",
            b"\x43\x57\x53": "SWF (Compressed)",
            b"\x46\x57\x53": "SWF (Uncompressed)",
            b"\x4F\x54\x54\x4F": "OTF Font",
            b"\x00\x01\x00\x00\x00": "TTF Font",
            b"\x49\x73\x5A\x21": "ISZ",
            b"\x44\x41\x41": "DAA",
            b"\x4C\x66\x4C\x65": "EVT",
            b"\x45\x6C\x66\x46\x69\x6C\x65": "EVTX",
            b"\x72\x65\x67\x66": "Windows Registry",
            b"\x21\x42\x44\x4E": "PST",
            b"\x4C\x5A\x49\x50": "LZIP",
            b"\x30\x37\x30\x37\x30\x37": "CPIO",
            b"\x49\x49\x2A\x00": "TIFF (LE)",
            b"\x4D\x4D\x00\x2A": "TIFF (BE)",
            b"\x49\x49\x2B\x00": "BigTIFF (LE)",
            b"\x4D\x4D\x00\x2B": "BigTIFF (BE)",
            b"\x44\x49\x43\x4D": "DICOM",
            b"\x66\x4C\x61\x43": "FLAC",
            b"\x2E\x73\x6E\x64": "AU/SND",
            b"\x25\x21\x50\x53": "PostScript",
            b"\x3C\x3C\x3C\x20": "VDI (Oracle)",
            b"\x63\x6F\x6E\x65\x63\x74\x69\x78": "VHD",
            b"\x76\x68\x64\x78\x66\x69\x6C\x65": "VHDX",
            b"\xAA\xAA\xAA\xAA": "Crowdstrike SYS",
            b"\x43\x43\x30\x30\x31": "ISO9660",
            b"\x4D\x53\x48\x7C": "HL7 (MSH)",
            b"\x42\x53\x48\x7C": "HL7 (BSH)",
            b"\x52\x49\x46\x46": "WebP (WEBP)",  # Special case: needs 8 bytes offset to confirm 'WEBP'
            b"\x00\x00\x00\x14\x66\x74\x79\x70\x69\x73\x6F\x6D": "MP4/M4A/M4V",
            b"\x46\x72\x6F\x6D\x48\x65\x61\x64": "PSD",
            b"\x53\x51\x4C\x69\x74\x65\x20\x66\x6F\x72\x6D\x61\x74\x20\x33": "SQLite",
            b"\x28\x66\x61\x74\x20\x63\x6F\x64\x65\x29": "Java Class",
            b"\xCA\xFE\xBA\xBE": "Java Class",
            b"\x43\x61\x66\x66\x65\x69\x6E\x65": "Java Class (Variant)",
            b"\x6B\x64\x6D\x66": "KDM",
            b"\x44\x45\x41\x44\x42\x45\x45\x46": "DEB",
            b"\x2E\x72\x70\x6D": "RPM",
            b"\xF0\xED\xF0\xED": "IMG (Apple)",
            b"\x41\x52\x43\x01": "ARC (FreeArc)",
            b"\x41\x52\x43\x00": "ARC (FreeArc Alt)",
            b"\x1A\x45\xDF\xA3": "WEBM/MKV/MKA",
            b"\xF7\xFF\xFF\xFF\xC8\xFF\xFF\xFF\xF6\xFF\xFF\xFF": "DMG (Apple)",
            b"\x00\x61\x73\x6D": "WASM",
            b"\x45\x58\x54\x33": "EXT3/EXT4",
            b"\x00" * 16: "BIN/DAT (Zero Filled)",
            b"\x00\x00\x01\x00": "CUR/ICO",
            b"\x41\x43\x31\x30": "DWG/DXF",
            b"\x3B\x44\x57\x47\x44\x69\x73\x6B\x46\x69\x6C\x65": "DWG (Alt)",
            b"\x30\x30\x30\x30\x4C\x48\x53": "LZH/LHA",
            b"\x5A\x4F\x4F": "ZOO",
            b"\x41\x44\x49\x46": "ADF",
            b"\x4D\x53\x4A\x45\x54": "MDB",
            b"\x53\x71\x4C\x69\x74\x65\x20\x66\x6F\x72\x6D\x61\x74\x20\x33": "SQLite (Alt)",
            b"\x00\x00\x00\x0C\x6A\x46\x54\x59\x50\x6D\x6A\x70\x32": "JPEG 2000 (JP2)",
            b"\x4C\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46": "LN",
            b"\x00\x00\x01\xBA": "MPG/MPEG/DAT",
            b"\x00\x00\x01\xB3": "MPG/MPEG",
            b"\x00\x00\x01\xB6": "MPG/MPEG",
            b"\x00\x00\x01\xB7": "MPG/MPEG",
            b"\x00\x00\x01\xB8": "MPG/MPEG",
            b"\x00\x00\x01\xB9": "MPG/MPEG",
            b"\x00\x00\x01\xBC": "MPG/MPEG",
            b"\x00\x00\x01\xBE": "MPG/MPEG",
            b"\x30\x26\xB2\x75\x8E\x66\xCF\x11\xA6\xD9\x00\xAA\x00\x62\xCE\x6C": "WMV/WMA/ASF",
            b"\x1B\x4C\x00\x00": "SYS/COM",
            b"\x1F\x9D": "Z/TGZ",
            b"\x04\x22\x4D\x18": "MDF",
            b"\x53\x49\x4D\x50\x4C\x45": "SIMPLE TEXT",
            b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1": "MSI (Also DOC/XLS)",
            b"\x30\x82": "PEM/CER/DER (X.509)",
            b"\x20\x20\x20\x20": "TXT (Spaces)",
            b"\x7B\x22": "JSON",
            b"\x4C\x69\x73\x74": "Shell Script (LIST)",
            b"\x47\x4B\x53\x4D": "GKS (Graphics Kernel System)",
            b"\x01\xDA": "IRIS RGB",
            b"\xF1\x00\x40\xBB": "ITC (CMU WM)",
            b"\xFF\xD8\xFF\xE0": "JPEG (JFIF)",  
            b"\x49\x49\x4E\x31": "NIFF (Navy TIFF)",
            b"\x56\x49\x45\x57": "PM Format",
            b"\x59\xA6\x6A\x95": "Sun Rasterfile",
            b"\x67\x69\x6D\x70\x20\x78\x63\x66\x20\x76": "XCF (GIMP)",
            b"\x23\x46\x49\x47": "XFig Format",
            b"\x2F\x2A\x20\x58\x50\x4D\x20\x2A\x2F": "XPM (X PixMap)",
            b"\x42\x5A": "BZIP",
            b"\x1F\x9D": "Compress (.Z)", 
            b"\x99\x00": "PGP Public Ring",
            b"\x95\x01": "PGP Security Ring",
            b"\x95\x00": "PGP Security Ring (Alt)",
            b"\xA6\x00": "PGP Encrypted Data",
        }

    def analyze(self, file_path):
        self.analysis_results = {}
        try:
            self.file_metadata(file_path)
            self.magic_number_check(file_path)
            self.entropy_analysis(file_path)
            self.header_spoof_check(file_path)
            self.byte_pattern_analysis(file_path)
            self.structure_validation(file_path)
            self.pe_header_analysis(file_path)
            self.static_analysis(file_path)
            self.calculate_detection(file_path)
            self.calculate_risk_score()
            self.compute_hashes(file_path)
        except Exception as e:
            self.analysis_results = {"error": f"Analysis failed: {str(e)}"}
        return self.analysis_results

    def file_metadata(self, file_path):
        stat_info = os.stat(file_path)
        metadata = {
            'creation_time': datetime.datetime.fromtimestamp(stat_info.st_ctime).strftime('%Y-%m-%d %H:%M IST'),
            'modification_time': datetime.datetime.fromtimestamp(stat_info.st_mtime).strftime('%Y-%m-%d %H:%M IST'),
            'access_time': datetime.datetime.fromtimestamp(stat_info.st_atime).strftime('%Y-%m-%d %H:%M IST'),
        }
        self.analysis_results['metadata'] = metadata

    def compute_hashes(self, file_path):
        hashes = {}
        try:
            with open(file_path, "rb") as f:
                content = f.read()
                hashes['md5'] = hashlib.md5(content).hexdigest()
                hashes['sha1'] = hashlib.sha1(content).hexdigest()
                hashes['sha256'] = hashlib.sha256(content).hexdigest()
        except Exception:
            hashes = {'md5': 'N/A', 'sha1': 'N/A', 'sha256': 'N/A'}
        self.analysis_results['hashes'] = hashes

    def magic_number_check(self, file_path):
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
                sorted_magic_db = sorted(self.magic_db.items(), key=lambda x: len(x[0]), reverse=True)
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
    
        self.analysis_results["magic"] = {
            "Detected Type": detected_type,
            "Declared Type": declared_type,
            "Status": status,
            "Extension": extension,
            "Embedded Objects": embedded_objects,
            "Metadata": metadata
        }

    def entropy_analysis(self, file_path):
        chunk_size = 256
        entropies = []
        total_bytes = 0
        byte_counts_total = Counter()

        try:
            with open(file_path, "rb") as f:
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    total_bytes += len(chunk)
                    byte_counts = Counter(chunk)
                    byte_counts_total.update(byte_counts)
                    length = len(chunk)
                    if length > 0:
                        entropy = -sum((count / length) * math.log2(count / length) for count in byte_counts.values() if count > 0)
                        entropies.append(round(entropy, 2))

            overall_entropy = 0
            if total_bytes > 0:
                overall_entropy = -sum((count / total_bytes) * math.log2(count / total_bytes) for count in byte_counts_total.values() if count > 0)

            detected_type = self.analysis_results["magic"]["Detected Type"]
            entropy_thresholds = {"PDF": 7.5, "EXE": 8.0, "JPEG": 7.8, "PNG": 7.8}
            threshold = entropy_thresholds.get(detected_type, 7.5)

            entropy_variance = np.var(entropies) if entropies else 0
            anomaly_detected = entropy_variance > 0.5 or any(e > threshold + 0.5 for e in entropies)

            lsb_suspicious = anomaly_detected and detected_type in ["PNG", "JPEG"]

            entropy_stats = {
                "Mean Entropy": round(np.mean(entropies), 2) if entropies else 0,
                "Overall Entropy": round(overall_entropy, 2),
                "LSB Check": "Hidden bits suspected" if lsb_suspicious else "No hidden bits detected",
                "Anomaly Detected": "Yes" if anomaly_detected else "No"
            }

            self.analysis_results["entropy"] = entropy_stats
            self.analysis_results["entropy_chunks"] = entropies[:150]
        except Exception:
            self.analysis_results["entropy"] = {
                "Mean Entropy": 0,
                "Overall Entropy": 0,
                "LSB Check": "N/A",
                "Anomaly Detected": "N/A"
            }
            self.analysis_results["entropy_chunks"] = []

    def header_spoof_check(self, file_path):
        try:
            with open(file_path, "rb") as f:
                header = f.read(512)

            matched_type = "Unknown"
            matched_sig = None

            # Match against magic_db
            for sig, filetype in self.magic_db.items():
                if header.startswith(sig):
                    matched_type = filetype
                    matched_sig = sig
                    break

            # Extract declared type
            metadata = self.analysis_results.get("magic", {}).get("Metadata", {})
            declared_type = metadata.get("FileType", "UNKNOWN")
            mime_type = self.analysis_results.get("magic", {}).get("Detected Type", "UNKNOWN")

            spoof_detected = False
            details = []

            # 1. PE Files (.exe/.dll)
            if matched_type in ["DOS MZ (EXE)", "SYS/COM"]:
                if header[:2] == b"MZ":
                    try:
                        e_lfanew = struct.unpack("<L", header[60:64])[0]
                        if header[e_lfanew:e_lfanew+4] == b"PE\0\0":
                            details.append("Valid PE header found")
                            if "EXE" not in declared_type and "DLL" not in declared_type and "SYS" not in declared_type:
                                spoof_detected = True
                        else:
                            details.append("Invalid PE structure")
                            spoof_detected = True
                    except:
                        details.append("PE header parsing failed")
                        spoof_detected = True
                elif header[:2] == b"\x1B\x4C":
                    details.append("Valid SYS/COM header found")
                else:
                    details.append("Invalid SYS/COM structure")
                    spoof_detected = True

            # 2. PDF
            elif matched_type.startswith("PDF"):
                if b"%PDF-" in header[:8]:
                    details.append("Valid PDF header found")
                else:
                    details.append("Invalid PDF structure")
                    spoof_detected = True

            # 3. ZIP-based formats (ZIP, DOCX, PPTX, etc.)
            elif matched_type.startswith("ZIP"):
                if header[:4] in [b'PK\x03\x04', b'PK\x05\x06', b'PK\x07\x08']:
                    details.append("Valid ZIP structure")
                else:
                    details.append("Invalid ZIP structure")
                    spoof_detected = True

            # 4. PNG
            elif matched_type == "PNG":
                if header.startswith(b"\x89PNG\r\n\x1a\n"):
                    details.append("Valid PNG header")
                else:
                    details.append("Invalid PNG format")
                    spoof_detected = True

            # 5. JPEG
            elif matched_type.startswith("JPEG") or matched_type == "NIFF (Navy TIFF)":
                if header[:3] == b"\xFF\xD8\xFF" or header[:4] == b"\x49\x49\x4E\x31":
                    details.append("Valid JPEG/NIFF start marker")
                else:
                    details.append("Invalid JPEG/NIFF structure")
                    spoof_detected = True

            # 6. MP3
            elif matched_type.startswith("MP3"):
                if header[:3] in [b'ID3', b'\xFF\xFB', b'\xFF\xF3', b'\xFF\xF2']:
                    details.append("Valid MP3 format")
                else:
                    details.append("Invalid MP3 structure")
                    spoof_detected = True

            # 7. RAR
            elif "RAR" in matched_type:
                if header.startswith(b"Rar!") or header.startswith(b"\x52\x61\x72\x21\x1A\x07"):
                    details.append("Valid RAR structure")
                else:
                    details.append("Invalid RAR header")
                    spoof_detected = True

            # 8. ELF
            elif matched_type == "ELF":
                if header[:4] == b"\x7FELF":
                    details.append("Valid ELF file")
                else:
                    details.append("Invalid ELF header")
                    spoof_detected = True

            # 9. BMP
            elif matched_type == "BMP":
                if header[:2] == b"BM":
                    details.append("Valid BMP file")
                else:
                    details.append("Invalid BMP header")
                    spoof_detected = True

            # 10. JSON
            elif matched_type == "JSON":
                if header.strip().startswith(b'{'):
                    details.append("Likely valid JSON")
                else:
                    details.append("Does not start like JSON")
                    spoof_detected = True

            # 11. XML
            elif matched_type == "XML":
                if header.strip().startswith(b"<?xml"):
                    details.append("Likely valid XML")
                else:
                    details.append("Does not start like XML")
                    spoof_detected = True

            # 12. UTF-encoded Text
            elif matched_type in ["UTF-8 BOM (Text)", "UTF-16LE BOM (Text)", "UTF-16BE BOM (Text)"]:
                if header.startswith(b"\xEF\xBB\xBF") or header.startswith(b"\xFF\xFE") or header.startswith(b"\xFE\xFF"):
                    details.append(f"Valid {matched_type} header")
                else:
                    details.append(f"Invalid {matched_type} structure")
                    spoof_detected = True

            # 13. GIF
            elif matched_type in ["GIF87a", "GIF89a"]:
                if header.startswith(b"GIF87a") or header.startswith(b"GIF89a"):
                    details.append("Valid GIF header")
                else:
                    details.append("Invalid GIF structure")
                    spoof_detected = True

            # 14. MS Office (DOC/XLS/PPT old) or MSI
            elif matched_type in ["MS Office (DOC/XLS/PPT old)", "MSI (Also DOC/XLS)"]:
                if header.startswith(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"):
                    details.append("Valid MS Office/MSI header")
                else:
                    details.append("Invalid MS Office/MSI structure")
                    spoof_detected = True

            # 15. RIFF-based (WAV/AVI) or WebP
            elif matched_type in ["RIFF (WAV/AVI)", "WebP (WEBP)"]:
                if header.startswith(b"RIFF"):
                    if header[8:12] == b"WEBP":
                        details.append("Valid WebP structure")
                    elif header[8:12] in [b"WAVE", b"AVI "]:
                        details.append("Valid RIFF (WAV/AVI) structure")
                    else:
                        details.append("Invalid RIFF structure")
                        spoof_detected = True
                else:
                    details.append("Invalid RIFF/WebP header")
                    spoof_detected = True

            # 16. MIDI
            elif matched_type == "MIDI":
                if header.startswith(b"MThd"):
                    details.append("Valid MIDI header")
                else:
                    details.append("Invalid MIDI structure")
                    spoof_detected = True

            # 17. GZIP
            elif matched_type == "GZIP":
                if header.startswith(b"\x1F\x8B"):
                    details.append("Valid GZIP header")
                else:
                    details.append("Invalid GZIP structure")
                    spoof_detected = True

            # 18. 7-Zip
            elif matched_type == "7-Zip":
                if header.startswith(b"\x37\x7A\xBC\xAF\x27\x1C"):
                    details.append("Valid 7-Zip header")
                else:
                    details.append("Invalid 7-Zip structure")
                    spoof_detected = True

            # 19. CAB
            elif matched_type == "CAB":
                if header.startswith(b"MSCF"):
                    details.append("Valid CAB header")
                else:
                    details.append("Invalid CAB structure")
                    spoof_detected = True

            # 20. RTF
            elif matched_type == "RTF":
                if header.startswith(b"{\\rtf1"):
                    details.append("Valid RTF header")
                else:
                    details.append("Invalid RTF structure")
                    spoof_detected = True

            # 21. Ogg
            elif matched_type == "Ogg":
                if header.startswith(b"OggS"):
                    details.append("Valid Ogg header")
                else:
                    details.append("Invalid Ogg structure")
                    spoof_detected = True

            # 22. AVI
            elif matched_type == "AVI":
                if header.startswith(b"AVI "):
                    details.append("Valid AVI header")
                else:
                    details.append("Invalid AVI structure")
                    spoof_detected = True

            # 23. FLV
            elif matched_type == "FLV":
                if header.startswith(b"FLV"):
                    details.append("Valid FLV header")
                else:
                    details.append("Invalid FLV structure")
                    spoof_detected = True

            # 24. SWF
            elif matched_type in ["SWF (Compressed)", "SWF (Uncompressed)"]:
                if header.startswith(b"CWS") or header.startswith(b"FWS"):
                    details.append("Valid SWF header")
                else:
                    details.append("Invalid SWF structure")
                    spoof_detected = True

            # 25. Fonts (OTF/TTF)
            elif matched_type in ["OTF Font", "TTF Font"]:
                if header.startswith(b"OTTO") or header.startswith(b"\x00\x01\x00\x00\x00"):
                    details.append(f"Valid {matched_type} header")
                else:
                    details.append(f"Invalid {matched_type} structure")
                    spoof_detected = True

            # 26. ISZ
            elif matched_type == "ISZ":
                if header.startswith(b"IsZ!"):
                    details.append("Valid ISZ header")
                else:
                    details.append("Invalid ISZ structure")
                    spoof_detected = True

            # 27. DAA
            elif matched_type == "DAA":
                if header.startswith(b"DAA"):
                    details.append("Valid DAA header")
                else:
                    details.append("Invalid DAA structure")
                    spoof_detected = True

            # 28. EVT/EVTX
            elif matched_type in ["EVT", "EVTX"]:
                if header.startswith(b"LfLe") or header.startswith(b"ElfFile"):
                    details.append(f"Valid {matched_type} header")
                else:
                    details.append(f"Invalid {matched_type} structure")
                    spoof_detected = True

            # 29. Windows Registry
            elif matched_type == "Windows Registry":
                if header.startswith(b"regf"):
                    details.append("Valid Windows Registry header")
                else:
                    details.append("Invalid Windows Registry structure")
                    spoof_detected = True

            # 30. PST
            elif matched_type == "PST":
                if header.startswith(b"!BDN"):
                    details.append("Valid PST header")
                else:
                    details.append("Invalid PST structure")
                    spoof_detected = True

            # 31. LZIP
            elif matched_type == "LZIP":
                if header.startswith(b"LZIP"):
                    details.append("Valid LZIP header")
                else:
                    details.append("Invalid LZIP structure")
                    spoof_detected = True

            # 32. CPIO
            elif matched_type == "CPIO":
                if header.startswith(b"070707"):
                    details.append("Valid CPIO header")
                else:
                    details.append("Invalid CPIO structure")
                    spoof_detected = True

            # 33. TIFF/BigTIFF
            elif matched_type in ["TIFF (LE)", "TIFF (BE)", "BigTIFF (LE)", "BigTIFF (BE)"]:
                if header[:4] in [b"II*\x00", b"MM\x00*", b"II+\x00", b"MM\x00+"]:
                    details.append(f"Valid {matched_type} header")
                else:
                    details.append(f"Invalid {matched_type} structure")
                    spoof_detected = True

            # 34. DICOM
            elif matched_type == "DICOM":
                if header.startswith(b"DICM"):
                    details.append("Valid DICOM header")
                else:
                    details.append("Invalid DICOM structure")
                    spoof_detected = True

            # 35. FLAC
            elif matched_type == "FLAC":
                if header.startswith(b"fLaC"):
                    details.append("Valid FLAC header")
                else:
                    details.append("Invalid FLAC structure")
                    spoof_detected = True

            # 36. AU/SND
            elif matched_type == "AU/SND":
                if header.startswith(b".snd"):
                    details.append("Valid AU/SND header")
                else:
                    details.append("Invalid AU/SND structure")
                    spoof_detected = True

            # 37. PostScript
            elif matched_type == "PostScript":
                if header.startswith(b"%!PS"):
                    details.append("Valid PostScript header")
                else:
                    details.append("Invalid PostScript structure")
                    spoof_detected = True

            # 38. VDI/VHD/VHDX
            elif matched_type in ["VDI (Oracle)", "VHD", "VHDX"]:
                if header.startswith(b"<<< ") or header.startswith(b"conectix") or header.startswith(b"vhdxfile"):
                    details.append(f"Valid {matched_type} header")
                else:
                    details.append(f"Invalid {matched_type} structure")
                    spoof_detected = True

            # 39. Crowdstrike SYS
            elif matched_type == "Crowdstrike SYS":
                if header.startswith(b"\xAA\xAA\xAA\xAA"):
                    details.append("Valid Crowdstrike SYS header")
                else:
                    details.append("Invalid Crowdstrike SYS structure")
                    spoof_detected = True

            # 40. ISO9660
            elif matched_type == "ISO9660":
                if header.startswith(b"CC001"):
                    details.append("Valid ISO9660 header")
                else:
                    details.append("Invalid ISO9660 structure")
                    spoof_detected = True

            # 41. HL7 (MSH/BSH)
            elif matched_type in ["HL7 (MSH)", "HL7 (BSH)"]:
                if header.startswith(b"MSH|") or header.startswith(b"BSH|"):
                    details.append(f"Valid {matched_type} header")
                else:
                    details.append(f"Invalid {matched_type} structure")
                    spoof_detected = True

            # 42. MP4/M4A/M4V
            elif matched_type == "MP4/M4A/M4V":
                if header.startswith(b"\x00\x00\x00\x14ftypisom"):
                    details.append("Valid MP4/M4A/M4V header")
                else:
                    details.append("Invalid MP4/M4A/M4V structure")
                    spoof_detected = True

            # 43. PSD
            elif matched_type == "PSD":
                if header.startswith(b"FromHead"):
                    details.append("Valid PSD header")
                else:
                    details.append("Invalid PSD structure")
                    spoof_detected = True

            # 44. SQLite
            elif matched_type.startswith("SQLite"):
                if header.startswith(b"SQLite format 3"):
                    details.append("Valid SQLite header")
                else:
                    details.append("Invalid SQLite structure")
                    spoof_detected = True

            # 45. Java Class
            elif matched_type.startswith("Java Class"):
                if header.startswith(b"(fat code)") or header.startswith(b"\xCA\xFE\xBA\xBE") or header.startswith(b"Caffeine"):
                    details.append("Valid Java Class header")
                else:
                    details.append("Invalid Java Class structure")
                    spoof_detected = True

            # 46. KDM
            elif matched_type == "KDM":
                if header.startswith(b"kdmf"):
                    details.append("Valid KDM header")
                else:
                    details.append("Invalid KDM structure")
                    spoof_detected = True

            # 47. DEB
            elif matched_type == "DEB":
                if header.startswith(b"DEADBEEF"):
                    details.append("Valid DEB header")
                else:
                    details.append("Invalid DEB structure")
                    spoof_detected = True

            # 48. RPM
            elif matched_type == "RPM":
                if header.startswith(b".rpm"):
                    details.append("Valid RPM header")
                else:
                    details.append("Invalid RPM structure")
                    spoof_detected = True

            # 49. IMG (Apple)
            elif matched_type == "IMG (Apple)":
                if header.startswith(b"\xF0\xED\xF0\xED"):
                    details.append("Valid IMG (Apple) header")
                else:
                    details.append("Invalid IMG (Apple) structure")
                    spoof_detected = True

            # 50. ARC (FreeArc)
            elif matched_type in ["ARC (FreeArc)", "ARC (FreeArc Alt)"]:
                if header.startswith(b"ARC\x01") or header.startswith(b"ARC\x00"):
                    details.append("Valid ARC header")
                else:
                    details.append("Invalid ARC structure")
                    spoof_detected = True

            # 51. WEBM/MKV/MKA
            elif matched_type == "WEBM/MKV/MKA":
                if header.startswith(b"\x1A\x45\xDF\xA3"):
                    details.append("Valid WEBM/MKV/MKA header")
                else:
                    details.append("Invalid WEBM/MKV/MKA structure")
                    spoof_detected = True

            # 52. DMG (Apple)
            elif matched_type == "DMG (Apple)":
                if header.startswith(b"\xF7\xFF\xFF\xFF\xC8\xFF\xFF\xFF\xF6\xFF\xFF\xFF"):
                    details.append("Valid DMG header")
                else:
                    details.append("Invalid DMG structure")
                    spoof_detected = True

            # 53. WASM
            elif matched_type == "WASM":
                if header.startswith(b"\x00asm"):
                    details.append("Valid WASM header")
                else:
                    details.append("Invalid WASM structure")
                    spoof_detected = True

            # 54. EXT3/EXT4
            elif matched_type == "EXT3/EXT4":
                if header.startswith(b"EXT3"):
                    details.append("Valid EXT3/EXT4 header")
                else:
                    details.append("Invalid EXT3/EXT4 structure")
                    spoof_detected = True

            # 55. BIN/DAT (Zero Filled)
            elif matched_type == "BIN/DAT (Zero Filled)":
                if header.startswith(b"\x00" * 16):
                    details.append("Valid BIN/DAT (Zero Filled) header")
                else:
                    details.append("Invalid BIN/DAT structure")
                    spoof_detected = True

            # 56. CUR/ICO
            elif matched_type == "CUR/ICO":
                if header.startswith(b"\x00\x00\x01\x00"):
                    details.append("Valid CUR/ICO header")
                else:
                    details.append("Invalid CUR/ICO structure")
                    spoof_detected = True

            # 57. DWG/DXF
            elif matched_type in ["DWG/DXF", "DWG (Alt)"]:
                if header.startswith(b"AC10") or header.startswith(b";DWGDiskFile"):
                    details.append("Valid DWG/DXF header")
                else:
                    details.append("Invalid DWG/DXF structure")
                    spoof_detected = True

            # 58. LZH/LHA
            elif matched_type == "LZH/LHA":
                if header.startswith(b"0000LHS"):
                    details.append("Valid LZH/LHA header")
                else:
                    details.append("Invalid LZH/LHA structure")
                    spoof_detected = True

            # 59. ZOO
            elif matched_type == "ZOO":
                if header.startswith(b"ZOO"):
                    details.append("Valid ZOO header")
                else:
                    details.append("Invalid ZOO structure")
                    spoof_detected = True

            # 60. ADF
            elif matched_type == "ADF":
                if header.startswith(b"ADIF"):
                    details.append("Valid ADF header")
                else:
                    details.append("Invalid ADF structure")
                    spoof_detected = True

            # 61. MDB
            elif matched_type == "MDB":
                if header.startswith(b"MSJET"):
                    details.append("Valid MDB header")
                else:
                    details.append("Invalid MDB structure")
                    spoof_detected = True

            # 62. JPEG 2000 (JP2)
            elif matched_type == "JPEG 2000 (JP2)":
                if header.startswith(b"\x00\x00\x00\x0CjFTYPmjp2"):
                    details.append("Valid JPEG 2000 header")
                else:
                    details.append("Invalid JPEG 2000 structure")
                    spoof_detected = True

            # 63. LN
            elif matched_type == "LN":
                if header.startswith(b"L\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46"):
                    details.append("Valid LN header")
                else:
                    details.append("Invalid LN structure")
                    spoof_detected = True

            # 64. MPG/MPEG/DAT
            elif matched_type.startswith("MPG/MPEG"):
                if header[:4] in [b"\x00\x00\x01\xBA", b"\x00\x00\x01\xB3", b"\x00\x00\x01\xB6", b"\x00\x00\x01\xB7", b"\x00\x00\x01\xB8", b"\x00\x00\x01\xB9", b"\x00\x00\x01\xBC", b"\x00\x00\x01\xBE"]:
                    details.append("Valid MPG/MPEG header")
                else:
                    details.append("Invalid MPG/MPEG structure")
                    spoof_detected = True

            # 65. WMV/WMA/ASF
            elif matched_type == "WMV/WMA/ASF":
                if header.startswith(b"\x30\x26\xB2\x75\x8E\x66\xCF\x11\xA6\xD9\x00\xAA\x00\x62\xCE\x6C"):
                    details.append("Valid WMV/WMA/ASF header")
                else:
                    details.append("Invalid WMV/WMA/ASF structure")
                    spoof_detected = True

            # 66. Z/TGZ
            elif matched_type == "Z/TGZ":
                if header.startswith(b"\x1F\x9D"):
                    details.append("Valid Z/TGZ header")
                else:
                    details.append("Invalid Z/TGZ structure")
                    spoof_detected = True

            # 67. MDF
            elif matched_type == "MDF":
                if header.startswith(b"\x04\x22\x4D\x18"):
                    details.append("Valid MDF header")
                else:
                    details.append("Invalid MDF structure")
                    spoof_detected = True

            # 68. SIMPLE TEXT
            elif matched_type == "SIMPLE TEXT":
                if header.startswith(b"SIMPLE"):
                    details.append("Valid SIMPLE TEXT header")
                else:
                    details.append("Invalid SIMPLE TEXT structure")
                    spoof_detected = True

            # 69. PEM/CER/DER (X.509)
            elif matched_type == "PEM/CER/DER (X.509)":
                if header.startswith(b"0\x82"):
                    details.append("Valid PEM/CER/DER header")
                else:
                    details.append("Invalid PEM/CER/DER structure")
                    spoof_detected = True

            # 70. TXT (Spaces)
            elif matched_type == "TXT (Spaces)":
                if header.startswith(b"    "):
                    details.append("Valid TXT (Spaces) header")
                else:
                    details.append("Invalid TXT (Spaces) structure")
                    spoof_detected = True

            # 71. Shell Script (LIST)
            elif matched_type == "Shell Script (LIST)":
                if header.startswith(b"List"):
                    details.append("Valid Shell Script (LIST) header")
                else:
                    details.append("Invalid Shell Script (LIST) structure")
                    spoof_detected = True

            # 72. GKS (Graphics Kernel System)
            elif matched_type == "GKS (Graphics Kernel System)":
                if header.startswith(b"GKSM"):
                    details.append("Valid GKS header")
                else:
                    details.append("Invalid GKS structure")
                    spoof_detected = True

            # 73. IRIS RGB
            elif matched_type == "IRIS RGB":
                if header.startswith(b"\x01\xDA"):
                    details.append("Valid IRIS RGB header")
                else:
                    details.append("Invalid IRIS RGB structure")
                    spoof_detected = True

            # 74. ITC (CMU WM)
            elif matched_type == "ITC (CMU WM)":
                if header.startswith(b"\xF1\x00\x40\xBB"):
                    details.append("Valid ITC header")
                else:
                    details.append("Invalid ITC structure")
                    spoof_detected = True

            # 75. PM Format
            elif matched_type == "PM Format":
                if header.startswith(b"VIEW"):
                    details.append("Valid PM Format header")
                else:
                    details.append("Invalid PM Format structure")
                    spoof_detected = True

            # 76. Sun Rasterfile
            elif matched_type == "Sun Rasterfile":
                if header.startswith(b"\x59\xA6\x6A\x95"):
                    details.append("Valid Sun Rasterfile header")
                else:
                    details.append("Invalid Sun Rasterfile structure")
                    spoof_detected = True

            # 77. XCF (GIMP)
            elif matched_type == "XCF (GIMP)":
                if header.startswith(b"gimp xcf v"):
                    details.append("Valid XCF header")
                else:
                    details.append("Invalid XCF structure")
                    spoof_detected = True

            # 78. XFig Format
            elif matched_type == "XFig Format":
                if header.startswith(b"#FIG"):
                    details.append("Valid XFig header")
                else:
                    details.append("Invalid XFig structure")
                    spoof_detected = True

            # 79. XPM (X PixMap)
            elif matched_type == "XPM (X PixMap)":
                if header.startswith(b"/* XPM */"):
                    details.append("Valid XPM header")
                else:
                    details.append("Invalid XPM structure")
                    spoof_detected = True

            # 80. BZIP
            elif matched_type == "BZIP":
                if header.startswith(b"BZ"):
                    details.append("Valid BZIP header")
                else:
                    details.append("Invalid BZIP structure")
                    spoof_detected = True

            # 81. Compress (.Z)
            elif matched_type == "Compress (.Z)":
                if header.startswith(b"\x1F\x9D"):
                    details.append("Valid Compress (.Z) header")
                else:
                    details.append("Invalid Compress (.Z) structure")
                    spoof_detected = True

            # 82. PGP-related
            elif matched_type in ["PGP Public Ring", "PGP Security Ring", "PGP Security Ring (Alt)", "PGP Encrypted Data"]:
                if header[:2] in [b"\x99\x00", b"\x95\x01", b"\x95\x00", b"\xA6\x00"]:
                    details.append(f"Valid {matched_type} header")
                else:
                    details.append(f"Invalid {matched_type} structure")
                    spoof_detected = True

            # Compare declared and actual types
            if declared_type != matched_type and declared_type != "UNKNOWN":
                spoof_detected = True
                details.append(f"Declared type '{declared_type}' mismatches detected type '{matched_type}'")

            self.analysis_results["spoof"] = {
                "Spoof Detected": "Yes" if spoof_detected else "No",
                "Detected by Header": matched_type,
                "Declared Type": declared_type,
                "MIME Type": mime_type,
                "Matched Signature": str(matched_sig) if matched_sig else "None",
                "Details": "; ".join(details)
            }

        except Exception as e:
            self.analysis_results["spoof"] = {
                "Spoof Detected": "N/A",
            "Details": f"Failed to check header: {str(e)}"
        }


    def pe_header_analysis(self, file_path):
        file_type = self.analysis_results.get("magic", {}).get("Detected Type", "")
        pe_info = {"Analyzed": False, "Details": "No parser for this format"}

        try:
            with open(file_path, "rb") as f:
                content = f.read(4096)

            # -------- PE (EXE) --------
            if file_type in ["DOS MZ (EXE)", "SYS/COM"]:
                try:
                    if content[:2] == b"MZ":
                        e_lfanew = struct.unpack("<L", content[60:64])[0]
                        if content[e_lfanew:e_lfanew+4] == b"PE\0\0":
                            optional_header_offset = e_lfanew + 24
                            machine = struct.unpack("<H", content[e_lfanew+4:e_lfanew+6])[0]
                            number_of_sections = struct.unpack("<H", content[e_lfanew+6:e_lfanew+8])[0]
                            time_date_stamp = struct.unpack("<L", content[e_lfanew+8:e_lfanew+12])[0]
                            entry_point = struct.unpack("<L", content[optional_header_offset+16:optional_header_offset+20])[0]
                            machine_types = {0x14c: "x86", 0x8664: "x64"}
                            result = {
                                "Analyzed": True,
                                "Format": "PE Executable",
                                "Machine Type": machine_types.get(machine, f"Unknown (0x{machine:04x})"),
                                "Number of Sections": number_of_sections,
                                "Compilation Time": datetime.datetime.fromtimestamp(time_date_stamp).strftime('%Y-%m-%d %H:%M:%S'),
                                "Entry Point": f"0x{entry_point:08x}"
                            }
                        else:
                            result = {"Analyzed": False, "Details": "Invalid PE structure"}
                    elif content[:2] == b"\x1B\x4C":
                        result = {
                            "Analyzed": True,
                            "Format": "SYS/COM",
                            "Details": "System or COM file detected"
                        }
                except Exception as e:
                    result = {"Analyzed": False, "Details": f"PE/SYS parsing failed: {str(e)}"}

            # -------- PDF --------
            elif file_type.startswith("PDF"):
                if content.startswith(b"%PDF-"):
                    version = content[5:8].decode(errors="ignore")
                    result = {
                        "Analyzed": True,
                        "Format": "PDF",
                        "PDF Version": version
                    }

            # -------- ELF --------
            elif file_type == "ELF":
                bit_type = "64-bit" if content[4] == 2 else "32-bit"
                endian = "Little" if content[5] == 1 else "Big"
                result = {
                    "Analyzed": True,
                    "Format": "ELF Executable",
                    "Bit": bit_type,
                    "Endian": endian,
                    "Entry Point": f"0x{struct.unpack('<I', content[24:28])[0]:08x}" if bit_type == "32-bit"
                                   else f"0x{struct.unpack('<Q', content[24:32])[0]:016x}"
                }

            # -------- ZIP --------
            elif file_type.startswith("ZIP"):
                if content[:4] in [b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"]:
                    mod_time = struct.unpack("<H", content[10:12])[0]
                    mod_date = struct.unpack("<H", content[12:14])[0]
                    result = {
                        "Analyzed": True,
                        "Format": "ZIP Archive",
                        "Last Modified": f"{mod_date:04x}-{mod_time:04x}"
                    }

            # -------- MP3 --------
            elif file_type.startswith("MP3"):
                if content[:3] == b"ID3":
                    version = f"ID3v2.{content[3]}.{content[4]}"
                    result = {
                        "Analyzed": True,
                        "Format": "MP3 Audio",
                        "ID3 Tag Version": version
                    }
                else:
                    result = {
                        "Analyzed": True,
                        "Format": "MP3 Audio",
                        "Details": "No ID3 tag, raw MP3 stream"
                    }

            # -------- PNG --------
            elif file_type == "PNG":
                width = struct.unpack(">I", content[16:20])[0]
                height = struct.unpack(">I", content[20:24])[0]
                bit_depth = content[24]
                color_type = content[25]
                result = {
                    "Analyzed": True,
                    "Format": "PNG Image",
                    "Width": width,
                    "Height": height,
                    "Bit Depth": bit_depth,
                    "Color Type": color_type
                }

            # -------- JPEG --------
            elif file_type.startswith("JPEG") or file_type == "NIFF (Navy TIFF)":
                if content[6:10] == b"JFIF":
                    result = {
                        "Analyzed": True,
                        "Format": "JPEG Image",
                        "Encoding": "JFIF"
                    }
                elif content[6:10] == b"Exif":
                    result = {
                        "Analyzed": True,
                        "Format": "JPEG Image",
                        "Encoding": "Exif"
                    }
                elif content[:4] == b"\x49\x49\x4E\x31":
                    result = {
                        "Analyzed": True,
                        "Format": "NIFF Image",
                        "Encoding": "Navy TIFF"
                    }
                else:
                    result = {
                        "Analyzed": True,
                        "Format": "JPEG Image",
                        "Encoding": "Unknown or Baseline"
                    }

            # -------- GIF --------
            elif file_type in ["GIF87a", "GIF89a"]:
                width = struct.unpack("<H", content[6:8])[0]
                height = struct.unpack("<H", content[810])[0]
                result = {
                    "Analyzed": True,
                    "Format": f"GIF ({file_type})",
                    "Width": width,
                    "Height": height
                }

            # -------- BMP --------
            elif file_type == "BMP":
                file_size = struct.unpack("<I", content[2:6])[0]
                width = struct.unpack("<I", content[18:22])[0]
                height = struct.unpack("<I", content[22:26])[0]
                result = {
                    "Analyzed": True,
                    "Format": "BMP Image",
                    "File Size": file_size,
                    "Width": width,
                    "Height": height
                }

            # -------- MS Office (DOC/XLS/PPT old) or MSI --------
            elif file_type in ["MS Office (DOC/XLS/PPT old)", "MSI (Also DOC/XLS)"]:
                if content.startswith(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"):
                    result = {
                        "Analyzed": True,
                        "Format": "MS Office/MSI",
                        "Details": "Compound File Binary Format detected"
                    }

            # -------- RIFF (WAV/AVI) or WebP --------
            elif file_type in ["RIFF (WAV/AVI)", "WebP (WEBP)"]:
                if content[8:12] == b"WAVE":
                    result = {
                        "Analyzed": True,
                        "Format": "WAV Audio",
                        "Details": "RIFF-based WAV format"
                    }
                elif content[8:12] == b"AVI ":
                    result = {
                        "Analyzed": True,
                        "Format": "AVI Video",
                        "Details": "RIFF-based AVI format"
                    }
                elif content[8:12] == b"WEBP":
                    result = {
                        "Analyzed": True,
                        "Format": "WebP Image",
                        "Details": "RIFF-based WebP format"
                    }

            # -------- MIDI --------
            elif file_type == "MIDI":
                if content.startswith(b"MThd"):
                    tracks = struct.unpack(">H", content[10:12])[0]
                    result = {
                        "Analyzed": True,
                        "Format": "MIDI Audio",
                        "Number of Tracks": tracks
                    }

            # -------- RAR --------
            elif "RAR" in file_type:
                flags = struct.unpack("<H", content[10:12])[0] if file_type == "RAR v5.0" else struct.unpack("<H", content[9:11])[0]
                result = {
                    "Analyzed": True,
                    "Format": f"RAR Archive ({file_type})",
                    "Flags": f"0x{flags:04x}"
                }

            # -------- GZIP --------
            elif file_type == "GZIP":
                flags = content[3]
                mtime = struct.unpack("<I", content[4:8])[0]
                result = {
                    "Analyzed": True,
                    "Format": "GZIP Archive",
                    "Flags": f"0x{flags:02x}",
                    "Modification Time": datetime.datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M:%S') if mtime else "Not set"
                }

            # -------- 7-Zip --------
            elif file_type == "7-Zip":
                major_version = content[6]
                minor_version = content[7]
                result = {
                    "Analyzed": True,
                    "Format": "7-Zip Archive",
                    "Version": f"{major_version}.{minor_version}"
                }

            # -------- CAB --------
            elif file_type == "CAB":
                folder_count = struct.unpack("<H", content[10:12])[0]
                file_count = struct.unpack("<H", content[12:14])[0]
                result = {
                    "Analyzed": True,
                    "Format": "CAB Archive",
                    "Folder Count": folder_count,
                    "File Count": file_count
                }

            # -------- UTF-encoded Text --------
            elif file_type in ["UTF-8 BOM (Text)", "UTF-16LE BOM (Text)", "UTF-16BE BOM (Text)"]:
                encoding = file_type.split()[0]
                result = {
                    "Analyzed": True,
                    "Format": f"Text ({encoding})",
                    "Details": f"{encoding} encoded text file"
                }

            # -------- XML --------
            elif file_type == "XML":
                version = content[6:11].decode(errors="ignore") if content.startswith(b"<?xml") else "Unknown"
                result = {
                    "Analyzed": True,
                    "Format": "XML",
                    "Version": version
                }

            # -------- RTF --------
            elif file_type == "RTF":
                result = {
                    "Analyzed": True,
                    "Format": "RTF Document",
                    "Details": "Rich Text Format detected"
                }

            # -------- Ogg --------
            elif file_type == "Ogg":
                version = content[4]
                result = {
                    "Analyzed": True,
                    "Format": "Ogg Container",
                    "Version": f"0x{version:02x}"
                }

            # -------- AVI --------
            elif file_type == "AVI":
                result = {
                    "Analyzed": True,
                    "Format": "AVI Video",
                    "Details": "AVI format detected"
                }

            # -------- FLV --------
            elif file_type == "FLV":
                version = content[3]
                result = {
                    "Analyzed": True,
                    "Format": "FLV Video",
                    "Version": f"0x{version:02x}"
                }

            # -------- SWF --------
            elif file_type in ["SWF (Compressed)", "SWF (Uncompressed)"]:
                version = content[3]
                result = {
                    "Analyzed": True,
                    "Format": "SWF Flash",
                    "Version": f"0x{version:02x}",
                    "Compressed": "Yes" if file_type == "SWF (Compressed)" else "No"
                }

            # -------- Fonts (OTF/TTF) --------
            elif file_type in ["OTF Font", "TTF Font"]:
                result = {
                    "Analyzed": True,
                    "Format": file_type,
                    "Details": f"{file_type} detected"
                }

            # -------- ISZ --------
            elif file_type == "ISZ":
                result = {
                    "Analyzed": True,
                    "Format": "ISZ Image",
                    "Details": "Compressed disk image detected"
                }

            # -------- DAA --------
            elif file_type == "DAA":
                result = {
                    "Analyzed": True,
                    "Format": "DAA Image",
                    "Details": "Direct Access Archive detected"
                }

            # -------- EVT/EVTX --------
            elif file_type in ["EVT", "EVTX"]:
                result = {
                    "Analyzed": True,
                    "Format": file_type,
                    "Details": f"Windows Event Log ({file_type}) detected"
                }

            # -------- Windows Registry --------
            elif file_type == "Windows Registry":
                version = struct.unpack("<I", content[4:8])[0]
                result = {
                    "Analyzed": True,
                    "Format": "Windows Registry",
                    "Version": f"0x{version:08x}"
                }

            # -------- PST --------
            elif file_type == "PST":
                result = {
                    "Analyzed": True,
                    "Format": "PST Email Archive",
                    "Details": "Outlook Personal Storage Table detected"
                }

            # -------- LZIP --------
            elif file_type == "LZIP":
                result = {
                    "Analyzed": True,
                    "Format": "LZIP Archive",
                    "Details": "LZIP compressed file detected"
                }

            # -------- CPIO --------
            elif file_type == "CPIO":
                result = {
                    "Analyzed": True,
                    "Format": "CPIO Archive",
                    "Details": "CPIO archive detected"
                }

            # -------- TIFF/BigTIFF --------
            elif file_type in ["TIFF (LE)", "TIFF (BE)", "BigTIFF (LE)", "BigTIFF (BE)"]:
                ifd_offset = struct.unpack("<I" if "LE" in file_type else ">I", content[4:8])[0]
                result = {
                    "Analyzed": True,
                    "Format": file_type,
                    "IFD Offset": f"0x{ifd_offset:08x}"
                }

            # -------- DICOM --------
            elif file_type == "DICOM":
                result = {
                    "Analyzed": True,
                    "Format": "DICOM Medical Image",
                    "Details": "DICOM format detected"
                }

            # -------- FLAC --------
            elif file_type == "FLAC":
                result = {
                    "Analyzed": True,
                    "Format": "FLAC Audio",
                    "Details": "Free Lossless Audio Codec detected"
                }

            # -------- AU/SND --------
            elif file_type == "AU/SND":
                data_offset = struct.unpack(">I", content[4:8])[0]
                result = {
                    "Analyzed": True,
                    "Format": "AU/SND Audio",
                    "Data Offset": f"0x{data_offset:08x}"
                }

            # -------- PostScript --------
            elif file_type == "PostScript":
                version = content[4:10].decode(errors="ignore")
                result = {
                    "Analyzed": True,
                    "Format": "PostScript",
                    "Version": version
                }

            # -------- VDI/VHD/VHDX --------
            elif file_type in ["VDI (Oracle)", "VHD", "VHDX"]:
                result = {
                    "Analyzed": True,
                    "Format": file_type,
                    "Details": f"Virtual Disk Image ({file_type}) detected"
                }

            # -------- Crowdstrike SYS --------
            elif file_type == "Crowdstrike SYS":
                result = {
                    "Analyzed": True,
                    "Format": "Crowdstrike SYS",
                    "Details": "Crowdstrike system file detected"
                }

            # -------- ISO9660 --------
            elif file_type == "ISO9660":
                result = {
                    "Analyzed": True,
                    "Format": "ISO9660 Disk Image",
                    "Details": "CD/DVD image detected"
                }

            # -------- HL7 (MSH/BSH) --------
            elif file_type in ["HL7 (MSH)", "HL7 (BSH)"]:
                result = {
                    "Analyzed": True,
                    "Format": file_type,
                    "Details": "HL7 healthcare messaging format detected"
                }

            # -------- MP4/M4A/M4V --------
            elif file_type == "MP4/M4A/M4V":
                major_brand = content[16:20].decode(errors="ignore")
                result = {
                    "Analyzed": True,
                    "Format": "MP4/M4A/M4V",
                    "Major Brand": major_brand
                }

            # -------- PSD --------
            elif file_type == "PSD":
                version = struct.unpack(">H", content[8:10])[0]
                result = {
                    "Analyzed": True,
                    "Format": "PSD Image",
                    "Version": version
                }

            # -------- SQLite --------
            elif file_type.startswith("SQLite"):
                page_size = struct.unpack(">H", content[16:18])[0]
                result = {
                    "Analyzed": True,
                    "Format": "SQLite Database",
                    "Page Size": page_size
                }

            # -------- Java Class --------
            elif file_type.startswith("Java Class"):
                major_version = struct.unpack(">H", content[6:8])[0]
                minor_version = struct.unpack(">H", content[4:6])[0]
                result = {
                    "Analyzed": True,
                    "Format": "Java Class",
                    "Version": f"{major_version}.{minor_version}"
                }

            # -------- KDM --------
            elif file_type == "KDM":
                result = {
                    "Analyzed": True,
                    "Format": "KDM",
                    "Details": "Key Delivery Message detected"
                }

            # -------- DEB --------
            elif file_type == "DEB":
                result = {
                    "Analyzed": True,
                    "Format": "DEB Package",
                    "Details": "Debian package detected"
                }

            # -------- RPM --------
            elif file_type == "RPM":
                result = {
                    "Analyzed": True,
                    "Format": "RPM Package",
                    "Details": "Red Hat Package Manager file detected"
                }

            # -------- IMG (Apple) --------
            elif file_type == "IMG (Apple)":
                result = {
                    "Analyzed": True,
                    "Format": "IMG (Apple)",
                    "Details": "Apple disk image detected"
                }

            # -------- ARC (FreeArc) --------
            elif file_type in ["ARC (FreeArc)", "ARC (FreeArc Alt)"]:
                result = {
                    "Analyzed": True,
                    "Format": "ARC Archive",
                    "Details": f"FreeArc archive ({file_type}) detected"
                }

            # -------- WEBM/MKV/MKA --------
            elif file_type == "WEBM/MKV/MKA":
                result = {
                    "Analyzed": True,
                    "Format": "WEBM/MKV/MKA",
                    "Details": "Matroska-based media container detected"
                }

            # -------- DMG (Apple) --------
            elif file_type == "DMG (Apple)":
                result = {
                    "Analyzed": True,
                    "Format": "DMG (Apple)",
                    "Details": "Apple Disk Image detected"
                }

            # -------- WASM --------
            elif file_type == "WASM":
                version = struct.unpack("<I", content[4:8])[0]
                result = {
                    "Analyzed": True,
                    "Format": "WebAssembly",
                    "Version": f"0x{version:08x}"
                }

            # -------- EXT3/EXT4 --------
            elif file_type == "EXT3/EXT4":
                result = {
                    "Analyzed": True,
                    "Format": "EXT3/EXT4 Filesystem",
                    "Details": "Linux filesystem detected"
                }

            # -------- BIN/DAT (Zero Filled) --------
            elif file_type == "BIN/DAT (Zero Filled)":
                result = {
                    "Analyzed": True,
                    "Format": "BIN/DAT",
                    "Details": "Zero-filled binary/data file detected"
                }

            # -------- CUR/ICO --------
            elif file_type == "CUR/ICO":
                icon_count = struct.unpack("<H", content[4:6])[0]
                result = {
                    "Analyzed": True,
                    "Format": "CUR/ICO Image",
                    "Icon Count": icon_count
                }

            # -------- DWG/DXF --------
            elif file_type in ["DWG/DXF", "DWG (Alt)"]:
                result = {
                    "Analyzed": True,
                    "Format": "DWG/DXF",
                    "Details": "AutoCAD drawing file detected"
                }

            # -------- LZH/LHA --------
            elif file_type == "LZH/LHA":
                result = {
                    "Analyzed": True,
                    "Format": "LZH/LHA Archive",
                    "Details": "LHA archive detected"
                }

            # -------- ZOO --------
            elif file_type == "ZOO":
                result = {
                    "Analyzed": True,
                    "Format": "ZOO Archive",
                    "Details": "ZOO archive detected"
                }

            # -------- ADF --------
            elif file_type == "ADF":
                result = {
                    "Analyzed": True,
                    "Format": "ADF Image",
                    "Details": "Amiga Disk File detected"
                }

            # -------- MDB --------
            elif file_type == "MDB":
                result = {
                    "Analyzed": True,
                    "Format": "MDB Database",
                    "Details": "Microsoft Access database detected"
                }

            # -------- JPEG 2000 (JP2) --------
            elif file_type == "JPEG 2000 (JP2)":
                result = {
                    "Analyzed": True,
                    "Format": "JPEG 2000",
                    "Details": "JP2 image format detected"
                }

            # -------- LN --------
            elif file_type == "LN":
                result = {
                    "Analyzed": True,
                    "Format": "LN File",
                    "Details": "LN format detected"
                }

            # -------- MPG/MPEG/DAT --------
            elif file_type.startswith("MPG/MPEG"):
                result = {
                    "Analyzed": True,
                    "Format": "MPG/MPEG Video",
                    "Details": "MPEG video stream detected"
                }

            # -------- WMV/WMA/ASF --------
            elif file_type == "WMV/WMA/ASF":
                result = {
                    "Analyzed": True,
                    "Format": "WMV/WMA/ASF",
                    "Details": "Windows Media format detected"
                }

            # -------- Z/TGZ --------
            elif file_type == "Z/TGZ":
                result = {
                    "Analyzed": True,
                    "Format": "Z/TGZ Archive",
                    "Details": "Compressed tar or Z file detected"
                }

            # -------- MDF --------
            elif file_type == "MDF":
                result = {
                    "Analyzed": True,
                    "Format": "MDF Image",
                    "Details": "Media Descriptor File detected"
                }

            # -------- SIMPLE TEXT --------
            elif file_type == "SIMPLE TEXT":
                result = {
                    "Analyzed": True,
                    "Format": "Simple Text",
                    "Details": "Plain text file detected"
                }

            # -------- PEM/CER/DER (X.509) --------
            elif file_type == "PEM/CER/DER (X.509)":
                result = {
                    "Analyzed": True,
                    "Format": "X.509 Certificate",
                    "Details": "PEM/CER/DER certificate format detected"
                }

            # -------- TXT (Spaces) --------
            elif file_type == "TXT (Spaces)":
                result = {
                    "Analyzed": True,
                    "Format": "Text (Spaces)",
                    "Details": "Text file with leading spaces detected"
                }

            # -------- JSON --------
            elif file_type == "JSON":
                result = {
                    "Analyzed": True,
                    "Format": "JSON",
                    "Details": "JSON data format detected"
                }

            # -------- Shell Script (LIST) --------
            elif file_type == "Shell Script (LIST)":
                result = {
                    "Analyzed": True,
                    "Format": "Shell Script",
                    "Details": "Shell script with LIST header detected"
                }

            # -------- GKS (Graphics Kernel System) --------
            elif file_type == "GKS (Graphics Kernel System)":
                result = {
                    "Analyzed": True,
                    "Format": "GKS",
                    "Details": "Graphics Kernel System format detected"
                }

            # -------- IRIS RGB --------
            elif file_type == "IRIS RGB":
                width = struct.unpack(">H", content[4:6])[0]
                height = struct.unpack(">H", content[6:8])[0]
                result = {
                    "Analyzed": True,
                    "Format": "IRIS RGB Image",
                    "Width": width,
                    "Height": height
                }

            # -------- ITC (CMU WM) --------
            elif file_type == "ITC (CMU WM)":
                result = {
                    "Analyzed": True,
                    "Format": "ITC",
                    "Details": "CMU Window Manager format detected"
                }

            # -------- PM Format --------
            elif file_type == "PM Format":
                result = {
                    "Analyzed": True,
                    "Format": "PM Image",
                    "Details": "PM format detected"
                }

            # -------- Sun Rasterfile --------
            elif file_type == "Sun Rasterfile":
                width = struct.unpack(">I", content[8:12])[0]
                height = struct.unpack(">I", content[12:16])[0]
                result = {
                    "Analyzed": True,
                    "Format": "Sun Rasterfile",
                    "Width": width,
                    "Height": height
                }

            # -------- XCF (GIMP) --------
            elif file_type == "XCF (GIMP)":
                version = content[9:13].decode(errors="ignore")
                result = {
                    "Analyzed": True,
                    "Format": "XCF (GIMP)",
                    "Version": version
                }

            # -------- XFig Format --------
            elif file_type == "XFig Format":
                version = content[4:9].decode(errors="ignore")
                result = {
                    "Analyzed": True,
                    "Format": "XFig",
                    "Version": version
                }

            # -------- XPM (X PixMap) --------
            elif file_type == "XPM (X PixMap)":
                result = {
                    "Analyzed": True,
                    "Format": "XPM Image",
                    "Details": "X PixMap format detected"
                }

            # -------- BZIP --------
            elif file_type == "BZIP":
                result = {
                    "Analyzed": True,
                    "Format": "BZIP Archive",
                    "Details": "BZIP compressed file detected"
                }

            # -------- Compress (.Z) --------
            elif file_type == "Compress (.Z)":
                result = {
                    "Analyzed": True,
                    "Format": "Compress (.Z)",
                    "Details": "UNIX compress file detected"
                }

            # -------- PGP-related --------
            elif file_type in ["PGP Public Ring", "PGP Security Ring", "PGP Security Ring (Alt)", "PGP Encrypted Data"]:
                result = {
                    "Analyzed": True,
                    "Format": file_type,
                    "Details": f"PGP {file_type.split()[1].lower()} format detected"
                }

        except Exception as e:
            pe_info["Details"] = f"PE parsing failed: {str(e)}"

        self.analysis_results["pe"] = pe_info

    def byte_pattern_analysis(self, file_path):
        try:
            with open(file_path, "rb") as f:
                data = f.read(1024)

            bigrams = Counter(zip(data, data[1:]))
            total = sum(bigrams.values())
            if total == 0:
                return

            exe_bigrams = {(0x4D, 0x5A): 0.1, (0x50, 0x45): 0.05}
            similarity = sum(min(bigrams.get(k, 0) / total, v) for k, v in exe_bigrams.items()) / sum(exe_bigrams.values())

            self.analysis_results["pattern"] = {
                "Similarity to EXE": f"{int(similarity * 100)}% match to known EXE"
            }
        except Exception:
            self.analysis_results["pattern"] = {"Similarity to EXE": "N/A"}

    def structure_validation(self, file_path):
        valid = True
        details = "Structure valid"
    
        try:
            file_type = self.analysis_results["magic"]["Detected Type"]
    
            with open(file_path, "rb") as f:
                data = f.read()
    
            # --- ZIP ---
            if file_type.startswith("ZIP"):
                if not data.endswith(b"\x50\x4B\x05\x06"):
                    valid = False
                    details = "ZIP: Missing end of central directory (EOCD)"
    
            # --- PDF ---
            elif file_type.startswith("PDF"):
                if b"%%EOF" not in data[-1024:]:
                    valid = False
                    details = "PDF: Missing EOF marker"
    
            # --- PNG ---
            elif file_type == "PNG":
                if not data.endswith(b'\x00\x00\x00\x00IEND\xAE\x42\x60\x82') and b'IEND' not in data:
                    valid = False
                    details = "PNG: Missing IEND chunk"
    
            # --- JPEG ---
            elif file_type.startswith("JPEG") or file_type == "NIFF (Navy TIFF)":
                if not data.startswith(b'\xFF\xD8') or not data.endswith(b'\xFF\xD9'):
                    valid = False
                    details = "JPEG/NIFF: Missing start or end markers"
    
            # --- GZIP ---
            elif file_type == "GZIP":
                if not data.startswith(b'\x1F\x8B'):
                    valid = False
                    details = "GZIP: Missing header"
    
            # --- TAR ---
            elif "TAR" in file_type or file_path.endswith(".tar") or file_type == "Z/TGZ":
                if len(data) % 512 != 0:
                    valid = False
                    details = "TAR: Size not a multiple of 512 bytes"
    
            # --- MP3 ---
            elif file_type.startswith("MP3"):
                if not (data.startswith(b'ID3') or data[:3] in [b'\xFF\xFB', b'\xFF\xF3', b'\xFF\xF2']):
                    valid = False
                    details = "MP3: Missing ID3 or frame sync"
    
            # --- ELF ---
            elif file_type == "ELF":
                if not data.startswith(b'\x7FELF'):
                    valid = False
                    details = "ELF: Missing magic header"
    
            # --- PE (EXE) or SYS/COM ---
            elif file_type in ["DOS MZ (EXE)", "SYS/COM"]:
                if file_type == "DOS MZ (EXE)":
                    if not data.startswith(b'MZ'):
                        valid = False
                        details = "PE: Missing 'MZ' header"
                    else:
                        try:
                            e_lfanew = struct.unpack("<L", data[60:64])[0]
                            if data[e_lfanew:e_lfanew+4] != b'PE\0\0':
                                valid = False
                                details = "PE: Missing 'PE\\0\\0' header at e_lfanew"
                        except:
                            valid = False
                            details = "PE: Corrupt e_lfanew field"
                elif file_type == "SYS/COM":
                    if not data.startswith(b'\x1B\x4C'):
                        valid = False
                        details = "SYS/COM: Missing signature"
    
            # --- JSON ---
            elif file_type == "JSON":
                stripped = data.strip()
                if not (stripped.startswith(b'{') and stripped.endswith(b'}')) and not (stripped.startswith(b'[') and stripped.endswith (b']')):
                    valid = False
                    details = "JSON: Improper start or end"
    
            # --- XML ---
            elif file_type == "XML":
                if not data.strip().startswith(b"<?xml"):
                    valid = False
                    details = "XML: Missing <?xml tag"
    
            # --- RAR ---
            elif "RAR" in file_type:
                if not (data.startswith(b'Rar!\x1A\x07') or data.startswith(b'\x52\x61\x72\x21\x1A\x07')):
                    valid = False
                    details = "RAR: Missing RAR signature"
    
            # --- SQLite ---
            elif file_type.startswith("SQLite"):
                if not data.startswith(b"SQLite format 3\x00"):
                    valid = False
                    details = "SQLite: Missing header"
    
            # --- GIF ---
            elif file_type in ["GIF87a", "GIF89a"]:
                if not (data.startswith(b'GIF87a') or data.startswith(b'GIF89a')):
                    valid = False
                    details = "GIF: Missing header signature"
    
            # --- BMP ---
            elif file_type == "BMP":
                if not data.startswith(b'BM'):
                    valid = False
                    details = "BMP: Missing 'BM' header"
    
            # --- MS Office (DOC/XLS/PPT old) or MSI ---
            elif file_type in ["MS Office (DOC/XLS/PPT old)", "MSI (Also DOC/XLS)"]:
                if not data.startswith(b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1'):
                    valid = False
                    details = "MS Office/MSI: Missing Compound File Binary header"
    
            # --- RIFF (WAV/AVI) or WebP ---
            elif file_type in ["RIFF (WAV/AVI)", "WebP (WEBP)"]:
                if not data.startswith(b'RIFF'):
                    valid = False
                    details = "RIFF/WebP: Missing RIFF header"
                elif file_type == "WebP (WEBP)" and data[8:12] != b'WEBP':
                    valid = False
                    details = "WebP: Missing WEBP signature"
                elif file_type == "RIFF (WAV/AVI)" and data[8:12] not in [b'WAVE', b'AVI ']:
                    valid = False
                    details = "RIFF: Invalid format identifier"
    
            # --- MIDI ---
            elif file_type == "MIDI":
                if not data.startswith(b'MThd'):
                    valid = False
                    details = "MIDI: Missing MThd header"
    
            # --- 7-Zip ---
            elif file_type == "7-Zip":
                if not data.startswith(b'\x37\x7A\xBC\xAF\x27\x1C'):
                    valid = False
                    details = "7-Zip: Missing header signature"
    
            # --- CAB ---
            elif file_type == "CAB":
                if not data.startswith(b'MSCF'):
                    valid = False
                    details = "CAB: Missing MSCF header"
    
            # --- UTF-encoded Text ---
            elif file_type in ["UTF-8 BOM (Text)", "UTF-16LE BOM (Text)", "UTF-16BE BOM (Text)"]:
                if not (data.startswith(b'\xEF\xBB\xBF') or data.startswith(b'\xFF\xFE') or data.startswith(b'\xFE\xFF')):
                    valid = False
                    details = f"{file_type}: Missing BOM marker"
    
            # --- RTF ---
            elif file_type == "RTF":
                if not data.startswith(b'{\\rtf1'):
                    valid = False
                    details = "RTF: Missing RTF header"
    
            # --- Ogg ---
            elif file_type == "Ogg":
                if not data.startswith(b'OggS'):
                    valid = False
                    details = "Ogg: Missing OggS header"
    
            # --- AVI ---
            elif file_type == "AVI":
                if not data.startswith(b'AVI '):
                    valid = False
                    details = "AVI: Missing AVI header"
    
            # --- FLV ---
            elif file_type == "FLV":
                if not data.startswith(b'FLV'):
                    valid = False
                    details = "FLV: Missing FLV header"
    
            # --- SWF ---
            elif file_type in ["SWF (Compressed)", "SWF (Uncompressed)"]:
                if not (data.startswith(b'CWS') or data.startswith(b'FWS')):
                    valid = False
                    details = "SWF: Missing CWS or FWS header"
    
            # --- Fonts (OTF/TTF) ---
            elif file_type in ["OTF Font", "TTF Font"]:
                if not (data.startswith(b'OTTO') or data.startswith(b'\x00\x01\x00\x00\x00')):
                    valid = False
                    details = f"{file_type}: Missing font header"
    
            # --- ISZ ---
            elif file_type == "ISZ":
                if not data.startswith(b'IsZ!'):
                    valid = False
                    details = "ISZ: Missing ISZ header"
    
            # --- DAA ---
            elif file_type == "DAA":
                if not data.startswith(b'DAA'):
                    valid = False
                    details = "DAA: Missing DAA header"
    
            # --- EVT/EVTX ---
            elif file_type in ["EVT", "EVTX"]:
                if not (data.startswith(b'LfLe') or data.startswith(b'ElfFile')):
                    valid = False
                    details = f"{file_type}: Missing event log header"
    
            # --- Windows Registry ---
            elif file_type == "Windows Registry":
                if not data.startswith(b'regf'):
                    valid = False
                    details = "Windows Registry: Missing regf header"
    
            # --- PST ---
            elif file_type == "PST":
                if not data.startswith(b'!BDN'):
                    valid = False
                    details = "PST: Missing PST header"
    
            # --- LZIP ---
            elif file_type == "LZIP":
                if not data.startswith(b'LZIP'):
                    valid = False
                    details = "LZIP: Missing LZIP header"
    
            # --- CPIO ---
            elif file_type == "CPIO":
                if not data.startswith(b'070707'):
                    valid = False
                    details = "CPIO: Missing CPIO header"
    
            # --- TIFF/BigTIFF ---
            elif file_type in ["TIFF (LE)", "TIFF (BE)", "BigTIFF (LE)", "BigTIFF (BE)"]:
                if not (data.startswith(b'II*\x00') or data.startswith(b'MM\x00*') or
                        data.startswith(b'II+\x00') or data.startswith(b'MM\x00+')):
                    valid = False
                    details = f"{file_type}: Missing TIFF/BigTIFF header"
    
            # --- DICOM ---
            elif file_type == "DICOM":
                if not data.startswith(b'DICM'):
                    valid = False
                    details = "DICOM: Missing DICM header"
    
            # --- FLAC ---
            elif file_type == "FLAC":
                if not data.startswith(b'fLaC'):
                    valid = False
                    details = "FLAC: Missing fLaC header"
    
            # --- AU/SND ---
            elif file_type == "AU/SND":
                if not data.startswith(b'.snd'):
                    valid = False
                    details = "AU/SND: Missing .snd header"
    
            # --- PostScript ---
            elif file_type == "PostScript":
                if not data.startswith(b'%!PS'):
                    valid = False
                    details = "PostScript: Missing %!PS header"
    
            # --- VDI/VHD/VHDX ---
            elif file_type in ["VDI (Oracle)", "VHD", "VHDX"]:
                if not (data.startswith(b'<<< ') or data.startswith(b'conectix') or data.startswith(b'vhdxfile')):
                    valid = False
                    details = f"{file_type}: Missing virtual disk header"
    
            # --- Crowdstrike SYS ---
            elif file_type == "Crowdstrike SYS":
                if not data.startswith(b'\xAA\xAA\xAA\xAA'):
                    valid = False
                    details = "Crowdstrike SYS: Missing signature"
    
            # --- ISO9660 ---
            elif file_type == "ISO9660":
                if not data.startswith(b'CC001'):
                    valid = False
                    details = "ISO9660: Missing header"
    
            # --- HL7 (MSH/BSH) ---
            elif file_type in ["HL7 (MSH)", "HL7 (BSH)"]:
                if not (data.startswith(b'MSH|') or data.startswith(b'BSH|')):
                    valid = False
                    details = f"{file_type}: Missing HL7 header"
    
            # --- MP4/M4A/M4V ---
            elif file_type == "MP4/M4A/M4V":
                if not data.startswith(b'\x00\x00\x00\x14ftypisom'):
                    valid = False
                    details = "MP4/M4A/M4V: Missing ftyp header"
    
            # --- PSD ---
            elif file_type == "PSD":
                if not data.startswith(b'FromHead'):
                    valid = False
                    details = "PSD: Missing PSD header"
    
            # --- Java Class ---
            elif file_type.startswith("Java Class"):
                if not (data.startswith(b'(fat code)') or data.startswith(b'\xCA\xFE\xBA\xBE') or
                        data.startswith(b'Caffeine')):
                    valid = False
                    details = "Java Class: Missing class file signature"
    
            # --- KDM ---
            elif file_type == "KDM":
                if not data.startswith(b'kdmf'):
                    valid = False
                    details = "KDM: Missing kdmf header"
    
            # --- DEB ---
            elif file_type == "DEB":
                if not data.startswith(b'DEADBEEF'):
                    valid = False
                    details = "DEB: Missing DEADBEEF header"
    
            # --- RPM ---
            elif file_type == "RPM":
                if not data.startswith(b'.rpm'):
                    valid = False
                    details = "RPM: Missing .rpm header"
    
            # --- IMG (Apple) ---
            elif file_type == "IMG (Apple)":
                if not data.startswith(b'\xF0\xED\xF0\xED'):
                    valid = False
                    details = "IMG (Apple): Missing signature"
    
            # --- ARC (FreeArc) ---
            elif file_type in ["ARC (FreeArc)", "ARC (FreeArc Alt)"]:
                if not (data.startswith(b'ARC\x01') or data.startswith(b'ARC\x00')):
                    valid = False
                    details = "ARC: Missing ARC header"
    
            # --- WEBM/MKV/MKA ---
            elif file_type == "WEBM/MKV/MKA":
                if not data.startswith(b'\x1A\x45\xDF\xA3'):
                    valid = False
                    details = "WEBM/MKV/MKA: Missing EBML header"
    
            # --- DMG (Apple) ---
            elif file_type == "DMG (Apple)":
                if not data.startswith(b'\xF7\xFF\xFF\xFF\xC8\xFF\xFF\xFF\xF6\xFF\xFF\xFF'):
                    valid = False
                    details = "DMG (Apple): Missing signature"
    
            # --- WASM ---
            elif file_type == "WASM":
                if not data.startswith(b'\x00asm'):
                    valid = False
                    details = "WASM: Missing WebAssembly header"
    
            # --- EXT3/EXT4 ---
            elif file_type == "EXT3/EXT4":
                if not data.startswith(b'EXT3'):
                    valid = False
                    details = "EXT3/EXT4: Missing filesystem signature"
    
            # --- BIN/DAT (Zero Filled) ---
            elif file_type == "BIN/DAT (Zero Filled)":
                if not data.startswith(b'\x00' * 16):
                    valid = False
                    details = "BIN/DAT: Missing zero-filled header"
    
            # --- CUR/ICO ---
            elif file_type == "CUR/ICO":
                if not data.startswith(b'\x00\x00\x01\x00'):
                    valid = False
                    details = "CUR/ICO: Missing icon header"
    
            # --- DWG/DXF ---
            elif file_type in ["DWG/DXF", "DWG (Alt)"]:
                if not (data.startswith(b'AC10') or data.startswith(b';DWGDiskFile')):
                    valid = False
                    details = "DWG/DXF: Missing drawing file header"
    
            # --- LZH/LHA ---
            elif file_type == "LZH/LHA":
                if not data.startswith(b'0000LHS'):
                    valid = False
                    details = "LZH/LHA: Missing archive header"
    
            # --- ZOO ---
            elif file_type == "ZOO":
                if not data.startswith(b'ZOO'):
                    valid = False
                    details = "ZOO: Missing ZOO header"
    
            # --- ADF ---
            elif file_type == "ADF":
                if not data.startswith(b'ADIF'):
                    valid = False
                    details = "ADF: Missing ADF header"
    
            # --- MDB ---
            elif file_type == "MDB":
                if not data.startswith(b'MSJET'):
                    valid = False
                    details = "MDB: Missing MSJET header"
    
            # --- JPEG 2000 (JP2) ---
            elif file_type == "JPEG 2000 (JP2)":
                if not data.startswith(b'\x00\x00\x00\x0CjFTYPmjp2'):
                    valid = False
                    details = "JPEG 2000: Missing JP2 header"
    
            # --- LN ---
            elif file_type == "LN":
                if not data.startswith(b'L\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46'):
                    valid = False
                    details = "LN: Missing LN header"
    
            # --- MPG/MPEG/DAT ---
            elif file_type.startswith("MPG/MPEG"):
                if not data[:4] in [b'\x00\x00\x01\xBA', b'\x00\x00\x01\xB3', b'\x00\x00\x01\xB6', b'\x00\x00\x01\xB7',
                                    b'\x00\x00\x01\xB8', b'\x00\x00\x01\xB9', b'\x00\x00\x01\xBC', b'\x00\x00\x01\xBE']:
                    valid = False
                    details = "MPG/MPEG: Missing valid MPEG header"
    
            # --- WMV/WMA/ASF ---
            elif file_type == "WMV/WMA/ASF":
                if not data.startswith(b'\x30\x26\xB2\x75\x8E\x66\xCF\x11\xA6\xD9\x00\xAA\x00\x62\xCE\x6C'):
                    valid = False
                    details = "WMV/WMA/ASF: Missing ASF header"
    
            # --- MDF ---
            elif file_type == "MDF":
                if not data.startswith(b'\x04\x22\x4D\x18'):
                    valid = False
                    details = "MDF: Missing MDF header"
    
            # --- SIMPLE TEXT ---
            elif file_type == "SIMPLE TEXT":
                if not data.startswith(b'SIMPLE'):
                    valid = False
                    details = "SIMPLE TEXT: Missing SIMPLE header"
    
            # --- PEM/CER/DER (X.509) ---
            elif file_type == "PEM/CER/DER (X.509)":
                if not data.startswith(b'0\x82'):
                    valid = False
                    details = "PEM/CER/DER: Missing X.509 header"
    
            # --- TXT (Spaces) ---
            elif file_type == "TXT (Spaces)":
                if not data.startswith(b'    '):
                    valid = False
                    details = "TXT (Spaces): Missing spaces header"
    
            # --- Shell Script (LIST) ---
            elif file_type == "Shell Script (LIST)":
                if not data.startswith(b'List'):
                    valid = False
                    details = "Shell Script (LIST): Missing List header"
    
            # --- GKS (Graphics Kernel System) ---
            elif file_type == "GKS (Graphics Kernel System)":
                if not data.startswith(b'GKSM'):
                    valid = False
                    details = "GKS: Missing GKSM header"
    
            # --- IRIS RGB ---
            elif file_type == "IRIS RGB":
                if not data.startswith(b'\x01\xDA'):
                    valid = False
                    details = "IRIS RGB: Missing IRIS header"
    
            # --- ITC (CMU WM) ---
            elif file_type == "ITC (CMU WM)":
                if not data.startswith(b'\xF1\x00\x40\xBB'):
                    valid = False
                    details = "ITC: Missing ITC header"
    
            # --- PM Format ---
            elif file_type == "PM Format":
                if not data.startswith(b'VIEW'):
                    valid = False
                    details = "PM Format: Missing VIEW header"
    
            # --- Sun Rasterfile ---
            elif file_type == "Sun Rasterfile":
                if not data.startswith(b'\x59\xA6\x6A\x95'):
                    valid = False
                    details = "Sun Rasterfile: Missing raster header"
    
            # --- XCF (GIMP) ---
            elif file_type == "XCF (GIMP)":
                if not data.startswith(b'gimp xcf v'):
                    valid = False
                    details = "XCF: Missing GIMP XCF header"
    
            # --- XFig Format ---
            elif file_type == "XFig Format":
                if not data.startswith(b'#FIG'):
                    valid = False
                    details = "XFig: Missing #FIG header"
    
            # --- XPM (X PixMap) ---
            elif file_type == "XPM (X PixMap)":
                if not data.startswith(b'/* XPM */'):
                    valid = False
                    details = "XPM: Missing XPM header"
    
            # --- BZIP ---
            elif file_type == "BZIP":
                if not data.startswith(b'BZ'):
                    valid = False
                    details = "BZIP: Missing BZ header"
    
            # --- Compress (.Z) ---
            elif file_type == "Compress (.Z)":
                if not data.startswith(b'\x1F\x9D'):
                    valid = False
                    details = "Compress (.Z): Missing .Z header"
    
            # --- PGP-related ---
            elif file_type in ["PGP Public Ring", "PGP Security Ring", "PGP Security Ring (Alt)", "PGP Encrypted Data"]:
                if not data[:2] in [b'\x99\x00', b'\x95\x01', b'\x95\x00', b'\xA6\x00']:
                    valid = False
                    details = f"{file_type}: Missing PGP header"
    
        except Exception as e:
            valid = False
            details = f"Failed to validate structure: {str(e)}"
    
        self.analysis_results["structure"] = {
            "Valid": "Yes" if valid else "No",
            "Details": details
        }
    
    def static_analysis(self, file_path):
        static_data = {}
        try:
            with open(file_path, "rb") as f:
                content = f.read()
                strings = [s.decode('utf-8', errors='ignore') for s in content.split() if len(s) > 4]
                static_data['strings'] = ", ".join(strings[:5]) if strings else "None"

            mean_entropy = self.analysis_results.get('entropy', {}).get('Mean Entropy', 0)
            static_data['obfuscation'] = "Possible" if mean_entropy > 7.5 else "None"
            static_data['signature'] = "N/A"  # Placeholder
        except Exception:
            static_data = {'strings': 'N/A', 'obfuscation': 'N/A', 'signature': 'N/A'}

        self.analysis_results['static'] = static_data

    def calculate_detection(self, file_path):
        detection = {"name": "N/A"}
        try:
            if self.analysis_results['risk']['Level'] == "HIGH" or self.analysis_results['spoof']['Spoof Detected'] == "Yes":
                detection['name'] = "Trojan.GenericKD.12345"
        except Exception:
            pass
        self.analysis_results['detection'] = detection

    def calculate_risk_score(self):
        risk_score = 0
        try:
            if self.analysis_results["magic"]["Status"] == "SPOOFED":
                risk_score += 50
            if self.analysis_results["entropy"]["Anomaly Detected"] == "Yes":
                risk_score += 30
            if self.analysis_results["magic"].get("Embedded Objects", {}).get("JavaScript", False) or self.analysis_results["magic"].get("Embedded Objects", {}).get("Executables", False):
                risk_score += 40
            try:
                rule = yara.compile(source='rule example {strings: $a = "malicious" condition: $a}')
                matches = rule.match(self.file_path)
                if matches:
                    risk_score += 60
            except Exception:
                pass
        except Exception:
            risk_score = 0

        self.analysis_results["risk"] = {
            "Score": risk_score,
            "Level": "LOW" if risk_score < 30 else "MEDIUM" if risk_score < 70 else "HIGH"
        }

    def generate_entropy_graph(self, entropies):
        if not entropies:
            return None

        fig, ax = plt.subplots(figsize=(6, 2))
        ax.bar(range(len(entropies)), entropies, color='#5c6bc0', edgecolor='#7986cb', width=0.8)
        ax.set_title('Entropy Distribution', fontsize=10)
        ax.set_ylim(0, 8)
        ax.set_xlabel('Chunk Index', fontsize=8)
        ax.set_ylabel('Entropy', fontsize=8)
        ax.set_xticks(range(0, min(len(entropies), 150), 20))
        ax.set_yticks(range(0, 9))
        ax.tick_params(axis='both', which='major', labelsize=6)
        plt.tight_layout()

        buffer = BytesIO()
        plt.savefig(buffer, format='png', dpi=150)
        buffer.seek(0)
        plt.close()
        return buffer