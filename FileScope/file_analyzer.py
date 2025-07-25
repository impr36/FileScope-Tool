from Imports import *
from magic_db import magic_db

class FileAnalyzer:
    def __init__(self):
        self.analysis_results = {}
        self.magic_db = magic_db

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
            file_header = f.read(1024)
            detected_type = "Unknown"
            if file_header.startswith(b"\x52\x49\x46\x46") and file_header[8:12] == b"WEBP":
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

        metadata = {}
        try:
            with exiftool.ExifTool() as et:
                metadata = et.get_metadata(file_path)
                metadata["FileType"] = metadata.get("FileType", "UNKNOWN")
                metadata["CreateDate"] = metadata.get("CreateDate", "N/A")
        except Exception:
            metadata["FileType"] = "UNKNOWN"
            metadata["Error"] = "Metadata extraction failed"
            metadata["CreateDate"] = "N/A"

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

            is_pe = False
            pe_details = "No PE header found"
            if header[:2] == b"MZ":
                try:
                    e_lfanew = struct.unpack("<L", header[60:64])[0]
                    if e_lfanew < len(header) and header[e_lfanew:e_lfanew+4] == b"PE\0\0":
                        is_pe = True
                        pe_details = "Valid PE header found"
                except Exception as e:
                    pe_details = f"PE header check failed: {str(e)}"

            metadata = self.analysis_results["magic"]["Metadata"]
            declared_format = metadata.get("FileType", "UNKNOWN")
            spoof_detected = is_pe and declared_format not in ["EXE", "DLL", "PDF"] and self.analysis_results["magic"]["Detected Type"] != declared_format

            self.analysis_results["spoof"] = {
                "Spoof Detected": "Yes" if spoof_detected else "No",
                "Details": pe_details
            }
        except Exception:
            self.analysis_results["spoof"] = {"Spoof Detected": "N/A", "Details": "Failed to check header"}

    def pe_header_analysis(self, file_path):
        pe_info = {"Analyzed": False, "Details": "Not a PE file", "Imports": "N/A"}
        try:
            if self.analysis_results["magic"]["Detected Type"] == "DOS MZ (EXE)":
                with open(file_path, "rb") as f:
                    header = f.read(4096)
                    e_lfanew = struct.unpack("<L", header[60:64])[0]
                    if e_lfanew < len(header) and header[e_lfanew:e_lfanew+4] == b"PE\0\0":
                        optional_header_offset = e_lfanew + 24
                        machine = struct.unpack("<H", header[e_lfanew+4:e_lfanew+6])[0]
                        number_of_sections = struct.unpack("<H", header[e_lfanew+6:e_lfanew+8])[0]
                        time_date_stamp = struct.unpack("<L", header[e_lfanew+8:e_lfanew+12])[0]
                        entry_point = struct.unpack("<L", header[optional_header_offset+16:optional_header_offset+20])[0]

                        machine_types = {0x14c: "x86", 0x8664: "x64"}
                        machine_str = machine_types.get(machine, f"Unknown (0x{machine:04x})")
                        time_str = datetime.datetime.fromtimestamp(time_date_stamp).strftime('%Y-%m-%d %H:%M:%S')

                        pe_info = {
                            "Analyzed": True,
                            "Machine Type": machine_str,
                            "Number of Sections": number_of_sections,
                            "Compilation Time": time_str,
                            "Entry Point": f"0x{entry_point:08x}"
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
            if self.analysis_results["magic"]["Detected Type"] == "ZIP":
                with open(file_path, "rb") as f:
                    data = f.read()
                    if not data.endswith(b"\x50\x4B\x05\x06"):
                        valid = False
                        details = "Invalid ZIP end of central directory"
        except Exception:
            details = "Failed to validate structure"

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
