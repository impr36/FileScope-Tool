# 🔍 FileScope

**See Beyond the Surface of Your Files**

FileScope is a powerful, open-source Python tool for in-depth file analysis. Whether you're a cybersecurity enthusiast, developer, or just curious, FileScope helps you uncover what's really inside your files—file types, metadata, entropy, hidden risks, and more—all wrapped in a clean, drag-and-drop GUI with PDF report generation.

---

## ✨ Features

### 🔍 Deep File Analysis
- Detects file types using magic numbers and over **80+ known signatures**.
- Extracts metadata (creation/modification times, size, etc.).
- Calculates MD5, SHA1, and SHA256 checksums.
- Performs **entropy analysis** to flag encryption or obfuscation.
- Validates file headers and structure.
- Extracts embedded objects and metadata (PDF, ZIP, JPEG, MP3, and more).

### 🗂️ Broad Format Support
- **Images**: JPEG, PNG, GIF, BMP  
- **Archives**: ZIP, RAR, 7z, TAR, GZIP  
- **Audio/Video**: MP3, FLAC, Ogg, MP4, WEBM  
- **Documents**: PDF, RTF, XML, JSON  
- **Executables**: EXE, ELF  
- **Fonts**: TTF, OTF  
- ...and many more! *(See `magic_db.py` for the full list.)*

### 🖥️ Interactive GUI
- Built with **Tkinter + TkinterDnD2**.
- Drag-and-drop support for instant file analysis.
- Clean and intuitive interface.
- **One-click PDF report** with visual entropy graphs via ReportLab.

### 🧩 Modular Architecture
- Modular design with separate files for:
  - Magic number detection: `CheckMagic.py`
  - File signature database: `magic_db.py`
- Easily extendable to support new formats or features.

### 🔐 Security-Focused
- Detects spoofed headers and suspicious embedded objects (e.g., JavaScript in PDFs).
- Generates a **risk score** for each file.
- Flags hidden executable-like behavior in non-executables.

---

## 🚀 Getting Started

### ✅ Prerequisites
- **Python 3.11 or 3.12** (Python 3.13 may cause compatibility issues).
- **Linux dependencies**:
  ```bash
  sudo apt-get install libmagic1 python3-tk
### ✅ Prerequisites
- **Python 3.11 or 3.12** (Python 3.13 may have compatibility issues).
- On **Linux**, install system dependencies:
  ```bash
  sudo apt-get install libmagic1 python3-tk
  sudo apt-get install python3-tkinterdnd2  # if needed
  
### 💾 Installation
```bash
# Clone the repository
git clone https://github.com/your-username/filescope-tool.git
cd filescope-tool

# (Recommended) Create a virtual environment for linux
python -m venv venv
source venv/bin/activate  # On Windows: .\venv\Scripts\activate

# Install dependencies for window and linux
pip install -r requirements.txt
```
Dependencies include:
```
matplotlib
python-magic-bin      # Use python-magic on Linux
numpy
PyPDF2
mutagen
Pillow
pydicom
mido
py7zr
rarfile
pycdlib
fonttools
pymediainfo
striprtf
tkinterdnd2
reportlab
⚠️ Windows users: If python-magic-bin fails, manually install libmagic. See Troubleshooting.
```
### ▶️ Run the Tool
```bash
python gui3.py
#Drag and drop a file into the GUI or click to browse. FileScope will analyze it and display results. You can also generate a detailed PDF report.
```
📁 Project Structure
```bash
filescope-tool/
├── CheckMagic.py       # Magic number detection logic
├── file_analyzer.py   # Core file analysis logic
├── magic_db.py         # Signature database
├── GUI.py             # GUI application
├── requirements.txt    # Dependency list
└── README.md           # This file
```
### 🖱️ Usage
Launch the GUI:

```bash

python gui3.py
Drag-and-drop or use the file picker to select a file.
```
### View:

-File type and extension match  
-Timestamps and metadata  
-Hash values (MD5/SHA1/SHA256)  
-Entropy graph  
-Risk score & possible threats  
-Click to export a full PDF report.  

### 🛠️ Troubleshooting
❌ Windows: ImportError: failed to find libmagic
Make sure python-magic-bin is installed:

```bash

pip install python-magic-bin
```
If the error persists:
Download magic.dll and magic.mgc from: https://github.com/nscaife/file-win32/releases.  
Place them in C:\Windows\System32 or add to your PATH.  

### 🐧 Linux: Missing Dependencies
```bash
sudo apt-get install libmagic1 python3-tk
🐍 Python 3.13 Compatibility
```
Some packages (like pydicom, tkinterdnd2) may not work with Python 3.13.   
Use:  
```bash
python3.11 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```
### 📦 RPM Support
The tool handles the lack of rpm support on non-Linux systems gracefully (via try-except block).


