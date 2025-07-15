FileScope 🔍
Uncover the Secrets of Your Files!
FileScope is a powerful, open-source Python tool designed to analyze files with precision and ease. Whether you're a cybersecurity enthusiast, a developer, or just curious about what’s inside your files, FileScope provides deep insights into file types, metadata, entropy, and potential risks—all wrapped in a user-friendly GUI with drag-and-drop support and PDF report generation.
✨ Features

Comprehensive File Analysis:

Identifies file types using magic numbers and a robust database of over 80 file signatures.
Analyzes file metadata, including creation, modification, and access times.
Computes MD5, SHA1, and SHA256 hashes for file integrity verification.
Performs entropy analysis to detect potential obfuscation or encryption.
Checks for header spoofing and validates file structures.
Extracts embedded objects and metadata from formats like PDF, ZIP, JPEG, MP3, and more.


Supported File Formats:

Images (JPEG, PNG, GIF, BMP)
Archives (ZIP, RAR, 7z, TAR, GZIP)
Audio/Video (MP3, FLAC, Ogg, MP4, WEBM)
Documents (PDF, RTF, XML, JSON)
Executables (EXE, ELF) and fonts (TTF, OTF)
And many more (see magic_db.py for the full list)!


Interactive GUI:

Built with Tkinter and TkinterDnD2 for drag-and-drop file selection.
Displays detailed analysis results in an intuitive interface.
Generates professional PDF reports with embedded entropy graphs using ReportLab.


Modular Design:

Separated logic for magic number checking (CheckMagic.py) and file signatures (magic_db.py).
Extensible architecture for adding new file types and analysis methods.


Security Insights:

Detects potential spoofing and suspicious embedded objects (e.g., JavaScript in PDFs).
Calculates risk scores based on file characteristics.
Identifies executable-like patterns in non-executable files.



🚀 Getting Started
Prerequisites

Python: Version 3.11 or 3.12 (Python 3.13 may have compatibility issues with some dependencies).
System Dependencies (for Linux users):
Install libmagic1 for file type detection: sudo apt-get install libmagic1
Install Tkinter: sudo apt-get install python3-tk
Install TkinterDnD2 dependencies (if needed): sudo apt-get install python3-tkinterdnd2



Installation

Clone the Repository:
git clone https://github.com/your-username/filescope-tool.git
cd filescope-tool


Set Up a Virtual Environment (recommended):
python -m venv venv
source venv/bin/activate  # On Windows: .\venv\Scripts\activate


Install Dependencies:
pip install -r requirements.txt

The requirements.txt includes:
matplotlib
python-magic-bin  # Use python-magic on Linux
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

Note for Windows Users: If python-magic-bin fails, ensure libmagic is installed (see Troubleshooting).

Run the Tool:
python gui3.py

Drag and drop a file onto the GUI or click to select a file for analysis. Results are displayed in the GUI, and you can generate a PDF report with detailed findings.


📂 Project Structure
filescope-tool/
├── CheckMagic.py       # Magic number checking logic
├── file_analyzer3.py   # Core file analysis class
├── magic_db.py        # Database of file signatures
├── gui3.py            # GUI implementation with Tkinter
├── requirements.txt    # Python dependencies
└── README.md          # This file

🖱️ Usage

Launch gui3.py to open the FileScope GUI.
Drag and drop a file or use the file picker to select a file.
View the analysis results, including:
File type and extension validation
Metadata (creation/modification times, hashes)
Entropy analysis with a visual graph
Risk score and potential security issues


Click to generate a PDF report summarizing the analysis, complete with an entropy distribution graph.

🛠️ Troubleshooting

Windows: ImportError: failed to find libmagic:
Ensure python-magic-bin is installed (pip install python-magic-bin).
Alternatively, install libmagic manually:
Download from https://github.com/nscaife/file-win32/releases.
Add magic.dll and magic.mgc to C:\Windows\System32 or your PATH.




Linux: Missing system dependencies:
Install libmagic1: sudo apt-get install libmagic1.
Install Tkinter: sudo apt-get install python3-tk.


Python 3.13 Issues: Some packages (e.g., tkinterdnd2, pydicom) may not support Python 3.13. Use Python 3.11 or 3.12:python3.11 -m venv venv
source venv/bin/activate
pip install -r requirements.txt


RPM Analysis: The rpm module is not included as it’s Linux-specific and unsupported on Windows. The code handles this gracefully with a try-except block.

🤝 Contributing
Contributions are welcome! To contribute:

Fork the repository.
Create a feature branch (git checkout -b feature/your-feature).
Commit your changes (git commit -m "Add your feature").
Push to the branch (git push origin feature/your-feature).
Open a pull request.

Please include tests and update documentation for new features.
📜 License
This project is licensed under the MIT License. See the LICENSE file for details.
🙌 Acknowledgments

Built with Python, Tkinter, and ReportLab.
Inspired by the need for accessible, open-source file analysis tools.
Thanks to the open-source community for libraries like python-magic, Pillow, and mutagen.

📬 Contact
Have questions or suggestions? Open an issue or reach out to your-username.
FileScope: See Beyond the Surface of Your Files! 🔍
