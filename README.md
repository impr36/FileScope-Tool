# FileScope-Tool
Magic Number Check:
-The magic_db was incorrectly placed inside the magic_number_check method. It has been moved to the appropriate scope within the method for clarity. -Added bounds checking in the match_magic function to prevent index errors when the file is too small to contain the header or footer. -Fixed the Photoshop entry in magic_db (changed "FromHead" to "8BPS" for correct PSD file identification). -Added error handling to catch and report issues during file reading or magic number analysis. -Ensured file_type is properly defined by storing it in the instance (self.file_type) after the MIME detection.

Error Handling:
-Added comprehensive error handling across all analysis methods (magic_number_check, entropy_analysis, header_spoof_check, byte_pattern_analysis, structure_validation, display_results, plot_entropy, and export_pdf) to prevent crashes and provide meaningful feedback to the user via the output text box or message boxes. -Added checks for empty files or invalid file paths in analyze_file and other methods.

Entropy Plot:
-Fixed the entropy plot to dynamically calculate bar width based on the number of entropy values to prevent overlap or incorrect scaling. -Added error handling to display an error message on the canvas if plotting fails.

Debug Information:
-Added a Debug field to analysis_results["magic"] to store detailed information about what happened during the analysis. -The match_magic function now returns a tuple containing the matched entry (or None) and a debug message explaining why no match was found. -Debug messages are inserted into the output text box to help identify the issue (e.g., "Empty file or no data read" or "No matching magic number found").

File Validation:
-Added an explicit check for file existence and readability at the start of the method.

Improved MIME Detection:
-Stored the file_type in self.file_type to ensure it's available for other methods. -Added error handling to catch issues with python-magic and report them in the output.

Robust Magic Number Matching:
-Ensured the file is checked for sufficient length before attempting to match headers or footers. -Added a check for empty files in match_magic.

Output Enhancement:
-The debug information is displayed in the output text box, making it easier to see why the file type is "Unknown".

Notes:
The code assumes the tkinterdnd2, python-magic, and reportlab libraries are installed. Ensure they are available in your environment: pip install tkinterdnd2 python-magic reportlab

On some systems, python-magic-bin may be needed instead of python-magic for Windows compatibility: pip install python-magic-bin

The magic library requires libmagic to be installed on the system (e.g., libmagic1 on Ubuntu or file on macOS via Homebrew).

The entropy graph is a simple visualization. You may want to enhance it with labels or a scale for better usability.

The byte_pattern_analysis method uses a simplistic approach to EXE detection. Consider expanding the bigram database or using more sophisticated pattern analysis for real-world use.

Installation Commands(terminal VS Code):
curl -o python-installer.exe https://www.python.org/ftp/python/3.13.0/python-3.13.0-amd64.exe python --version pip --version

DON'T FOREGET TO SET PATH IN THE ENVIRONMENT VARIABLES(IF NOT ADDED)

pip install numpy

pip install tkinterdnd2

pip install python-magic-bin

pip install reportlab

pip install matplotlib
