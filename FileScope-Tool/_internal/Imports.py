import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinterdnd2 import DND_FILES, TkinterDnD
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, Image
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
import os
import datetime
from io import BytesIO
import random
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
import hashlib
import zipfile
import mutagen
from mutagen.mp3 import MP3
from PIL import Image
from PIL.ExifTags import TAGS
import sqlite3
import json
import pydicom
from mido import MidiFile
import tarfile
from py7zr import SevenZipFile
import xml.etree.ElementTree as ET
from rarfile import RarFile
from pycdlib import PyCdlib
from mutagen.flac import FLAC
from mutagen.oggvorbis import OggVorbis
from fontTools.ttLib import TTFont
import pymediainfo
from striprtf.striprtf import rtf_to_text
import winreg
import gzip
import exiftool
import yara
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.lib.utils import ImageReader