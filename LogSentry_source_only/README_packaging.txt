LogSentry Packaging Guide
=========================

Files included:
- gui.pyw
- gui_debug.py
- analyzer.py
- sample_log.txt
- LogSentry.spec
- build_windows.bat
- version_info.txt
- requirements_packaging.txt

Fastest build path on Windows:
1. Put all files in one folder.
2. Double-click build_windows.bat.
3. Wait for PyInstaller to finish.
4. Open dist\LogSentry\LogSentry.exe.

What the build script does:
- installs PyInstaller and tkinterdnd2
- builds a windowed executable with no console
- bundles sample_log.txt
- writes version metadata into the EXE

Where files go:
- dist\LogSentry\LogSentry.exe
- dist\LogSentry\sample_log.txt

Notes:
- The app now reads bundled files through a packaging-safe resource path.
- Generated sample logs and startup error logs are written next to the EXE.
- If you want a custom icon later, replace icon=None in LogSentry.spec with your .ico file path.
- If Windows SmartScreen complains, that is normal for unsigned hobby builds.

Recommended test:
- Copy the finished dist\LogSentry folder to a different location.
- Launch LogSentry.exe there.
- Verify Browse, drag-and-drop, sample log loading, and exports all work.
