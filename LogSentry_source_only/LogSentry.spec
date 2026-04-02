# PyInstaller spec for LogSentry
# Build with: pyinstaller --noconfirm --clean LogSentry.spec

from pathlib import Path
from PyInstaller.utils.hooks import collect_submodules

project_dir = Path.cwd()

hiddenimports = collect_submodules('tkinterdnd2')
datas = []

sample_log = project_dir / 'sample_log.txt'
if sample_log.exists():
    datas.append((str(sample_log), '.'))

app = Analysis(
    ['gui.pyw'],
    pathex=[str(project_dir)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(app.pure)

exe = EXE(
    pyz,
    app.scripts,
    [],
    exclude_binaries=True,
    name='LogSentry',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    version='version_info.txt',
    icon='cybersecurity_curtis.ico',
)

coll = COLLECT(
    exe,
    app.binaries,
    app.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='LogSentry',
)
