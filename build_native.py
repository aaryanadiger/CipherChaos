"""Build the C DSA library using MSVC on Windows or a C compiler on Unix."""
import argparse
import hashlib
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
NATIVE = ROOT / 'native'
MACHINE = 'x64' if sys.maxsize > 2**32 else 'x86'
PLATFORM = 'windows-' + MACHINE if os.name == 'nt' else platform.system().lower() + '-' + platform.machine()
LIBRARY = NATIVE / 'bin' / PLATFORM / ('cc_dsa.dll' if os.name == 'nt' else 'libcc_dsa.dylib' if sys.platform == 'darwin' else 'libcc_dsa.so')


def source_digest():
    return hashlib.sha256(b''.join((NATIVE / name).read_bytes().replace(b'\r\n', b'\n')
                                  for name in ('cc_dsa.h', 'cc_dsa.c'))).hexdigest()


def build(force=False, test=False):
    stamp = LIBRARY.with_suffix('.sha256')
    digest = source_digest()
    current = not force and LIBRARY.exists() and stamp.exists() and stamp.read_text().strip() == digest
    if current and not test:
        return LIBRARY
    LIBRARY.parent.mkdir(parents=True, exist_ok=True)
    if os.name == 'nt':
        vswhere = Path(os.environ.get('ProgramFiles(x86)', r'C:\Program Files (x86)')) / 'Microsoft Visual Studio/Installer/vswhere.exe'
        if not vswhere.exists():
            raise RuntimeError('Install Visual Studio C++ Build Tools, then run python build_native.py.')
        installation = subprocess.check_output([str(vswhere), '-latest', '-products', '*', '-requires',
            'Microsoft.VisualStudio.Component.VC.Tools.x86.x64', '-property', 'installationPath'], text=True).strip()
        if not installation:
            raise RuntimeError('Visual Studio C++ build tools were not found.')
        vcvars = Path(installation) / 'VC/Auxiliary/Build' / ('vcvars64.bat' if MACHINE == 'x64' else 'vcvars32.bat')
        result = subprocess.run(f'cmd /d /s /c ""{vcvars}" >nul && set"',
                                capture_output=True, text=True, check=True)
        environment = os.environ.copy()
        for line in result.stdout.splitlines():
            key, separator, value = line.partition('=')
            if separator and key:
                environment[key] = value
        compiler = shutil.which('cl.exe', path=environment.get('Path', environment.get('PATH', '')))
        if not compiler:
            raise RuntimeError('MSVC environment did not provide cl.exe.')
        flags = [compiler, '/nologo', '/std:c11', '/W4', '/WX', '/O2', '/MT']
        if not current:
            subprocess.run(flags + ['/LD', str(NATIVE / 'cc_dsa.c'), '/Fe:' + str(LIBRARY),
                '/Fo:' + str(LIBRARY.parent / 'cc_dsa.obj'), '/link',
                '/IMPLIB:' + str(LIBRARY.parent / 'cc_dsa.lib')], env=environment, check=True)
        if test:
            executable = LIBRARY.parent / 'test_dsa.exe'
            subprocess.run(flags + [str(NATIVE / 'cc_dsa.c'), str(NATIVE / 'test_dsa.c'),
                '/Fe:' + str(executable), '/Fo:' + str(LIBRARY.parent) + os.sep], env=environment, check=True)
            subprocess.run([str(executable)], check=True)
    else:
        compiler = os.environ.get('CC') or shutil.which('cc') or shutil.which('gcc') or shutil.which('clang')
        if not compiler:
            raise RuntimeError('Install a C compiler, then run python build_native.py.')
        flags = [compiler, '-std=c11', '-Wall', '-Wextra', '-Werror', '-O2']
        if not current:
            subprocess.run(flags + ['-fPIC', '-dynamiclib' if sys.platform == 'darwin' else '-shared',
                str(NATIVE / 'cc_dsa.c'), '-o', str(LIBRARY)], check=True)
        if test:
            executable = LIBRARY.parent / 'test_dsa'
            subprocess.run(flags + [str(NATIVE / 'cc_dsa.c'), str(NATIVE / 'test_dsa.c'),
                '-o', str(executable)], check=True)
            subprocess.run([str(executable)], check=True)
    stamp.write_text(digest + '\n', encoding='ascii')
    return LIBRARY


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--force', action='store_true')
    parser.add_argument('--test', action='store_true', help='Compile and run standalone C assertions.')
    args = parser.parse_args()
    print(build(force=args.force, test=args.test))
