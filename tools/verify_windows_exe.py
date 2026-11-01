"""Inspect the generated PE's GUI, icon and UAC manifest without running it."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from xml.etree import ElementTree

import pefile


def verify_executable(path: Path) -> dict[str, bool]:
    """Validate that the on-disk PE exposes the required branding resources."""
    if not path.is_file() or path.suffix.lower() != '.exe':
        raise ValueError('Se esperaba un archivo EXE existente')

    executable = pefile.PE(str(path), fast_load=True)
    try:
        executable.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']]
        )
        gui = executable.OPTIONAL_HEADER.Subsystem == 2
        resources = getattr(executable, 'DIRECTORY_ENTRY_RESOURCE', None)
        icon = False
        admin_manifest = False
        if resources is not None:
            for entry in resources.entries:
                if entry.id == 14:  # RT_GROUP_ICON
                    icon = True
                if entry.id != 24:  # RT_MANIFEST
                    continue
                for named in entry.directory.entries:
                    for language in named.directory.entries:
                        data = language.data.struct
                        raw = executable.get_data(data.OffsetToData, data.Size)
                        try:
                            xml = ElementTree.fromstring(raw)
                        except ElementTree.ParseError:
                            continue
                        if any(elem.tag.endswith('requestedExecutionLevel') and
                               elem.attrib.get('level') == 'requireAdministrator'
                               for elem in xml.iter()):
                            admin_manifest = True
        return {'windows_gui_subsystem': gui,
                'embedded_application_icon': icon,
                'uac_requires_admin': admin_manifest}
    finally:
        executable.close()


def main() -> int:
    """Read a single command-line executable and report verified properties."""
    parser = argparse.ArgumentParser()
    parser.add_argument('exe', type=Path)
    arguments = parser.parse_args()
    try:
        result = verify_executable(arguments.exe)
    except (OSError, ValueError, pefile.PEFormatError) as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        return 2
    for key, verified in result.items():
        print(f'{key}: {"OK" if verified else "FALTA"}')
    return 0 if all(result.values()) else 1


if __name__ == '__main__':
    raise SystemExit(main())
