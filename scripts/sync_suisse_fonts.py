#!/usr/bin/env python3
"""Create deterministic GPUI font assets from the sibling interface project.

This is a maintainer-only sync step. The generated TrueType files are checked in,
so application builds never depend on Python, fonttools, the interface checkout,
or the network.
"""

from pathlib import Path

from fontTools.ttLib import TTFont


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT.parent / "interface" / "src" / "assets" / "fonts" / "suisse"
DESTINATION = ROOT / "assets" / "fonts"

FONTS = (
    ("SuisseIntl-Regular-WebXL.woff2", "SuisseIntl-Regular.ttf", "Suisse Intl", "Regular"),
    ("SuisseIntl-Medium-WebXL.woff2", "SuisseIntl-Medium.ttf", "Suisse Intl", "Medium"),
    ("SuisseIntl-SemiBold-WebXL.woff2", "SuisseIntl-SemiBold.ttf", "Suisse Intl", "SemiBold"),
    ("SuisseIntl-Bold-WebXL.woff2", "SuisseIntl-Bold.ttf", "Suisse Intl", "Bold"),
    (
        "SuisseIntlMono-Regular-WebXL.woff2",
        "SuisseIntlMono-Regular.ttf",
        "Suisse Intl Mono",
        "Regular",
    ),
    (
        "SuisseIntlMono-Bold-WebXL.woff2",
        "SuisseIntlMono-Bold.ttf",
        "Suisse Intl Mono",
        "Bold",
    ),
)


def set_family_names(font: TTFont, family: str, style: str) -> None:
    name_table = font["name"]
    rewritten_ids = {1, 2, 3, 4, 6, 16, 17}
    name_table.names = [
        name for name in name_table.names if name.nameID not in rewritten_ids
    ]

    full_name = family if style == "Regular" else f"{family} {style}"
    postscript_name = f"{family.replace(' ', '')}-{style}"
    unique_name = f"Ekubo:{postscript_name}"
    values = {
        1: family,
        2: style,
        3: unique_name,
        4: full_name,
        6: postscript_name,
        16: family,
        17: style,
    }
    for platform_id, encoding_id, language_id in ((3, 1, 0x409), (1, 0, 0)):
        for name_id, value in values.items():
            name_table.setName(value, name_id, platform_id, encoding_id, language_id)


def main() -> None:
    DESTINATION.mkdir(parents=True, exist_ok=True)
    for source_name, destination_name, family, style in FONTS:
        source = SOURCE / source_name
        if not source.is_file():
            raise FileNotFoundError(f"missing Suisse source font: {source}")

        font = TTFont(source, recalcTimestamp=False)
        font.flavor = None
        set_family_names(font, family, style)
        font.save(DESTINATION / destination_name, reorderTables=False)


if __name__ == "__main__":
    main()
