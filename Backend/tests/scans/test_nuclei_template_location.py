"""
The network Nuclei plugin finds the templates the image ships.

The backend image installs them at /opt/nuclei-templates and declares that as
NUCLEI_TEMPLATES_DIR. The plugin read only NUCLEI_TEMPLATES, fell back to
~/nuclei-templates, found nothing, and on the Linux VM skipped active template
verification on every network scan with one INFO line (13 Oct 2026).
"""

from __future__ import annotations

import os

from engines.vulnerability.plugins.nuclei_probe import _resolve_template_dir


def test_an_explicit_setting_wins():
    assert (
        _resolve_template_dir(
            {
                "NUCLEI_TEMPLATES": "/srv/t",
                "NUCLEI_TEMPLATES_DIR": "/opt/nuclei-templates",
            }
        )
        == "/srv/t"
    )


def test_the_images_declared_location_is_used_next():
    assert (
        _resolve_template_dir({"NUCLEI_TEMPLATES_DIR": "/opt/nuclei-templates"})
        == "/opt/nuclei-templates"
    )


def test_with_neither_the_tools_own_location_is_the_default():
    assert _resolve_template_dir({}) == os.path.join(
        os.path.expanduser("~"), "nuclei-templates"
    )
