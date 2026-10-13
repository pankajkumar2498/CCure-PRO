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


def test_the_image_makes_the_templates_readable_to_non_root():
    # `nuclei -update-templates` creates 0700 directories and COPY keeps the
    # mode: as the image's own `ccure` user nuclei found no templates at all.
    from testpaths import BACKEND_ROOT

    dockerfile = (BACKEND_ROOT / "Dockerfile").read_text(encoding="utf-8")
    update = dockerfile.index("nuclei -update-templates")
    copy = dockerfile.index("/root/nuclei-templates /opt/nuclei-templates")
    chmod = dockerfile.index("chmod -R a+rX /root/nuclei-templates")
    assert update < chmod < copy
