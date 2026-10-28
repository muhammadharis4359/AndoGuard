"""Structural APK and session comparison engine."""

from typing import TYPE_CHECKING

from andoguard.models import ApkDiffResult

if TYPE_CHECKING:
    from andoguard.api import AndoGuard


def diff_andoguard_instances(ag_a: "AndoGuard", ag_b: "AndoGuard") -> ApkDiffResult:
    """Compare two AndoGuard target instances and return structural differences."""
    name_a = str(ag_a.target_info.target_path)
    name_b = str(ag_b.target_info.target_path)

    files_a = set(ag_a.files())
    files_b = set(ag_b.files())

    perms_a = set(ag_a.manifest.permissions())
    perms_b = set(ag_b.manifest.permissions())

    classes_a = set(ag_a.classes())
    classes_b = set(ag_b.classes())

    comps_a = {c.name for c in ag_a.manifest.components()}
    comps_b = {c.name for c in ag_b.manifest.components()}

    return ApkDiffResult(
        target_a=name_a,
        target_b=name_b,
        added_files=sorted(files_b - files_a),
        removed_files=sorted(files_a - files_b),
        added_permissions=sorted(perms_b - perms_a),
        removed_permissions=sorted(perms_a - perms_b),
        added_classes=sorted(classes_b - classes_a),
        removed_classes=sorted(classes_a - classes_b),
        added_components=sorted(comps_b - comps_a),
        removed_components=sorted(comps_a - comps_b),
    )
