"""Android Manifest XML parser and metadata normalizer."""

import xml.etree.ElementTree as ET

from andoguard.models import (
    ManifestComponent,
    ManifestData,
    ManifestSecurityFlags,
)

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"


def _clean_val(val: str | None) -> str | None:
    return val.strip() if val else None


def _get_android_attr(
    elem: ET.Element, attr_name: str, default: str | None = None
) -> str | None:
    """Retrieve attribute matching android:<attr_name> regardless of namespace formatting."""
    # Check with full URI namespace
    val = elem.attrib.get(f"{ANDROID_NS}{attr_name}")
    if val is not None:
        return val
    # Check with prefix
    val = elem.attrib.get(f"android:{attr_name}")
    if val is not None:
        return val
    # Check plain attribute name
    val = elem.attrib.get(attr_name)
    if val is not None:
        return val
    return default


def parse_manifest_element(
    root: ET.Element, raw_xml: str | None = None
) -> ManifestData:
    """Parse an XML root element of AndroidManifest.xml into ManifestData."""
    pkg_name = root.attrib.get("package")
    ver_code_str = _get_android_attr(root, "versionCode")
    ver_name = _get_android_attr(root, "versionName")

    ver_code = int(ver_code_str) if ver_code_str and ver_code_str.isdigit() else None

    # uses-sdk
    min_sdk = None
    target_sdk = None
    uses_sdk_elem = root.find("uses-sdk")
    if uses_sdk_elem is not None:
        min_str = _get_android_attr(uses_sdk_elem, "minSdkVersion")
        tgt_str = _get_android_attr(uses_sdk_elem, "targetSdkVersion")
        if min_str and min_str.isdigit():
            min_sdk = int(min_str)
        if tgt_str and tgt_str.isdigit():
            target_sdk = int(tgt_str)

    # permissions
    permissions: list[str] = []
    for elem in root.findall("uses-permission"):
        p_name = _get_android_attr(elem, "name")
        if p_name and p_name not in permissions:
            permissions.append(p_name)

    # declared permissions
    declared_perms: list[str] = []
    for elem in root.findall("permission"):
        p_name = _get_android_attr(elem, "name")
        if p_name and p_name not in declared_perms:
            declared_perms.append(p_name)

    # application
    app_elem = root.find("application")
    sec_flags = ManifestSecurityFlags()
    components: list[ManifestComponent] = []

    if app_elem is not None:
        debuggable_str = _get_android_attr(app_elem, "debuggable", "false")
        sec_flags.debuggable = (debuggable_str or "false").lower() in ("true", "1")

        backup_str = _get_android_attr(app_elem, "allowBackup", "true")
        sec_flags.allow_backup = (backup_str or "true").lower() not in ("false", "0")

        cleartext_str = _get_android_attr(app_elem, "usesCleartextTraffic")
        if cleartext_str is not None:
            sec_flags.uses_cleartext_traffic = cleartext_str.lower() in ("true", "1")
        else:
            # Android default: Target SDK >= 28 defaults to False, otherwise True
            sec_flags.uses_cleartext_traffic = bool(target_sdk and target_sdk < 28)

        sec_flags.network_security_config = _get_android_attr(
            app_elem, "networkSecurityConfig"
        )

        test_only_str = _get_android_attr(app_elem, "testOnly", "false")
        sec_flags.test_only = (test_only_str or "false").lower() in ("true", "1")

        component_tags = [
            ("activity", "activity"),
            ("service", "service"),
            ("receiver", "receiver"),
            ("provider", "provider"),
        ]

        for tag_name, c_type in component_tags:
            for c_elem in app_elem.findall(tag_name):
                c_name = _get_android_attr(c_elem, "name")
                if not c_name:
                    continue

                if c_name.startswith(".") and pkg_name:
                    c_name = f"{pkg_name}{c_name}"

                permission = _get_android_attr(c_elem, "permission")

                # Parse intent filters
                intent_filters: list[dict[str, list[str]]] = []
                has_intent_filter = False
                for if_elem in c_elem.findall("intent-filter"):
                    has_intent_filter = True
                    filter_entry: dict[str, list[str]] = {
                        "actions": [],
                        "categories": [],
                        "data_schemes": [],
                    }
                    for act in if_elem.findall("action"):
                        a_name = _get_android_attr(act, "name")
                        if a_name:
                            filter_entry["actions"].append(a_name)
                    for cat in if_elem.findall("category"):
                        cat_name = _get_android_attr(cat, "name")
                        if cat_name:
                            filter_entry["categories"].append(cat_name)
                    for d in if_elem.findall("data"):
                        scheme = _get_android_attr(d, "scheme")
                        if scheme:
                            filter_entry["data_schemes"].append(scheme)
                    intent_filters.append(filter_entry)

                exported_attr = _get_android_attr(c_elem, "exported")
                if exported_attr is not None:
                    exported = exported_attr.lower() in ("true", "1")
                else:
                    # In Android, components with intent filters are exported by default
                    exported = has_intent_filter

                components.append(
                    ManifestComponent(
                        name=c_name,
                        component_type=c_type,
                        exported=exported,
                        permission=permission,
                        intent_filters=intent_filters,
                        attributes=dict(c_elem.attrib.items()),
                    )
                )

    return ManifestData(
        package_name=pkg_name,
        version_code=ver_code,
        version_name=ver_name,
        min_sdk_version=min_sdk,
        target_sdk_version=target_sdk,
        permissions=permissions,
        declared_permissions=declared_perms,
        components=components,
        security_flags=sec_flags,
        raw_xml=raw_xml,
    )
