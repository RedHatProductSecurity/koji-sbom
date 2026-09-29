"""Tests for koji_sbom.generate (metadata-only Koji → SPDX)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from koji_sbom.assembly import binary_spdx_id
from koji_sbom.generate import (
    DEFAULT_FEDORA_KOJI_URL,
    FEDORA,
    generate_sbom,
    koji_hub_from_env,
    main,
    resolve_koji_hub,
    write_sbom_outputs,
)
from koji_sbom.models import RpmDep


def _build() -> dict[str, Any]:
    return {
        "build_id": 123,
        "package_name": "openssl",
        "name": "openssl",
        "version": "3.2.2",
        "release": "1.el10",
        "nvr": "openssl-3.2.2-1.el10",
        "epoch": 0,
    }


def _rpms() -> list[dict[str, Any]]:
    return [
        {"id": 1, "name": "openssl", "arch": "src", "nvr": "openssl-3.2.2-1.el10.src.rpm"},
        {"id": 2, "name": "openssl", "arch": "x86_64", "nvr": "openssl-3.2.2-1.el10.x86_64.rpm"},
        {"id": 3, "name": "openssl", "arch": "noarch", "nvr": "openssl-3.2.2-1.el10.noarch.rpm"},
        {
            "id": 4,
            "name": "openssl-debuginfo",
            "arch": "x86_64",
            "nvr": "openssl-debuginfo-3.2.2-1.el10.x86_64.rpm",
        },
        {"id": 5, "name": "openssl", "arch": "aarch64", "nvr": "openssl-3.2.2-1.el10.aarch64.rpm"},
    ]


def _bundled_provides() -> list[RpmDep]:
    return [
        RpmDep("bundled(libvterm)", "0.3.3", 1),
        RpmDep("golang(github.com/example/pkg)", "1.2.3", 1),
    ]


@patch("koji_sbom.generate.rpm_provides_and_requires_for_build")
@patch("koji_sbom.generate.KojiClient")
def test_generate_sbom_produces_rhel_shaped_document(
    mock_client_cls: MagicMock,
    mock_deps: MagicMock,
) -> None:
    client = mock_client_cls.return_value
    client.get_build.return_value = _build()
    client.list_rpms.return_value = _rpms()
    mock_deps.return_value = ([], [])

    sbom = generate_sbom("https://kojihub.example/kojihub", nvr="openssl-3.2.2-1.el10")

    assert sbom["spdxVersion"] == "SPDX-2.3"
    assert sbom["name"] == "openssl-3.2.2-1.el10"
    assert sbom["documentDescribes"] == ["SPDXRef-SRPM"]
    assert sbom["creationInfo"]["creators"] == ["Tool: koji-sbom-0.1.1"]
    assert sbom["creationInfo"]["created"].endswith("Z")

    pkg_ids = {p["SPDXID"] for p in sbom["packages"]}
    assert "SPDXRef-SRPM" in pkg_ids
    assert binary_spdx_id("openssl", "x86_64") in pkg_ids
    assert binary_spdx_id("openssl", "noarch") in pkg_ids
    assert binary_spdx_id("openssl-debuginfo", "x86_64") not in pkg_ids
    assert len(sbom["packages"]) == 3

    rel_types = {(r["spdxElementId"], r["relationshipType"]) for r in sbom["relationships"]}
    assert ("SPDXRef-DOCUMENT", "DESCRIBES") in rel_types
    assert (binary_spdx_id("openssl", "x86_64"), "GENERATED_FROM") in rel_types

    srpm = next(p for p in sbom["packages"] if p["SPDXID"] == "SPDXRef-SRPM")
    binary = next(p for p in sbom["packages"] if p["SPDXID"] == binary_spdx_id("openssl", "x86_64"))
    assert srpm["primaryPackagePurpose"] == "SOURCE"
    assert binary["primaryPackagePurpose"] == "LIBRARY"
    assert any("arch=src" in ref["referenceLocator"] for ref in srpm["externalRefs"])
    assert any("arch=x86_64" in ref["referenceLocator"] for ref in binary["externalRefs"])
    assert all("pkg:rpm/redhat/" in ref["referenceLocator"] for ref in srpm["externalRefs"])


@patch("koji_sbom.generate.rpm_provides_and_requires_for_build")
@patch("koji_sbom.generate.KojiClient")
def test_generate_sbom_fedora_namespace_purls(
    mock_client_cls: MagicMock,
    mock_deps: MagicMock,
) -> None:
    client = mock_client_cls.return_value
    client.get_build.return_value = _build()
    client.list_rpms.return_value = _rpms()
    mock_deps.return_value = ([], [])

    sbom = generate_sbom(
        "https://koji.fedoraproject.org/kojihub",
        nvr="openssl-3.2.2-1.fc45",
        namespace="fedora",
    )

    srpm = next(p for p in sbom["packages"] if p["SPDXID"] == "SPDXRef-SRPM")
    assert any("pkg:rpm/fedora/" in ref["referenceLocator"] for ref in srpm["externalRefs"])


@patch("koji_sbom.generate.rpm_provides_and_requires_for_build")
@patch("koji_sbom.generate.KojiClient")
def test_generate_sbom_includes_bundled_provides(
    mock_client_cls: MagicMock,
    mock_deps: MagicMock,
) -> None:
    client = mock_client_cls.return_value
    client.get_build.return_value = _build()
    client.list_rpms.return_value = _rpms()
    mock_deps.return_value = (_bundled_provides(), [])

    sbom = generate_sbom("https://kojihub.example/kojihub", build_id=123)

    bundled_pkgs = [p for p in sbom["packages"] if p["SPDXID"].startswith("SPDXRef-Bundled-")]
    assert bundled_pkgs
    bundled_rels = [
        r
        for r in sbom["relationships"]
        if r.get("relationshipType") == "DEPENDENCY_OF"
        and r.get("relatedSpdxElement") == "SPDXRef-SRPM"
    ]
    assert len(bundled_rels) == len(bundled_pkgs)


@patch("koji_sbom.generate.rpm_provides_and_requires_for_build")
@patch("koji_sbom.generate.KojiClient")
def test_generate_sbom_passes_module_nsvc_and_cpe_refs(
    mock_client_cls: MagicMock,
    mock_deps: MagicMock,
) -> None:
    client = mock_client_cls.return_value
    client.get_build.return_value = _build()
    client.list_rpms.return_value = _rpms()
    mock_deps.return_value = ([], [])

    sbom = generate_sbom(
        "https://kojihub.example/kojihub",
        nvr="openssl-3.2.2-1.el10",
        module_nsvc="openssl:3.2:1234567890:deadbeef",
        cpe_refs=["cpe:2.3:a:redhat:enterprise_linux:10:*:*:*:*:*:*:*"],
    )

    srpm = next(p for p in sbom["packages"] if p["SPDXID"] == "SPDXRef-SRPM")
    locators = [ref["referenceLocator"] for ref in srpm["externalRefs"]]
    assert any("rpmmod=openssl:3.2:1234567890:deadbeef" in loc for loc in locators)
    assert any(loc.startswith("cpe:2.3:") for loc in locators)


def test_write_sbom_outputs_writes_spdx(tmp_path: Path) -> None:
    build = _build()
    sbom = {"spdxVersion": "SPDX-2.3", "name": build["nvr"], "packages": [], "relationships": []}
    out = tmp_path / "openssl" / "openssl-rpm-sbom.json"
    write_sbom_outputs(sbom, out)

    assert out.is_file()
    written = json.loads(out.read_text(encoding="utf-8"))
    assert written["name"] == build["nvr"]


@patch("koji_sbom.generate.KojiClient")
def test_generate_sbom_build_not_found(mock_client_cls: MagicMock) -> None:
    mock_client_cls.return_value.get_build.return_value = None
    with pytest.raises(LookupError, match="build not found"):
        generate_sbom("https://kojihub.example/kojihub", nvr="missing-1-1.el10")


@patch("koji_sbom.generate.rpm_provides_and_requires_for_build")
@patch("koji_sbom.generate.KojiClient")
def test_generate_sbom_propagates_list_rpms_failure(
    mock_client_cls: MagicMock,
    mock_deps: MagicMock,
) -> None:
    client = mock_client_cls.return_value
    client.get_build.return_value = _build()
    client.list_rpms.side_effect = TimeoutError("conn timed out")
    mock_deps.return_value = ([], [])

    with pytest.raises(TimeoutError, match="conn timed out"):
        generate_sbom("https://kojihub.example/kojihub", nvr="openssl-3.2.2-1.el10")


def test_generate_sbom_requires_exactly_one_identifier() -> None:
    with pytest.raises(ValueError, match="exactly one"):
        generate_sbom("https://kojihub.example/kojihub")
    with pytest.raises(ValueError, match="exactly one"):
        generate_sbom(
            "https://kojihub.example/kojihub",
            nvr="openssl-3.2.2-1.el10",
            build_id=123,
        )


def test_resolve_koji_hub_prefers_flag_and_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("KOJI_URL", raising=False)
    monkeypatch.delenv("KOJI_HUB", raising=False)

    assert resolve_koji_hub("https://cli.example/kojihub") == "https://cli.example/kojihub"
    assert resolve_koji_hub() == DEFAULT_FEDORA_KOJI_URL

    monkeypatch.setenv("KOJI_HUB", "https://hub.example/kojihub")
    assert resolve_koji_hub() == "https://hub.example/kojihub"

    monkeypatch.setenv("KOJI_URL", "https://env.example/kojihub")
    assert resolve_koji_hub() == "https://hub.example/kojihub"


@patch("koji_sbom.generate.resolve_newer_epel_nvr", side_effect=lambda nvr: nvr)
@patch("koji_sbom.generate.generate_sbom")
def test_main_defaults_to_fedora_koji(
    mock_generate: MagicMock,
    _mock_bodhi: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("KOJI_URL", raising=False)
    monkeypatch.delenv("KOJI_HUB", raising=False)
    mock_generate.return_value = {"spdxVersion": "SPDX-2.3", "name": "openssl-3.2.2-1.el10"}

    rc = main(["openssl-3.2.2-1.el10"])

    assert rc == 0
    mock_generate.assert_called_once_with(
        DEFAULT_FEDORA_KOJI_URL,
        nvr="openssl-3.2.2-1.el10",
        build_id=None,
        namespace=FEDORA,
    )


def test_koji_hub_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("KOJI_URL", raising=False)
    monkeypatch.delenv("KOJI_HUB", raising=False)
    assert koji_hub_from_env() is None

    monkeypatch.setenv("KOJI_URL", "https://koji.example/kojihub")
    assert koji_hub_from_env() == "https://koji.example/kojihub"

    monkeypatch.setenv("KOJI_HUB", "https://hub.example/kojihub")
    assert koji_hub_from_env() == "https://hub.example/kojihub"


@patch("koji_sbom.generate.resolve_newer_epel_nvr", side_effect=lambda nvr: nvr)
@patch("koji_sbom.generate.generate_sbom")
def test_main_positional_nvr_writes_stdout(
    mock_generate: MagicMock,
    _mock_bodhi: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("KOJI_HUB", "https://kojihub.example/kojihub")
    mock_generate.return_value = {"spdxVersion": "SPDX-2.3", "name": "openssl-3.2.2-1.el10"}

    rc = main(["openssl-3.2.2-1.el10"])

    assert rc == 0
    mock_generate.assert_called_once_with(
        "https://kojihub.example/kojihub",
        nvr="openssl-3.2.2-1.el10",
        build_id=None,
        namespace=FEDORA,
    )
    out = capsys.readouterr().out
    assert json.loads(out)["name"] == "openssl-3.2.2-1.el10"


@patch("koji_sbom.generate.resolve_newer_epel_nvr", side_effect=lambda nvr: nvr)
@patch("koji_sbom.generate.generate_sbom")
def test_main_verbose_prints_hub_url_to_stderr(
    mock_generate: MagicMock,
    _mock_bodhi: MagicMock,
    capsys: pytest.CaptureFixture[str],
) -> None:
    mock_generate.return_value = {"spdxVersion": "SPDX-2.3", "name": "openssl-3.2.2-1.el10"}

    rc = main(
        [
            "--koji-url",
            "https://kojihub.example/kojihub",
            "--verbose",
            "openssl-3.2.2-1.el10",
        ]
    )

    assert rc == 0
    captured = capsys.readouterr()
    assert captured.err == (
        "koji hub: https://kojihub.example/kojihub\nfetching: openssl-3.2.2-1.el10\n"
    )
    assert json.loads(captured.out)["name"] == "openssl-3.2.2-1.el10"


@patch("koji_sbom.generate.resolve_newer_epel_nvr", side_effect=lambda nvr: nvr)
@patch("koji_sbom.generate.generate_sbom")
@patch("koji_sbom.generate.KojiClient")
def test_main_uses_koji_url_from_env(
    mock_client_cls: MagicMock,
    mock_generate: MagicMock,
    _mock_bodhi: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("KOJI_HUB", "https://kojihub.example/kojihub")
    out = tmp_path / "openssl" / "openssl-rpm-sbom.json"
    mock_generate.return_value = {"spdxVersion": "SPDX-2.3", "name": "openssl-3.2.2-1.el10"}

    rc = main(
        [
            "--nvr",
            "openssl-3.2.2-1.el10",
            "--output",
            str(out),
        ]
    )

    assert rc == 0
    mock_generate.assert_called_once_with(
        "https://kojihub.example/kojihub",
        nvr="openssl-3.2.2-1.el10",
        build_id=None,
        namespace=FEDORA,
    )


@patch("koji_sbom.generate.generate_sbom")
@patch(
    "koji_sbom.generate.resolve_newer_epel_nvr",
    return_value="libheif-1.23.5-4.el10_4",
)
def test_main_warns_when_bodhi_has_newer_but_keeps_requested_nvr(
    mock_bodhi: MagicMock,
    mock_generate: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("KOJI_HUB", "https://kojihub.example/kojihub")
    mock_generate.return_value = {
        "spdxVersion": "SPDX-2.3",
        "name": "libheif-1.20.2-6.el10_4",
    }

    rc = main(["libheif-1.20.2-6.el10_4"])

    assert rc == 0
    mock_bodhi.assert_called_once_with("libheif-1.20.2-6.el10_4")
    mock_generate.assert_called_once_with(
        "https://kojihub.example/kojihub",
        nvr="libheif-1.20.2-6.el10_4",
        build_id=None,
        namespace=FEDORA,
    )
    err = capsys.readouterr().err
    assert "warning: a newer build exists in Bodhi" in err
    assert "libheif-1.20.2-6.el10_4 → libheif-1.23.5-4.el10_4" in err


@patch("koji_sbom.generate.resolve_newer_epel_nvr")
@patch("koji_sbom.generate.generate_sbom")
def test_main_no_bodhi_skips_lookup(
    mock_generate: MagicMock,
    mock_bodhi: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("KOJI_HUB", "https://kojihub.example/kojihub")
    mock_generate.return_value = {
        "spdxVersion": "SPDX-2.3",
        "name": "libheif-1.20.2-6.el10_4",
    }

    rc = main(["--no-bodhi", "libheif-1.20.2-6.el10_4"])

    assert rc == 0
    mock_bodhi.assert_not_called()
    mock_generate.assert_called_once_with(
        "https://kojihub.example/kojihub",
        nvr="libheif-1.20.2-6.el10_4",
        build_id=None,
        namespace=FEDORA,
    )
    assert capsys.readouterr().err == ""


@patch("koji_sbom.generate.generate_sbom")
@patch(
    "koji_sbom.generate.lookup_package_stream_nvrs",
    return_value={
        "fedora-all": "libheif-1.23.5-4.fc46",
        "epel-8": "libheif-1.15.1-1.el8",
        "epel-9": "libheif-1.16.1-2.el9",
        "epel-10": "libheif-1.23.5-4.el10_4",
    },
)
def test_main_package_flag_prints_stream_nvrs(
    mock_lookup: MagicMock,
    mock_generate: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("KOJI_HUB", "https://kojihub.example/kojihub")

    rc = main(["--package", "libheif"])

    assert rc == 0
    mock_lookup.assert_called_once_with(
        "libheif",
        "https://kojihub.example/kojihub",
        use_bodhi=True,
    )
    mock_generate.assert_not_called()
    assert capsys.readouterr().out == (
        "fedora-all: libheif-1.23.5-4.fc46\n"
        "epel-8: libheif-1.15.1-1.el8\n"
        "epel-9: libheif-1.16.1-2.el9\n"
        "epel-10: libheif-1.23.5-4.el10_4\n"
    )


@patch("koji_sbom.generate.generate_sbom")
@patch(
    "koji_sbom.generate.lookup_package_stream_nvrs",
    return_value={
        "fedora-all": "libheif-1.23.5-4.fc46",
        "epel-8": "libheif-1.15.1-1.el8",
        "epel-9": "libheif-1.16.1-2.el9",
        "epel-10": "libheif-1.20.2-6.el10_4",
    },
)
def test_main_package_flag_no_bodhi(
    mock_lookup: MagicMock,
    mock_generate: MagicMock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("KOJI_HUB", "https://kojihub.example/kojihub")

    rc = main(["--no-bodhi", "--package", "libheif"])

    assert rc == 0
    mock_lookup.assert_called_once_with(
        "libheif",
        "https://kojihub.example/kojihub",
        use_bodhi=False,
    )
    mock_generate.assert_not_called()


@pytest.mark.parametrize(
    "argv",
    [
        ["--nvr", "libheif"],
        ["libheif"],
        ["--package", "libheif-1.20.2-6.el10_4"],
    ],
)
def test_main_rejects_package_and_nvr_on_the_wrong_flag(argv: list[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(argv)
    assert exc.value.code == 2
