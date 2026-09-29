"""Tests for koji_sbom.bodhi EPEL yum vs Bodhi NVR resolution."""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest
from koji_sbom.bodhi import (
    EpelBodhiIndex,
    EpelRelease,
    clear_epel_bodhi_index_cache,
    epel_major_from_nvr,
    epel_major_from_release,
    fetch_current_epel_releases,
    fetch_epel_bodhi_index,
    get_current_epel_releases,
    get_latest_epel_koji_tag,
    looks_like_rpm_nvr,
    lookup_package_stream_nvrs,
    package_name_from_nvr,
    resolve_newer_epel_nvr,
    resolve_newer_epel_nvrs,
)


@pytest.fixture(autouse=True)
def _clear_bodhi_cache() -> None:
    clear_epel_bodhi_index_cache()
    yield
    clear_epel_bodhi_index_cache()


@patch("koji_sbom.bodhi._http_get_json", side_effect=RuntimeError("bodhi down"))
def test_get_current_epel_releases_fails_without_fallback(_mock_get: Any) -> None:
    with pytest.raises(RuntimeError, match="bodhi down"):
        get_current_epel_releases()


@patch("koji_sbom.bodhi._http_get_json")
def test_fetch_current_epel_releases(mock_get: Any) -> None:
    mock_get.return_value = {
        "pages": 1,
        "releases": [
            {"name": "EPEL-8", "state": "current", "dist_tag": "epel8"},
            {"name": "EPEL-9", "state": "current", "dist_tag": "epel9"},
            {"name": "EPEL-9N", "state": "current", "dist_tag": "epel9-next"},
            {"name": "EPEL-10.2", "state": "current", "dist_tag": "epel10.2"},
            {"name": "EPEL-10.4", "state": "current", "dist_tag": "epel10.4"},
            {"name": "EPEL-8M", "state": "current", "dist_tag": "epel8-modular"},
            {"name": "F42", "state": "current", "dist_tag": "f42"},
        ],
    }
    releases = fetch_current_epel_releases()
    names = [r.name for r in releases]
    assert names == ["EPEL-8", "EPEL-9", "EPEL-9N", "EPEL-10.2", "EPEL-10.4"]
    assert "EPEL-8M" not in names


def test_get_latest_epel_koji_tag_picks_newest_minor(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "koji_sbom.bodhi.get_current_epel_releases",
        lambda refresh=False: (
            EpelRelease("EPEL-10.2", "epel10.2", 10, 2),
            EpelRelease("EPEL-10.4", "epel10.4", 10, 4),
            EpelRelease("EPEL-9", "epel9", 9, None),
            EpelRelease("EPEL-9N", "epel9-next", 9, None),
        ),
    )
    assert get_latest_epel_koji_tag(10) == "epel10.4"
    assert get_latest_epel_koji_tag(9) == "epel9"


def test_get_latest_epel_koji_tag_missing_major(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "koji_sbom.bodhi.get_current_epel_releases",
        lambda refresh=False: (EpelRelease("EPEL-9", "epel9", 9, None),),
    )
    with pytest.raises(LookupError, match="no current Bodhi EPEL release for major 10"):
        get_latest_epel_koji_tag(10)


def test_package_name_from_nvr() -> None:
    assert package_name_from_nvr("libheif-1.20.2-6.el10_4") == "libheif"
    assert package_name_from_nvr("python-django3-3.2.25-1.el8") == "python-django3"


def test_epel_major_from_nvr() -> None:
    assert epel_major_from_nvr("libheif-1.20.2-6.el10_4") == 10
    assert epel_major_from_nvr("bash-5.2.15-3.el9") == 9
    assert epel_major_from_nvr("bash-5.3.15-2.fc45") is None
    assert epel_major_from_nvr("openssl-3.2.2-1.el10") == 10


def test_epel_major_from_release() -> None:
    assert epel_major_from_release("EPEL-8") == 8
    assert epel_major_from_release("EPEL-9") == 9
    assert epel_major_from_release("EPEL-9N") == 9
    assert epel_major_from_release("EPEL-10.4") == 10
    assert epel_major_from_release("EPEL-10.3") == 10
    assert epel_major_from_release("F42") is None


def test_resolve_newer_bodhi_nvr_wins() -> None:
    index = EpelBodhiIndex(
        newest={("libheif", 10): ("libheif-1.23.5-4.el10_4", 0)},
    )
    assert (
        resolve_newer_epel_nvr("libheif-1.20.2-6.el10_4", index=index) == "libheif-1.23.5-4.el10_4"
    )


def test_resolve_older_bodhi_nvr_loses() -> None:
    index = EpelBodhiIndex(
        newest={("libheif", 10): ("libheif-1.19.0-1.el10_4", 0)},
    )
    assert (
        resolve_newer_epel_nvr("libheif-1.20.2-6.el10_4", index=index) == "libheif-1.20.2-6.el10_4"
    )


def test_epel_10_4_maps_only_to_el10_nvr() -> None:
    """EPEL-10.4 builds index under major 10; they must not replace an el9 NVR."""
    updates = [
        {
            "release": {"name": "EPEL-10.4"},
            "builds": [
                {"nvr": "libheif-1.23.5-4.el10_4", "type": "rpm", "epoch": 0},
            ],
        },
        {
            "release": {"name": "EPEL-9"},
            "builds": [
                {"nvr": "libheif-1.16.1-2.el9", "type": "rpm", "epoch": 0},
            ],
        },
    ]
    with patch("koji_sbom.bodhi._iter_bodhi_updates", side_effect=[updates, []]):
        index = fetch_epel_bodhi_index(releases=("EPEL-10.4", "EPEL-9"))
    assert index.lookup("libheif", 10) == ("libheif-1.23.5-4.el10_4", 0)
    assert index.lookup("libheif", 9) == ("libheif-1.16.1-2.el9", 0)
    assert resolve_newer_epel_nvr("libheif-1.15.0-1.el9", index=index) == "libheif-1.16.1-2.el9"
    # el9 yum NVR must not pick up the EPEL-10.4 Bodhi build
    assert resolve_newer_epel_nvr("libheif-1.16.1-2.el9", index=index) == "libheif-1.16.1-2.el9"


def test_fc_nvr_unchanged() -> None:
    index = EpelBodhiIndex(
        newest={("bash", 10): ("bash-5.2.15-3.el10", 0)},
    )
    assert resolve_newer_epel_nvr("bash-5.3.15-2.fc45", index=index) == "bash-5.3.15-2.fc45"


def test_resolve_newer_epel_nvrs_batch() -> None:
    index = EpelBodhiIndex(
        newest={
            ("libheif", 10): ("libheif-1.23.5-4.el10_4", 0),
            ("curl", 9): ("curl-8.11.0-1.el9", 0),
        },
    )
    assert resolve_newer_epel_nvrs(
        [
            "libheif-1.20.2-6.el10_4",
            "curl-8.10.0-1.el9",
            "bash-5.3.15-2.fc45",
        ],
        index=index,
    ) == [
        "libheif-1.23.5-4.el10_4",
        "curl-8.11.0-1.el9",
        "bash-5.3.15-2.fc45",
    ]


def test_index_skips_non_rpm_builds() -> None:
    updates = [
        {
            "release": {"name": "EPEL-10.4"},
            "builds": [
                {"nvr": "flatpak-app-1-1.el10_4", "type": "flatpak", "epoch": 0},
                {"nvr": "libheif-1.23.5-4.el10_4", "type": "rpm", "epoch": 0},
            ],
        },
    ]
    with patch("koji_sbom.bodhi._iter_bodhi_updates", side_effect=[updates, []]):
        index = fetch_epel_bodhi_index(releases=("EPEL-10.4",))
    assert list(index.newest) == [("libheif", 10)]


def test_mismatched_release_and_nvr_major_skipped() -> None:
    """A build whose NVR major disagrees with the Bodhi release is not indexed."""
    updates = [
        {
            "release": {"name": "EPEL-9"},
            "builds": [
                {"nvr": "libheif-1.23.5-4.el10_4", "type": "rpm", "epoch": 0},
            ],
        },
    ]
    with patch("koji_sbom.bodhi._iter_bodhi_updates", side_effect=[updates, []]):
        index = fetch_epel_bodhi_index(releases=("EPEL-9",))
    assert index.newest == {}


def test_looks_like_rpm_nvr() -> None:
    assert looks_like_rpm_nvr("libheif-1.20.2-6.el10_4")
    assert looks_like_rpm_nvr("bash-5.3.15-2.fc45")
    assert not looks_like_rpm_nvr("libheif")
    assert not looks_like_rpm_nvr("python-django3")


@patch("koji_sbom.bodhi.get_latest_epel_koji_tag")
@patch("koji_sbom.bodhi.get_current_epel_releases")
@patch("koji_sbom.bodhi.latest_tagged_nvr")
def test_lookup_package_stream_nvrs(
    mock_latest: Any,
    mock_releases: Any,
    mock_tag: Any,
) -> None:
    mock_releases.return_value = (
        EpelRelease("EPEL-8", "epel8", 8, None),
        EpelRelease("EPEL-9", "epel9", 9, None),
        EpelRelease("EPEL-9N", "epel9-next", 9, None),
        EpelRelease("EPEL-10.4", "epel10.4", 10, 4),
    )
    mock_tag.side_effect = lambda major, refresh=False: {
        8: "epel8",
        9: "epel9",
        10: "epel10.4",
    }[major]

    def _latest(koji_url: str, package: str, *, tag: str) -> str:
        assert package == "libheif"
        return {
            "rawhide": "libheif-1.23.5-4.fc46",
            "epel8": "libheif-1.15.1-1.el8",
            "epel9": "libheif-1.16.1-2.el9",
            "epel10.4": "libheif-1.20.2-6.el10_4",
        }[tag]

    mock_latest.side_effect = _latest
    index = EpelBodhiIndex(
        newest={
            ("libheif", 8): ("libheif-1.15.2-1.el8", 0),
            ("libheif", 10): ("libheif-1.23.5-4.el10_4", 0),
        },
    )
    assert lookup_package_stream_nvrs(
        "libheif",
        "https://koji.example/kojihub",
        index=index,
    ) == {
        "fedora-all": "libheif-1.23.5-4.fc46",
        "epel-8": "libheif-1.15.2-1.el8",
        "epel-9": "libheif-1.16.1-2.el9",
        "epel-10": "libheif-1.23.5-4.el10_4",
    }


@patch("koji_sbom.bodhi.get_latest_epel_koji_tag", return_value="epel10.4")
@patch(
    "koji_sbom.bodhi.get_current_epel_releases",
    return_value=(EpelRelease("EPEL-10.4", "epel10.4", 10, 4),),
)
@patch("koji_sbom.bodhi.latest_tagged_nvr")
def test_lookup_package_stream_nvrs_missing_stream(
    mock_latest: Any,
    _mock_releases: Any,
    _mock_tag: Any,
) -> None:
    def _latest(koji_url: str, package: str, *, tag: str) -> str:
        if tag == "rawhide":
            return "pkg-1-1.fc46"
        raise LookupError(tag)

    mock_latest.side_effect = _latest
    assert lookup_package_stream_nvrs(
        "pkg",
        "https://koji.example/kojihub",
        use_bodhi=False,
    ) == {
        "fedora-all": "pkg-1-1.fc46",
        "epel-10": None,
    }


@patch("koji_sbom.bodhi._http_get_json")
def test_fetch_paginates(mock_get: Any) -> None:
    mock_get.side_effect = [
        {
            "pages": 2,
            "updates": [
                {
                    "release": {"name": "EPEL-8"},
                    "builds": [{"nvr": "pkg-1-1.el8", "type": "rpm", "epoch": 0}],
                }
            ],
        },
        {
            "pages": 2,
            "updates": [
                {
                    "release": {"name": "EPEL-8"},
                    "builds": [{"nvr": "pkg-2-1.el8", "type": "rpm", "epoch": 0}],
                }
            ],
        },
        {"pages": 1, "updates": []},  # testing status
    ]
    index = fetch_epel_bodhi_index(releases=("EPEL-8",))
    assert index.lookup("pkg", 8) == ("pkg-2-1.el8", 0)
    assert mock_get.call_count == 3
