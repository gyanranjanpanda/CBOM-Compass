"""Code intake: archive safety, repository URL validation, and the HTTP path.

The archive tests are the important ones. Every case here is a real technique
against a naive `extractall`, so they are written as "this must be refused"
rather than "this returns a value".
"""

import io
import zipfile

import pytest
from fastapi.testclient import TestClient

from cbom_compass.api import create_app
from cbom_compass.ingest import (MAX_ENTRIES, IngestError, ingest_upload,
                                 normalise_repo_url, strip_symlinks)


def zip_bytes(entries, compress=zipfile.ZIP_DEFLATED):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compress) as archive:
        for name, content in entries:
            archive.writestr(name, content)
    return buffer.getvalue()


# --------------------------------------------------------------- archives

@pytest.mark.parametrize("name", [
    "../../etc/cron.d/evil",           # classic zip slip
    "/etc/cron.d/evil",                # absolute
    "..\\..\\Windows\\evil.bat",       # backslash separators
    "C:\\Windows\\evil.bat",           # drive letter
    "a/b/../../../../outside.py",      # traversal below a legitimate prefix
])
def test_archive_escaping_the_root_is_refused(tmp_path, name):
    with pytest.raises(IngestError, match="escapes|absolute"):
        ingest_upload(zip_bytes([(name, "x")]), "evil.zip", tmp_path)


def test_nothing_is_written_outside_the_workspace(tmp_path):
    workspace = tmp_path / "ws"
    with pytest.raises(IngestError):
        ingest_upload(zip_bytes([("../escaped.py", "x")]), "evil.zip", workspace)
    assert not (tmp_path / "escaped.py").exists()
    # the half-built tree is cleaned up rather than left behind
    assert list(workspace.iterdir()) == []


def test_decompression_bomb_is_refused(tmp_path):
    """A few MB on the wire that would expand to gigabytes on disk."""
    payload = zip_bytes([(f"bomb{i}.bin", b"\0" * (200 * 1024 * 1024)) for i in range(4)])
    assert len(payload) < 2 * 1024 * 1024        # genuinely small compressed
    with pytest.raises(IngestError, match="limit"):
        ingest_upload(payload, "bomb.zip", tmp_path)


def test_entry_count_is_capped(tmp_path):
    payload = zip_bytes([(f"f{i}.py", "x") for i in range(MAX_ENTRIES + 5)])
    with pytest.raises(IngestError, match="entries"):
        ingest_upload(payload, "many.zip", tmp_path)


def test_symlink_members_are_not_materialised(tmp_path):
    """A symlink to /etc/passwd would otherwise be read and quoted as evidence."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        info = zipfile.ZipInfo("secrets")
        info.external_attr = (0o120777 << 16)    # S_IFLNK
        archive.writestr(info, "/etc/passwd")
        archive.writestr("app.py", "import hashlib\n")
    source = ingest_upload(buffer.getvalue(), "linky.zip", tmp_path)
    assert not (source.root / "secrets").exists()
    assert (source.root / "app.py").exists()


def test_strip_symlinks_removes_links_created_after_extraction(tmp_path):
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "real.py").write_text("import hashlib\n")
    (tree / "link").symlink_to("/etc/passwd")
    assert strip_symlinks(tree) == 1
    assert not (tree / "link").exists()
    assert (tree / "real.py").exists()


def test_empty_and_unreadable_uploads_are_refused(tmp_path):
    with pytest.raises(IngestError, match="empty"):
        ingest_upload(b"", "e.zip", tmp_path)
    with pytest.raises(IngestError, match="not a readable zip"):
        ingest_upload(b"PK\x03\x04not-really-a-zip", "f.zip", tmp_path)


def test_plain_source_file_becomes_a_one_file_tree(tmp_path):
    source = ingest_upload(b"import hashlib\nhashlib.md5(b'x')\n", "lone.py", tmp_path)
    assert source.file_count == 1
    assert (source.root / "lone.py").read_text().startswith("import hashlib")


def test_archive_extracts_and_preserves_layout(tmp_path):
    source = ingest_upload(zip_bytes([("src/pay.py", "import hashlib\n"),
                                      ("requirements.txt", "cryptography==41.0.0\n")]),
                           "app.zip", tmp_path)
    assert source.kind == "upload" and source.file_count == 2
    assert (source.root / "src" / "pay.py").exists()


# ----------------------------------------------------------- repository URLs

@pytest.mark.parametrize("url", [
    "http://169.254.169.254/latest/meta-data",   # cloud metadata SSRF
    "file:///etc/passwd",
    "git://github.com/a/b",
    "ssh://git@github.com/a/b",
    "https://user:token@github.com/a/b",         # credential smuggling
    "https://internal.corp/a/b",
    "https://github.com.evil.example/a/b",       # suffix confusion
    "https://localhost:8000/a/b",
    "https://github.com/../../etc",              # traversal against the host
    "--upload-pack=sh/x",                        # argument-looking segment
    "https://github.com/a/b;rm -rf /",
    "https://github.com/onlyowner",
    "",
])
def test_hostile_repository_urls_are_refused(url):
    with pytest.raises(IngestError):
        normalise_repo_url(url)


@pytest.mark.parametrize("given,expected", [
    ("psf/requests", "github.com/psf/requests"),
    ("github.com/psf/requests", "github.com/psf/requests"),
    ("https://github.com/psf/requests", "github.com/psf/requests"),
    ("https://github.com/psf/requests.git", "github.com/psf/requests"),
    ("https://www.github.com/psf/requests", "github.com/psf/requests"),
    ("https://github.com/psf/requests/tree/main/src", "github.com/psf/requests"),
    ("https://gitlab.com/my-org/my.repo", "gitlab.com/my-org/my.repo"),
])
def test_valid_repository_urls_normalise(given, expected):
    clone_url, label = normalise_repo_url(given)
    assert label == expected
    assert clone_url.startswith("https://") and clone_url.endswith(".git")


# ------------------------------------------------------------------- HTTP

@pytest.fixture
def client(tmp_path):
    return TestClient(create_app(db_path=tmp_path / "t.db",
                                 workspace=tmp_path / "ws"))


def test_upload_endpoint_scans_and_stores(client):
    payload = zip_bytes([
        ("src/auth.py",
         "import hashlib\n"
         "from cryptography.hazmat.primitives.asymmetric import rsa\n"
         "def fp(x): return hashlib.md5(x).hexdigest()\n"
         "def tok(x): return hashlib.sha256(x).hexdigest()\n"
         "k = rsa.generate_private_key(65537, 1024)\n"),
    ])
    body = client.post("/api/scan/upload",
                       files={"file": ("app.zip", payload, "application/zip")}).json()

    assert body["run"]["label"] == "app.zip"
    assert body["run"]["origin"]["kind"] == "upload"
    found = {a["algorithm"]: a for a in body["assets"]}
    assert "MD5" in found and "RSA" in found and "SHA-256" in found
    # The report becomes the current one, so the dashboard picks it up.
    assert client.get("/api/report").json()["run"]["scan_id"] == body["run"]["scan_id"]


def test_uploaded_locations_are_relative_to_the_upload_not_the_workspace(client):
    payload = zip_bytes([("src/auth.py", "import hashlib\nhashlib.md5(b'x')\n")])
    body = client.post("/api/scan/upload",
                       files={"file": ("app.zip", payload, "application/zip")}).json()
    md5 = next(a for a in body["assets"] if a["algorithm"] == "MD5")
    assert md5["evidence"][0]["location"] == "src/auth.py:2"


def test_upload_rejections_reach_the_user_as_400(client):
    body = zip_bytes([("../../evil.py", "x")])
    response = client.post("/api/scan/upload",
                           files={"file": ("evil.zip", body, "application/zip")})
    assert response.status_code == 400
    assert "escapes" in response.json()["detail"]


def test_repo_endpoint_refuses_hostile_urls_without_cloning(client):
    for url in ("file:///etc/passwd", "http://169.254.169.254/a/b", "psf"):
        response = client.post("/api/scan/repo", json={"url": url})
        assert response.status_code == 400, url


def test_scanning_requires_the_scan_permission(client):
    payload = zip_bytes([("a.py", "import hashlib\n")])
    denied = client.post("/api/scan/upload",
                         files={"file": ("a.zip", payload, "application/zip")},
                         headers={"x-role": "auditor"})
    assert denied.status_code == 403
    assert client.post("/api/scan/repo", json={"url": "psf/requests"},
                       headers={"x-role": "auditor"}).status_code == 403


# ------------------------------------------------------- store concurrency

def test_concurrent_scans_do_not_corrupt_the_store(tmp_path):
    """Two scans finishing together must both persist.

    uvicorn runs sync endpoints in a threadpool, so the single shared sqlite3
    connection was used from several threads at once and raised
    "InterfaceError: bad parameter or other API misuse" from inside audit().
    Anyone running this for more than one user would have hit it.
    """
    import concurrent.futures as futures

    client = TestClient(create_app(db_path=tmp_path / "t.db",
                                   workspace=tmp_path / "ws"))
    payload = zip_bytes([("a.py", "import hashlib\nhashlib.md5(b'x')\n")])

    def scan(n):
        return client.post("/api/scan/upload",
                           files={"file": (f"u{n}.zip", payload, "application/zip")})

    with futures.ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(scan, range(8)))

    assert [r.status_code for r in results] == [200] * 8
    assert len(client.get("/api/scans").json()) == 8


def test_health_endpoint_is_cheap_and_honest(client, tmp_path):
    """The dashboard probes this to tell a dead server from a dropped connection."""
    before = client.get("/api/health").json()
    assert before == {"ok": True, "scans": False}

    payload = zip_bytes([("a.py", "import hashlib\nhashlib.md5(b'x')\n")])
    client.post("/api/scan/upload",
                files={"file": ("a.zip", payload, "application/zip")})
    assert client.get("/api/health").json() == {"ok": True, "scans": True}
