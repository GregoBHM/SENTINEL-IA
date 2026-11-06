"""Guard the versioned prerelease workflow against accidental YAML duplication.

This is a structural smoke test, not a substitute for GitHub's own workflow
parser or a Windows Actions execution.
"""
from pathlib import Path


def test_release_workflow_has_one_publish_pipeline():
    text = (Path(__file__).parents[1] / ".github" / "workflows"
            / "release-windows.yml").read_text(encoding="utf-8")
    assert text.count("name: Publish versioned Windows prerelease") == 1
    assert text.count("      - name: Validate version and release source") == 1
    assert text.count("      - name: Install Python 3.11 x64") == 1
    assert text.count("      - name: Publish GitHub Release with EXE and SHA-256") == 1
    assert text.count("gh release create ") == 1
    assert "    branches: [main]" in text
    assert "    tags:" in text
    assert "permissions:\n  contents: write" in text
    assert "    runs-on: windows-latest" in text


def test_release_version_code_is_complete_and_never_reuses_tag():
    text = (Path(__file__).parents[1] / ".github" / "workflows"
            / "release-windows.yml").read_text(encoding="utf-8")
    assert "if (-not ($baseVersion -cmatch " in text
    assert "vX.Y.Z-beta.N base version" in text
    assert "$prefix = $Matches[1]" in text
    assert "$sequence = 1000 + [int]$env:GITHUB_RUN_NUMBER" in text
    assert "Release $env:RELEASE_TAG already exists" in text
    assert "--prerelease --latest=false" in text
    assert "dist/SentinelOneGuard.sha256.txt" in text
    assert "Test, compile and verify Windows executable" in text
