"""Tests for Phase 3.2 Dataset Expansion."""

import pytest
import json
from pathlib import Path
from experiments.download_datasets import (
    SARDDownloader,
    NVDDownloader,
    JulietExtractor,
    CWE_CONFIGS,
    DownloadResult,
    DatasetSample,
    download_file,
)


class TestCWEConfigs:
    """Tests for CWE configuration."""
    
    def test_buffer_overflow_cwes(self):
        """Should have buffer overflow CWEs configured."""
        assert 120 in CWE_CONFIGS
        assert 121 in CWE_CONFIGS
        assert 787 in CWE_CONFIGS
    
    def test_injection_cwes(self):
        """Should have injection CWEs configured."""
        assert 89 in CWE_CONFIGS  # SQL Injection
        assert 78 in CWE_CONFIGS  # Command Injection
        assert 79 in CWE_CONFIGS  # XSS
    
    def test_path_traversal_cwe(self):
        """Should have path traversal CWE configured."""
        assert 22 in CWE_CONFIGS
    
    def test_cwe_has_name_and_prefix(self):
        """Each CWE should have name and SARD prefix."""
        for cwe_id, config in CWE_CONFIGS.items():
            assert "name" in config, f"CWE-{cwe_id} missing name"
            assert "sard_prefix" in config, f"CWE-{cwe_id} missing sard_prefix"


class TestDownloadResult:
    """Tests for DownloadResult dataclass."""
    
    def test_success_result(self):
        """Should create success result."""
        result = DownloadResult(
            success=True,
            file_path=Path("/tmp/test.json"),
            samples_count=10,
            cwe_id=89,
        )
        assert result.success
        assert result.samples_count == 10
    
    def test_failure_result(self):
        """Should create failure result."""
        result = DownloadResult(
            success=False,
            error="CWE not configured",
            cwe_id=999,
        )
        assert not result.success
        assert "not configured" in result.error


class TestSARDDownloader:
    """Tests for SARD downloader."""
    
    def test_init_creates_directory(self, tmp_path):
        """Should create output directory."""
        downloader = SARDDownloader(tmp_path)
        assert downloader.output_dir.exists()
    
    def test_download_cwe_creates_instructions(self, tmp_path):
        """Should create download instructions file."""
        downloader = SARDDownloader(tmp_path)
        result = downloader.download_cwe(89)
        
        assert result.success
        assert result.file_path.exists()
        assert "DOWNLOAD_INSTRUCTIONS.md" in result.file_path.name
    
    def test_download_unknown_cwe(self, tmp_path):
        """Should fail for unknown CWE."""
        downloader = SARDDownloader(tmp_path)
        result = downloader.download_cwe(99999)
        
        assert not result.success
        assert "not configured" in result.error
    
    def test_download_all(self, tmp_path):
        """Should download multiple CWEs."""
        downloader = SARDDownloader(tmp_path)
        results = downloader.download_all([89, 78])
        
        assert len(results) == 2
        assert all(r.success for r in results)


class TestNVDDownloader:
    """Tests for NVD downloader."""
    
    def test_init_creates_directory(self, tmp_path):
        """Should create output directory."""
        downloader = NVDDownloader(tmp_path)
        assert downloader.output_dir.exists()
    
    def test_download_cwe_creates_files(self, tmp_path):
        """Should create CVE files (may be empty without network)."""
        downloader = NVDDownloader(tmp_path)
        result = downloader.download_cwe(89, limit=5)
        
        assert result.success
        assert result.file_path.exists()
    
    def test_download_unknown_cwe(self, tmp_path):
        """Should fail for unknown CWE."""
        downloader = NVDDownloader(tmp_path)
        result = downloader.download_cwe(99999)
        
        assert not result.success


class TestJulietExtractor:
    """Tests for Juliet extractor."""
    
    def test_init(self, tmp_path):
        """Should initialize with paths."""
        juliet_dir = tmp_path / "juliet"
        output_dir = tmp_path / "output"
        
        extractor = JulietExtractor(juliet_dir, output_dir)
        assert extractor.juliet_dir == juliet_dir
        assert extractor.output_dir.exists()
    
    def test_extract_cwe_unknown(self, tmp_path):
        """Should fail for unknown CWE."""
        extractor = JulietExtractor(tmp_path, tmp_path)
        result = extractor.extract_cwe(99999)
        
        assert not result.success
    
    def test_extract_cwe_no_samples(self, tmp_path):
        """Should handle missing samples gracefully."""
        extractor = JulietExtractor(tmp_path / "nonexistent", tmp_path)
        result = extractor.extract_cwe(89)
        
        assert result.success
        assert result.samples_count == 0


class TestIntegration:
    """Integration tests for dataset downloading."""
    
    def test_all_cwes_have_handlers_and_configs(self):
        """CWE handlers should match download configs."""
        from src.mcp_servers.cwe_handlers import list_supported_cwes
        
        handler_cwes = set(list_supported_cwes())
        config_cwes = set(CWE_CONFIGS.keys())
        
        # All config CWEs should have handlers
        for cwe in config_cwes:
            assert cwe in handler_cwes, f"CWE-{cwe} in config but no handler"
    
    def test_create_dataset_structure(self, tmp_path):
        """Should create proper dataset structure."""
        # Create mock samples
        samples_dir = tmp_path / "samples"
        samples_dir.mkdir()
        
        # Create a sample manifest
        manifest = {
            "cwe_id": 89,
            "name": "SQL Injection",
            "vulnerable_samples": [],
            "safe_samples": [],
        }
        
        manifest_file = samples_dir / "manifest.json"
        with open(manifest_file, 'w') as f:
            json.dump(manifest, f)
        
        # Verify structure
        assert manifest_file.exists()
        loaded = json.loads(manifest_file.read_text())
        assert loaded["cwe_id"] == 89
