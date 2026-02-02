#!/usr/bin/env python3
"""
Dataset Download Script - Phase 3.2

Downloads and prepares vulnerability datasets for testing multi-CWE support.
Supports: SARD (Software Assurance Reference Dataset), NVD (CVE samples)

Usage:
    python download_datasets.py --dataset sard --cwe 89,78,79
    python download_datasets.py --dataset nvd --year 2023 --limit 100
"""

import os
import sys
import json
import argparse
import hashlib
import zipfile
import tarfile
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional
from urllib.request import urlopen, Request
from urllib.error import HTTPError, URLError


# Dataset configurations
SARD_BASE_URL = "https://samate.nist.gov/SARD"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Default output directory
DEFAULT_OUTPUT_DIR = Path(__file__).parent / "datasets"

# CWE configurations for download
CWE_CONFIGS = {
    # Memory safety
    120: {"name": "Buffer Copy", "sard_prefix": "CWE120", "juliet_patterns": ["CWE121_*", "CWE122_*"]},
    121: {"name": "Stack Buffer Overflow", "sard_prefix": "CWE121", "juliet_patterns": ["CWE121_*"]},
    122: {"name": "Heap Buffer Overflow", "sard_prefix": "CWE122", "juliet_patterns": ["CWE122_*"]},
    787: {"name": "Out-of-bounds Write", "sard_prefix": "CWE787", "juliet_patterns": ["CWE121_*", "CWE122_*", "CWE124_*"]},
    125: {"name": "Out-of-bounds Read", "sard_prefix": "CWE125", "juliet_patterns": ["CWE126_*", "CWE127_*"]},
    126: {"name": "Buffer Over-read", "sard_prefix": "CWE126", "juliet_patterns": ["CWE126_*"]},
    127: {"name": "Buffer Under-read", "sard_prefix": "CWE127", "juliet_patterns": ["CWE127_*"]},
    # Injection
    89: {"name": "SQL Injection", "sard_prefix": "CWE89", "juliet_patterns": ["CWE89_*"]},
    78: {"name": "Command Injection", "sard_prefix": "CWE78", "juliet_patterns": ["CWE78_*"]},
    79: {"name": "XSS", "sard_prefix": "CWE79", "juliet_patterns": ["CWE79_*"]},
    # Path traversal
    22: {"name": "Path Traversal", "sard_prefix": "CWE22", "juliet_patterns": ["CWE22_*", "CWE23_*"]},
    23: {"name": "Relative Path Traversal", "sard_prefix": "CWE23", "juliet_patterns": ["CWE23_*"]},
}


@dataclass
class DownloadResult:
    """Result of a download operation."""
    success: bool
    file_path: Optional[Path] = None
    error: Optional[str] = None
    samples_count: int = 0
    cwe_id: int = 0


@dataclass
class DatasetSample:
    """A vulnerability sample from a dataset."""
    id: str
    cwe_id: int
    source_file: str
    source_code: str
    is_vulnerable: bool
    description: str = ""
    metadata: dict = field(default_factory=dict)


def download_file(url: str, output_path: Path, timeout: int = 30) -> bool:
    """Download a file from URL."""
    try:
        req = Request(url, headers={"User-Agent": "MCP-Vul Dataset Downloader"})
        with urlopen(req, timeout=timeout) as response:
            with open(output_path, 'wb') as f:
                f.write(response.read())
        return True
    except (HTTPError, URLError, TimeoutError) as e:
        print(f"Download error: {e}")
        return False


def extract_archive(archive_path: Path, output_dir: Path) -> bool:
    """Extract zip or tar archive."""
    try:
        if archive_path.suffix == '.zip':
            with zipfile.ZipFile(archive_path, 'r') as zf:
                zf.extractall(output_dir)
        elif archive_path.suffix in ('.tar', '.gz', '.tgz'):
            with tarfile.open(archive_path, 'r:*') as tf:
                tf.extractall(output_dir)
        return True
    except Exception as e:
        print(f"Extraction error: {e}")
        return False


class SARDDownloader:
    """
    Downloads samples from SARD (Software Assurance Reference Dataset).
    
    SARD provides categorized test cases for various CWE types.
    https://samate.nist.gov/SARD/
    """
    
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir / "sard"
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def download_cwe(self, cwe_id: int, limit: int = 50) -> DownloadResult:
        """
        Download samples for a specific CWE from SARD.
        
        Note: SARD requires manual download. This generates a download guide.
        """
        config = CWE_CONFIGS.get(cwe_id)
        if not config:
            return DownloadResult(
                success=False,
                error=f"CWE-{cwe_id} not configured",
                cwe_id=cwe_id,
            )
        
        cwe_dir = self.output_dir / f"CWE{cwe_id}"
        cwe_dir.mkdir(exist_ok=True)
        
        # Generate download instructions
        instructions_file = cwe_dir / "DOWNLOAD_INSTRUCTIONS.md"
        instructions = f"""# SARD Download Instructions for CWE-{cwe_id}

## {config['name']}

### Manual Download Steps:

1. Visit: https://samate.nist.gov/SARD/test-suites
2. Search for: CWE-{cwe_id}
3. Download the test suite archive
4. Extract to this directory: `{cwe_dir}`

### Expected Structure:

```
{cwe_dir}/
├── vulnerable/
│   ├── sample1.c
│   └── sample2.c
└── safe/
    ├── sample1_fixed.c
    └── sample2_fixed.c
```

### Juliet Test Suite

For comprehensive C/C++ samples, use Juliet:
- URL: https://samate.nist.gov/SARD/test-suites/juliet
- Extract CWE-{cwe_id} cases from Juliet

### Processing

After download, run:
```bash
python experiments/extract_juliet.py --cwe {cwe_id} --output {cwe_dir}
```
"""
        
        with open(instructions_file, 'w') as f:
            f.write(instructions)
        
        # Check if samples already exist
        existing_samples = list(cwe_dir.glob("**/*.c"))
        
        return DownloadResult(
            success=True,
            file_path=instructions_file,
            samples_count=len(existing_samples),
            cwe_id=cwe_id,
        )
    
    def download_all(self, cwe_ids: list[int]) -> list[DownloadResult]:
        """Download samples for multiple CWEs."""
        results = []
        for cwe_id in cwe_ids:
            result = self.download_cwe(cwe_id)
            results.append(result)
            print(f"CWE-{cwe_id}: {result.samples_count} existing samples")
        return results


class NVDDownloader:
    """
    Downloads CVE information from NVD (National Vulnerability Database).
    
    Uses NVD 2.0 API to fetch CVE details for analysis.
    https://nvd.nist.gov/developers/vulnerabilities
    """
    
    def __init__(self, output_dir: Path, api_key: str = None):
        self.output_dir = output_dir / "nvd"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.api_key = api_key
    
    def fetch_cves(
        self, 
        cwe_id: int = None, 
        year: int = None,
        limit: int = 100,
    ) -> list[dict]:
        """
        Fetch CVE entries from NVD API.
        
        Args:
            cwe_id: Filter by CWE ID
            year: Filter by publication year
            limit: Maximum entries to fetch
        
        Returns:
            List of CVE entries
        """
        params = [f"resultsPerPage={min(limit, 2000)}"]
        
        if cwe_id:
            params.append(f"cweId=CWE-{cwe_id}")
        
        if year:
            params.append(f"pubStartDate={year}-01-01T00:00:00.000")
            params.append(f"pubEndDate={year}-12-31T23:59:59.999")
        
        url = f"{NVD_API_URL}?{'&'.join(params)}"
        
        headers = {"User-Agent": "MCP-Vul Dataset Downloader"}
        if self.api_key:
            headers["apiKey"] = self.api_key
        
        try:
            req = Request(url, headers=headers)
            with urlopen(req, timeout=60) as response:
                data = json.loads(response.read().decode())
                return data.get("vulnerabilities", [])
        except Exception as e:
            print(f"NVD API error: {e}")
            return []
    
    def download_cwe(self, cwe_id: int, limit: int = 50) -> DownloadResult:
        """Download CVE entries for a specific CWE."""
        config = CWE_CONFIGS.get(cwe_id)
        if not config:
            return DownloadResult(
                success=False,
                error=f"CWE-{cwe_id} not configured",
                cwe_id=cwe_id,
            )
        
        cwe_dir = self.output_dir / f"CWE{cwe_id}"
        cwe_dir.mkdir(exist_ok=True)
        
        cves = self.fetch_cves(cwe_id=cwe_id, limit=limit)
        
        # Save CVE entries
        output_file = cwe_dir / "cves.json"
        with open(output_file, 'w') as f:
            json.dump(cves, f, indent=2)
        
        # Generate summary
        summary_file = cwe_dir / "summary.md"
        summary = f"""# NVD CVEs for CWE-{cwe_id}

## {config['name']}

**Total CVEs fetched:** {len(cves)}

## CVE List
"""
        for cve in cves[:20]:  # Show first 20
            cve_data = cve.get("cve", {})
            cve_id = cve_data.get("id", "Unknown")
            desc = cve_data.get("descriptions", [{}])[0].get("value", "")[:100]
            summary += f"\n- **{cve_id}**: {desc}..."
        
        with open(summary_file, 'w') as f:
            f.write(summary)
        
        return DownloadResult(
            success=True,
            file_path=output_file,
            samples_count=len(cves),
            cwe_id=cwe_id,
        )


class JulietExtractor:
    """
    Extends Juliet extraction to support multiple CWE types.
    
    Works with existing extract_juliet.py infrastructure.
    """
    
    def __init__(self, juliet_dir: Path, output_dir: Path):
        self.juliet_dir = juliet_dir
        self.output_dir = output_dir / "juliet"
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def find_cwe_samples(self, cwe_id: int) -> list[Path]:
        """Find samples for a CWE in Juliet directory."""
        config = CWE_CONFIGS.get(cwe_id)
        if not config:
            return []

        # Use juliet_patterns if available, otherwise fall back to default pattern
        patterns = config.get("juliet_patterns", [f"CWE{cwe_id}_*"])

        samples = []
        for pattern in patterns:
            samples.extend(self.juliet_dir.glob(f"**/{pattern}/**/*.c"))

        return samples
    
    def extract_cwe(self, cwe_id: int, limit: int = 100) -> DownloadResult:
        """Extract samples for a specific CWE."""
        config = CWE_CONFIGS.get(cwe_id)
        if not config:
            return DownloadResult(
                success=False,
                error=f"CWE-{cwe_id} not configured",
                cwe_id=cwe_id,
            )
        
        cwe_dir = self.output_dir / f"CWE{cwe_id}"
        cwe_dir.mkdir(exist_ok=True)
        
        samples = self.find_cwe_samples(cwe_id)[:limit]
        
        # Categorize samples
        vulnerable = []
        safe = []
        
        for sample in samples:
            is_vuln = "_bad" in sample.name or "__bad" in str(sample)
            if is_vuln:
                vulnerable.append(sample)
            else:
                safe.append(sample)
        
        # Save manifest
        manifest = {
            "cwe_id": cwe_id,
            "name": config["name"],
            "vulnerable_samples": [str(p) for p in vulnerable],
            "safe_samples": [str(p) for p in safe],
        }
        
        manifest_file = cwe_dir / "manifest.json"
        with open(manifest_file, 'w') as f:
            json.dump(manifest, f, indent=2)
        
        return DownloadResult(
            success=True,
            file_path=manifest_file,
            samples_count=len(samples),
            cwe_id=cwe_id,
        )


def main():
    parser = argparse.ArgumentParser(
        description="Download vulnerability datasets for MCP-Vul"
    )
    parser.add_argument(
        "--dataset",
        choices=["sard", "nvd", "juliet", "all"],
        default="all",
        help="Dataset to download",
    )
    parser.add_argument(
        "--cwe",
        type=str,
        default="120,89,78,79,22",
        help="Comma-separated CWE IDs",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help="Output directory",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=50,
        help="Max samples per CWE",
    )
    parser.add_argument(
        "--nvd-api-key",
        type=str,
        default=os.environ.get("NVD_API_KEY"),
        help="NVD API key (optional, increases rate limit)",
    )
    parser.add_argument(
        "--juliet-dir",
        type=Path,
        default=Path(__file__).parent.parent / "data" / "juliet_raw" / "C" / "testcases",
        help="Path to Juliet test suite (default: data/juliet_raw/C/testcases)",
    )
    
    args = parser.parse_args()
    
    cwe_ids = [int(c.strip()) for c in args.cwe.split(",")]
    args.output.mkdir(parents=True, exist_ok=True)
    
    print(f"Output directory: {args.output}")
    print(f"CWEs to download: {cwe_ids}")
    print()
    
    results = []
    
    if args.dataset in ("sard", "all"):
        print("=== SARD Dataset ===")
        sard = SARDDownloader(args.output)
        results.extend(sard.download_all(cwe_ids))
        print()
    
    if args.dataset in ("nvd", "all"):
        print("=== NVD Dataset ===")
        nvd = NVDDownloader(args.output, api_key=args.nvd_api_key)
        for cwe_id in cwe_ids:
            result = nvd.download_cwe(cwe_id, limit=args.limit)
            results.append(result)
            print(f"CWE-{cwe_id}: {result.samples_count} CVEs")
        print()
    
    if args.dataset in ("juliet", "all"):
        print("=== Juliet Extraction ===")
        if args.juliet_dir.exists():
            juliet = JulietExtractor(args.juliet_dir, args.output)
            for cwe_id in cwe_ids:
                result = juliet.extract_cwe(cwe_id, limit=args.limit)
                results.append(result)
                print(f"CWE-{cwe_id}: {result.samples_count} samples")
        else:
            print(f"Juliet directory not found: {args.juliet_dir}")
        print()
    
    # Summary
    print("=== Summary ===")
    total_samples = sum(r.samples_count for r in results)
    print(f"Total samples/entries: {total_samples}")
    print(f"Output directory: {args.output}")


if __name__ == "__main__":
    main()
