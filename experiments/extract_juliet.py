"""Extract CWE-121/122 test cases from Juliet Test Suite.

This script extracts individual bad/good functions from the Juliet Test Suite
for use in vulnerability detection experiments.
"""

import os
import re
import json
import random
from pathlib import Path
from typing import Generator


def find_juliet_files(juliet_path: Path, cwe: str = "CWE121") -> Generator[Path, None, None]:
    """Find all C files for the specified CWE."""
    cwe_dirs = [d for d in juliet_path.iterdir() if d.is_dir() and cwe in d.name]
    
    for cwe_dir in cwe_dirs:
        for subdir in cwe_dir.iterdir():
            if subdir.is_dir():
                for file in subdir.glob("*.c"):
                    # Skip main files and helper files
                    if "main" not in file.name.lower():
                        yield file


def extract_functions(file_path: Path) -> list[dict]:
    """Extract bad and good functions from a Juliet test case file."""
    try:
        content = file_path.read_text(encoding='utf-8', errors='ignore')
    except Exception:
        return []
    
    functions = []
    
    # Pattern to match function definitions
    # Matches: void FunctionName(...) { ... }
    func_pattern = re.compile(
        r'(void\s+(\w+)\s*\([^)]*\)\s*\{)',
        re.MULTILINE
    )
    
    for match in func_pattern.finditer(content):
        func_name = match.group(2)
        start_pos = match.start()
        
        # Determine if this is a bad or good function
        is_bad = '_bad' in func_name.lower() or func_name.lower().startswith('bad')
        is_good = 'good' in func_name.lower()
        
        if not (is_bad or is_good):
            continue
        
        # Find the matching closing brace
        brace_count = 0
        end_pos = match.end() - 1  # Start from the opening brace
        
        for i, char in enumerate(content[match.end()-1:], start=match.end()-1):
            if char == '{':
                brace_count += 1
            elif char == '}':
                brace_count -= 1
                if brace_count == 0:
                    end_pos = i + 1
                    break
        
        func_body = content[start_pos:end_pos]
        
        # Skip very long or very short functions
        if len(func_body) < 50 or len(func_body) > 3000:
            continue
        
        functions.append({
            'name': func_name,
            'source': func_body,
            'is_vulnerable': is_bad,
            'file': str(file_path.name),
        })
    
    return functions


def create_dataset(
    juliet_path: Path,
    output_path: Path,
    count: int = 100,
    cwe: str = "CWE121",
    balanced: bool = True,
) -> dict:
    """
    Create a dataset from Juliet test cases.
    
    Args:
        juliet_path: Path to Juliet testcases directory
        output_path: Path to save the dataset JSON
        count: Number of samples to include
        cwe: CWE to extract (CWE121 or CWE122)
        balanced: If True, include equal numbers of bad and good samples
    """
    all_bad = []
    all_good = []
    
    print(f"Scanning {juliet_path} for {cwe} test cases...")
    
    for file_path in find_juliet_files(juliet_path, cwe):
        functions = extract_functions(file_path)
        for func in functions:
            if func['is_vulnerable']:
                all_bad.append(func)
            else:
                all_good.append(func)
    
    print(f"Found {len(all_bad)} bad functions and {len(all_good)} good functions")
    
    # Sample functions
    if balanced:
        n_each = count // 2
        selected_bad = random.sample(all_bad, min(n_each, len(all_bad)))
        selected_good = random.sample(all_good, min(n_each, len(all_good)))
        selected = selected_bad + selected_good
    else:
        all_funcs = all_bad + all_good
        selected = random.sample(all_funcs, min(count, len(all_funcs)))
    
    random.shuffle(selected)
    
    # Create dataset
    samples = []
    for i, func in enumerate(selected):
        samples.append({
            'id': f"juliet_{cwe}_{i:04d}",
            'function_name': func['name'],
            'source_code': func['source'],
            'is_vulnerable': func['is_vulnerable'],
            'source_file': func['file'],
        })
    
    dataset = {
        'metadata': {
            'source': f'Juliet Test Suite 1.3 - {cwe}',
            'total_samples': len(samples),
            'vulnerable_count': sum(1 for s in samples if s['is_vulnerable']),
            'safe_count': sum(1 for s in samples if not s['is_vulnerable']),
        },
        'samples': samples,
    }
    
    # Save dataset
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(dataset, f, indent=2)
    
    print(f"Dataset saved to {output_path}")
    print(f"  Total: {len(samples)}")
    print(f"  Vulnerable: {dataset['metadata']['vulnerable_count']}")
    print(f"  Safe: {dataset['metadata']['safe_count']}")
    
    return dataset


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Extract Juliet test cases")
    parser.add_argument(
        "--juliet-path",
        type=Path,
        default=Path("data/juliet_raw/C/testcases"),
        help="Path to Juliet testcases directory"
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data/juliet_samples/juliet_cwe121.json"),
        help="Output dataset path"
    )
    parser.add_argument(
        "--count",
        type=int,
        default=100,
        help="Number of samples to extract"
    )
    parser.add_argument(
        "--cwe",
        type=str,
        default="CWE121",
        choices=["CWE121", "CWE122"],
        help="CWE to extract"
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for reproducibility"
    )
    
    args = parser.parse_args()
    random.seed(args.seed)
    
    create_dataset(
        juliet_path=args.juliet_path,
        output_path=args.output,
        count=args.count,
        cwe=args.cwe,
    )
