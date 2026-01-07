"""Prepare dataset from Juliet Test Suite for CWE-120.

This script extracts function samples from the Juliet Test Suite
and creates a labeled dataset for experiments.
"""

import json
import re
import argparse
from pathlib import Path
from dataclasses import dataclass, asdict


@dataclass
class FunctionSample:
    """A function sample from the test suite."""
    id: str
    source_code: str
    function_name: str
    is_vulnerable: bool  # True = bad, False = good
    file_origin: str
    cwe_id: str = "CWE-120"


def extract_functions_from_file(file_path: Path) -> list[FunctionSample]:
    """Extract function definitions from a C file."""
    content = file_path.read_text(errors="ignore")
    samples = []
    
    # Pattern to match function definitions
    # This is simplified - real parsing would need tree-sitter
    func_pattern = re.compile(
        r'^((?:static\s+)?(?:void|int|char\s*\*?|size_t|ssize_t)\s+\w+\s*\([^)]*\)\s*\{)',
        re.MULTILINE
    )
    
    # Find all function starts
    matches = list(func_pattern.finditer(content))
    
    for i, match in enumerate(matches):
        start = match.start()
        
        # Find the matching closing brace
        brace_count = 0
        end = start
        in_string = False
        in_char = False
        
        for j, char in enumerate(content[start:], start):
            if char == '"' and not in_char and (j == 0 or content[j-1] != '\\'):
                in_string = not in_string
            elif char == "'" and not in_string and (j == 0 or content[j-1] != '\\'):
                in_char = not in_char
            elif not in_string and not in_char:
                if char == '{':
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        end = j + 1
                        break
        
        if end > start:
            func_code = content[start:end]
            
            # Extract function name
            name_match = re.search(r'(\w+)\s*\(', match.group(1))
            func_name = name_match.group(1) if name_match else "unknown"
            
            # Determine if vulnerable based on naming convention
            is_bad = "_bad" in func_name.lower() or "bad" in func_name.lower()
            is_good = "_good" in func_name.lower() or "good" in func_name.lower()
            
            # Skip helper functions
            if not is_bad and not is_good:
                continue
            
            sample_id = f"{file_path.stem}_{func_name}"
            
            samples.append(FunctionSample(
                id=sample_id,
                source_code=func_code,
                function_name=func_name,
                is_vulnerable=is_bad,
                file_origin=str(file_path),
            ))
    
    return samples


def prepare_dataset(
    juliet_path: Path,
    output_path: Path,
    max_samples: int = 100,
) -> dict:
    """
    Prepare dataset from Juliet Test Suite.
    
    Args:
        juliet_path: Path to Juliet Test Suite directory
        output_path: Where to save the dataset
        max_samples: Maximum number of samples (balanced 50/50)
    """
    # Find CWE-120 test cases
    cwe_dirs = [
        juliet_path / "testcases" / "CWE120_Buffer_Copy_without_Checking_Size_of_Input",
        juliet_path / "testcases" / "CWE121_Stack_Based_Buffer_Overflow",
        juliet_path / "testcases" / "CWE122_Heap_Based_Buffer_Overflow",
    ]
    
    all_samples = []
    
    for cwe_dir in cwe_dirs:
        if not cwe_dir.exists():
            print(f"Warning: Directory not found: {cwe_dir}")
            continue
        
        # Find all C files
        c_files = list(cwe_dir.rglob("*.c"))
        print(f"Found {len(c_files)} C files in {cwe_dir.name}")
        
        for c_file in c_files:
            try:
                samples = extract_functions_from_file(c_file)
                all_samples.extend(samples)
            except Exception as e:
                print(f"Error processing {c_file}: {e}")
    
    print(f"Total samples extracted: {len(all_samples)}")
    
    # Balance the dataset
    bad_samples = [s for s in all_samples if s.is_vulnerable]
    good_samples = [s for s in all_samples if not s.is_vulnerable]
    
    print(f"Vulnerable samples: {len(bad_samples)}")
    print(f"Safe samples: {len(good_samples)}")
    
    # Take equal numbers
    half = max_samples // 2
    selected_bad = bad_samples[:half]
    selected_good = good_samples[:half]
    
    final_samples = selected_bad + selected_good
    
    # Save to JSON
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    dataset = {
        "metadata": {
            "source": "Juliet Test Suite",
            "cwe_id": "CWE-120",
            "total_samples": len(final_samples),
            "vulnerable_count": len(selected_bad),
            "safe_count": len(selected_good),
        },
        "samples": [asdict(s) for s in final_samples],
    }
    
    with open(output_path, "w") as f:
        json.dump(dataset, f, indent=2)
    
    print(f"Dataset saved to {output_path}")
    return dataset


def create_sample_dataset(output_path: Path) -> dict:
    """
    Create a small sample dataset with hand-crafted examples.
    
    Use this if Juliet Test Suite is not available.
    """
    samples = [
        # Vulnerable examples
        FunctionSample(
            id="sample_bad_strcpy_1",
            source_code='''void bad_strcpy(char *user_input) {
    char buffer[32];
    strcpy(buffer, user_input);  // No bounds check
    printf("%s", buffer);
}''',
            function_name="bad_strcpy",
            is_vulnerable=True,
            file_origin="sample",
        ),
        FunctionSample(
            id="sample_bad_memcpy_1",
            source_code='''void bad_memcpy(char *src, size_t len) {
    char dest[64];
    memcpy(dest, src, len);  // len not validated
}''',
            function_name="bad_memcpy",
            is_vulnerable=True,
            file_origin="sample",
        ),
        FunctionSample(
            id="sample_bad_sprintf_1",
            source_code='''void bad_sprintf(char *name) {
    char buffer[100];
    sprintf(buffer, "Hello, %s! Welcome to our system.", name);
}''',
            function_name="bad_sprintf",
            is_vulnerable=True,
            file_origin="sample",
        ),
        FunctionSample(
            id="sample_bad_gets_1",
            source_code='''void bad_gets() {
    char buffer[256];
    gets(buffer);  // Never safe
    process(buffer);
}''',
            function_name="bad_gets",
            is_vulnerable=True,
            file_origin="sample",
        ),
        FunctionSample(
            id="sample_bad_scanf_1",
            source_code='''void bad_scanf() {
    char name[32];
    scanf("%s", name);  // No width limit
    printf("Hello %s", name);
}''',
            function_name="bad_scanf",
            is_vulnerable=True,
            file_origin="sample",
        ),
        # Safe examples
        FunctionSample(
            id="sample_good_strncpy_1",
            source_code='''void good_strncpy(char *user_input) {
    char buffer[32];
    strncpy(buffer, user_input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\\0';
    printf("%s", buffer);
}''',
            function_name="good_strncpy",
            is_vulnerable=False,
            file_origin="sample",
        ),
        FunctionSample(
            id="sample_good_memcpy_1",
            source_code='''void good_memcpy(char *src, size_t len) {
    char dest[64];
    if (len <= sizeof(dest)) {
        memcpy(dest, src, len);
    }
}''',
            function_name="good_memcpy",
            is_vulnerable=False,
            file_origin="sample",
        ),
        FunctionSample(
            id="sample_good_snprintf_1",
            source_code='''void good_snprintf(char *name) {
    char buffer[100];
    snprintf(buffer, sizeof(buffer), "Hello, %s!", name);
}''',
            function_name="good_snprintf",
            is_vulnerable=False,
            file_origin="sample",
        ),
        FunctionSample(
            id="sample_good_fgets_1",
            source_code='''void good_fgets() {
    char buffer[256];
    if (fgets(buffer, sizeof(buffer), stdin) != NULL) {
        process(buffer);
    }
}''',
            function_name="good_fgets",
            is_vulnerable=False,
            file_origin="sample",
        ),
        FunctionSample(
            id="sample_good_scanf_1",
            source_code='''void good_scanf() {
    char name[32];
    scanf("%31s", name);  // Width limit set
    printf("Hello %s", name);
}''',
            function_name="good_scanf",
            is_vulnerable=False,
            file_origin="sample",
        ),
    ]
    
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    dataset = {
        "metadata": {
            "source": "Hand-crafted samples",
            "cwe_id": "CWE-120",
            "total_samples": len(samples),
            "vulnerable_count": sum(1 for s in samples if s.is_vulnerable),
            "safe_count": sum(1 for s in samples if not s.is_vulnerable),
        },
        "samples": [asdict(s) for s in samples],
    }
    
    with open(output_path, "w") as f:
        json.dump(dataset, f, indent=2)
    
    print(f"Sample dataset saved to {output_path}")
    return dataset


def main():
    parser = argparse.ArgumentParser(
        description="Prepare dataset from Juliet Test Suite"
    )
    parser.add_argument(
        "--juliet-path",
        type=Path,
        help="Path to Juliet Test Suite directory"
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data/juliet_samples/dataset.json"),
        help="Output path for the dataset"
    )
    parser.add_argument(
        "--max-samples",
        type=int,
        default=100,
        help="Maximum number of samples (balanced)"
    )
    parser.add_argument(
        "--sample-only",
        action="store_true",
        help="Create sample dataset without Juliet"
    )
    
    args = parser.parse_args()
    
    if args.sample_only or args.juliet_path is None:
        create_sample_dataset(args.output)
    else:
        prepare_dataset(args.juliet_path, args.output, args.max_samples)


if __name__ == "__main__":
    main()
