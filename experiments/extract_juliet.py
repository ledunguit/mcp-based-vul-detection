"""Extract CWE test cases from Juliet Test Suite.

This script extracts individual bad/good functions from the Juliet Test Suite
for use in vulnerability detection experiments.

Supports:
- CWE-120: Buffer Copy without Checking Size of Input
- CWE-121: Stack-based Buffer Overflow
- CWE-122: Heap-based Buffer Overflow  
- CWE-124: Buffer Underwrite
- CWE-125: Out-of-bounds Read
- CWE-126: Buffer Over-read
- CWE-127: Buffer Under-read
- CWE-787: Out-of-bounds Write
"""

import os
import re
import json
import random
from pathlib import Path
from typing import Generator
from dataclasses import dataclass, asdict


# CWE mapping for buffer overflow family
CWE_MAPPING = {
    "CWE120": {
        "id": "CWE-120",
        "name": "Buffer Copy without Checking Size of Input",
        "dir_patterns": ["CWE120", "Buffer_Copy"],
    },
    "CWE121": {
        "id": "CWE-121",
        "name": "Stack-based Buffer Overflow",
        "dir_patterns": ["CWE121", "Stack_Based"],
    },
    "CWE122": {
        "id": "CWE-122",
        "name": "Heap-based Buffer Overflow",
        "dir_patterns": ["CWE122", "Heap_Based"],
    },
    "CWE124": {
        "id": "CWE-124",
        "name": "Buffer Underwrite",
        "dir_patterns": ["CWE124", "Buffer_Underwrite"],
    },
    "CWE125": {
        "id": "CWE-125",
        "name": "Out-of-bounds Read",
        "dir_patterns": ["CWE125", "Out_of_bounds_Read"],
    },
    "CWE126": {
        "id": "CWE-126",
        "name": "Buffer Over-read",
        "dir_patterns": ["CWE126", "Buffer_Overread"],
    },
    "CWE127": {
        "id": "CWE-127",
        "name": "Buffer Under-read",
        "dir_patterns": ["CWE127", "Buffer_Underread"],
    },
    "CWE787": {
        "id": "CWE-787",
        "name": "Out-of-bounds Write",
        "dir_patterns": ["CWE787", "Out_of_bounds_Write"],
    },
}


@dataclass
class ExtractedFunction:
    """A function extracted from Juliet test suite."""
    name: str
    source_code: str
    is_vulnerable: bool
    source_file: str
    cwe_id: str
    sink_functions: list[str]


def find_juliet_files(juliet_path: Path, cwe_keys: list[str]) -> Generator[tuple[Path, str], None, None]:
    """Find all C files for the specified CWEs.
    
    Args:
        juliet_path: Path to testcases directory
        cwe_keys: List of CWE keys (e.g., ["CWE121", "CWE122"])
        
    Yields:
        Tuple of (file_path, cwe_id)
    """
    if not juliet_path.exists():
        print(f"Warning: Juliet path does not exist: {juliet_path}")
        return
    
    for cwe_key in cwe_keys:
        if cwe_key not in CWE_MAPPING:
            print(f"Warning: Unknown CWE key: {cwe_key}")
            continue
        
        cwe_info = CWE_MAPPING[cwe_key]
        cwe_id = cwe_info["id"]
        
        # Find directories matching this CWE
        for dir_pattern in cwe_info["dir_patterns"]:
            for cwe_dir in juliet_path.iterdir():
                if not cwe_dir.is_dir():
                    continue
                if dir_pattern not in cwe_dir.name:
                    continue
                
                # Recursively find C files
                for file in cwe_dir.rglob("*.c"):
                    # Skip main files, helper files, and support files
                    if any(skip in file.name.lower() for skip in ["main", "helper", "support"]):
                        continue
                    yield file, cwe_id


def detect_sink_functions(source_code: str) -> list[str]:
    """Detect dangerous sink functions in the source code."""
    sinks = []
    dangerous_functions = [
        "memcpy", "memmove", "memset",
        "strcpy", "strncpy", "strcat", "strncat",
        "sprintf", "snprintf", "vsprintf", "vsnprintf",
        "gets", "fgets",
        "scanf", "sscanf", "fscanf",
        "read", "recv", "recvfrom",
        "wcscpy", "wcsncpy", "wcscat", "wcsncat",
    ]
    
    for func in dangerous_functions:
        # Match function call pattern
        pattern = rf'\b{func}\s*\('
        if re.search(pattern, source_code):
            sinks.append(func)
    
    return sinks


def extract_functions(file_path: Path, cwe_id: str) -> list[ExtractedFunction]:
    """Extract bad and good functions from a Juliet test case file."""
    try:
        content = file_path.read_text(encoding='utf-8', errors='ignore')
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return []
    
    functions = []
    
    # Improved pattern to match function definitions
    # Matches: return_type function_name(params) { ... }
    func_pattern = re.compile(
        r'^((?:static\s+)?(?:void|int|char\s*\*?|size_t|ssize_t|unsigned\s+\w+|long)\s+(\w+)\s*\([^)]*\)\s*)\{',
        re.MULTILINE
    )
    
    for match in func_pattern.finditer(content):
        func_name = match.group(2)
        start_pos = match.start()
        
        # Determine if this is a bad or good function based on Juliet naming convention
        name_lower = func_name.lower()
        is_bad = any(pattern in name_lower for pattern in ['_bad', 'bad_', 'bad1', 'bad2'])
        is_good = any(pattern in name_lower for pattern in ['good', '_good', 'g2b', 'b2g'])
        
        if not (is_bad or is_good):
            continue
        
        # For functions with both bad and good patterns, prioritize based on context
        if is_bad and is_good:
            # Check if it's a goodG2B or goodB2G pattern (these are good)
            if 'g2b' in name_lower or 'b2g' in name_lower:
                is_bad = False
            else:
                is_good = False
        
        # Find the matching closing brace
        brace_count = 0
        end_pos = match.end() - 1  # Start from the opening brace
        in_string = False
        in_char = False
        escape_next = False
        
        for i, char in enumerate(content[match.end()-1:], start=match.end()-1):
            if escape_next:
                escape_next = False
                continue
            if char == '\\':
                escape_next = True
                continue
            if char == '"' and not in_char:
                in_string = not in_string
            elif char == "'" and not in_string:
                in_char = not in_char
            elif not in_string and not in_char:
                if char == '{':
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        end_pos = i + 1
                        break
        
        func_body = content[start_pos:end_pos]
        
        # Skip very long or very short functions
        if len(func_body) < 50 or len(func_body) > 5000:
            continue
        
        # Detect sink functions
        sinks = detect_sink_functions(func_body)
        
        functions.append(ExtractedFunction(
            name=func_name,
            source_code=func_body,
            is_vulnerable=is_bad,
            source_file=str(file_path.name),
            cwe_id=cwe_id,
            sink_functions=sinks,
        ))
    
    return functions


def create_dataset(
    juliet_path: Path,
    output_path: Path,
    count: int = 200,
    cwe_keys: list[str] | None = None,
    balanced: bool = True,
    seed: int = 42,
) -> dict:
    """
    Create a dataset from Juliet test cases.
    
    Args:
        juliet_path: Path to Juliet testcases directory
        output_path: Path to save the dataset JSON
        count: Number of samples to include
        cwe_keys: List of CWE keys to extract (default: all buffer overflow CWEs)
        balanced: If True, include equal numbers of bad and good samples
        seed: Random seed for reproducibility
    """
    random.seed(seed)
    
    if cwe_keys is None:
        cwe_keys = list(CWE_MAPPING.keys())
    
    all_bad = []
    all_good = []
    cwe_counts = {k: {"bad": 0, "good": 0} for k in cwe_keys}
    
    print(f"Scanning {juliet_path} for CWE test cases...")
    print(f"Looking for: {', '.join(cwe_keys)}")
    
    for file_path, cwe_id in find_juliet_files(juliet_path, cwe_keys):
        functions = extract_functions(file_path, cwe_id)
        cwe_key = cwe_id.replace("-", "")
        
        for func in functions:
            if func.is_vulnerable:
                all_bad.append(func)
                if cwe_key in cwe_counts:
                    cwe_counts[cwe_key]["bad"] += 1
            else:
                all_good.append(func)
                if cwe_key in cwe_counts:
                    cwe_counts[cwe_key]["good"] += 1
    
    print(f"\nExtraction Summary:")
    print(f"  Total bad functions: {len(all_bad)}")
    print(f"  Total good functions: {len(all_good)}")
    print(f"\nPer-CWE breakdown:")
    for cwe_key, counts in cwe_counts.items():
        if counts["bad"] > 0 or counts["good"] > 0:
            print(f"  {cwe_key}: {counts['bad']} bad, {counts['good']} good")
    
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
            'id': f"juliet_{func.cwe_id.replace('-', '')}_{i:04d}",
            'function_name': func.name,
            'source_code': func.source_code,
            'is_vulnerable': func.is_vulnerable,
            'source_file': func.source_file,
            'cwe_id': func.cwe_id,
            'sink_functions': func.sink_functions,
        })
    
    # Calculate per-CWE stats
    cwe_stats = {}
    for sample in samples:
        cwe = sample['cwe_id']
        if cwe not in cwe_stats:
            cwe_stats[cwe] = {"vulnerable": 0, "safe": 0}
        if sample['is_vulnerable']:
            cwe_stats[cwe]["vulnerable"] += 1
        else:
            cwe_stats[cwe]["safe"] += 1
    
    dataset = {
        'metadata': {
            'source': 'Juliet Test Suite 1.3',
            'cwe_types': list(cwe_stats.keys()),
            'total_samples': len(samples),
            'vulnerable_count': sum(1 for s in samples if s['is_vulnerable']),
            'safe_count': sum(1 for s in samples if not s['is_vulnerable']),
            'per_cwe_stats': cwe_stats,
        },
        'samples': samples,
    }
    
    # Save dataset
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(dataset, f, indent=2)
    
    print(f"\nDataset saved to {output_path}")
    print(f"  Total: {len(samples)}")
    print(f"  Vulnerable: {dataset['metadata']['vulnerable_count']}")
    print(f"  Safe: {dataset['metadata']['safe_count']}")
    
    return dataset


def create_extended_sample_dataset(output_path: Path) -> dict:
    """
    Create an extended sample dataset with hand-crafted examples.
    
    This includes more diverse examples for each CWE type.
    """
    samples = []
    
    # CWE-120/121 Buffer Copy Vulnerabilities
    vulnerable_samples = [
        # strcpy vulnerabilities
        {
            "id": "sample_bad_strcpy_1",
            "source_code": '''void bad_strcpy(char *user_input) {
    char buffer[32];
    strcpy(buffer, user_input);  // No bounds check
    printf("%s", buffer);
}''',
            "function_name": "bad_strcpy",
            "cwe_id": "CWE-120",
            "sink_functions": ["strcpy"],
        },
        {
            "id": "sample_bad_strcpy_2",
            "source_code": '''void bad_strcpy_argv(int argc, char *argv[]) {
    char local_buf[64];
    if (argc > 1) {
        strcpy(local_buf, argv[1]);  // Command line input unbounded
    }
}''',
            "function_name": "bad_strcpy_argv",
            "cwe_id": "CWE-121",
            "sink_functions": ["strcpy"],
        },
        # memcpy vulnerabilities
        {
            "id": "sample_bad_memcpy_1",
            "source_code": '''void bad_memcpy(char *src, size_t len) {
    char dest[64];
    memcpy(dest, src, len);  // len not validated
}''',
            "function_name": "bad_memcpy",
            "cwe_id": "CWE-120",
            "sink_functions": ["memcpy"],
        },
        {
            "id": "sample_bad_memcpy_2",
            "source_code": '''void bad_memcpy_heap(char *data, size_t size) {
    char *heap_buf = malloc(100);
    if (heap_buf) {
        memcpy(heap_buf, data, size);  // size may exceed 100
        free(heap_buf);
    }
}''',
            "function_name": "bad_memcpy_heap",
            "cwe_id": "CWE-122",
            "sink_functions": ["memcpy"],
        },
        # sprintf vulnerabilities
        {
            "id": "sample_bad_sprintf_1",
            "source_code": '''void bad_sprintf(char *name) {
    char buffer[100];
    sprintf(buffer, "Hello, %s! Welcome to our system.", name);
}''',
            "function_name": "bad_sprintf",
            "cwe_id": "CWE-120",
            "sink_functions": ["sprintf"],
        },
        {
            "id": "sample_bad_sprintf_2",
            "source_code": '''void bad_sprintf_multiple(char *first, char *last, int id) {
    char message[128];
    sprintf(message, "User: %s %s (ID: %d) logged in at %s", first, last, id, __TIME__);
    log_message(message);
}''',
            "function_name": "bad_sprintf_multiple",
            "cwe_id": "CWE-121",
            "sink_functions": ["sprintf"],
        },
        # gets vulnerability
        {
            "id": "sample_bad_gets_1",
            "source_code": '''void bad_gets() {
    char buffer[256];
    gets(buffer);  // Never safe
    process(buffer);
}''',
            "function_name": "bad_gets",
            "cwe_id": "CWE-120",
            "sink_functions": ["gets"],
        },
        # scanf vulnerabilities
        {
            "id": "sample_bad_scanf_1",
            "source_code": '''void bad_scanf() {
    char name[32];
    scanf("%s", name);  // No width limit
    printf("Hello %s", name);
}''',
            "function_name": "bad_scanf",
            "cwe_id": "CWE-120",
            "sink_functions": ["scanf"],
        },
        {
            "id": "sample_bad_scanf_2",
            "source_code": '''void bad_scanf_loop() {
    char input[16];
    while (1) {
        printf("Enter command: ");
        scanf("%s", input);  // Unbounded read in loop
        if (strcmp(input, "quit") == 0) break;
        execute_command(input);
    }
}''',
            "function_name": "bad_scanf_loop",
            "cwe_id": "CWE-121",
            "sink_functions": ["scanf"],
        },
        # strcat vulnerability
        {
            "id": "sample_bad_strcat_1",
            "source_code": '''void bad_strcat(char *prefix, char *suffix) {
    char result[64];
    strcpy(result, prefix);
    strcat(result, suffix);  // No check if combined length fits
}''',
            "function_name": "bad_strcat",
            "cwe_id": "CWE-120",
            "sink_functions": ["strcpy", "strcat"],
        },
        # read vulnerability
        {
            "id": "sample_bad_read_1",
            "source_code": '''void bad_read(int fd, size_t count) {
    char buffer[256];
    read(fd, buffer, count);  // count may exceed buffer size
}''',
            "function_name": "bad_read",
            "cwe_id": "CWE-120",
            "sink_functions": ["read"],
        },
        # recv vulnerability
        {
            "id": "sample_bad_recv_1",
            "source_code": '''void bad_recv(int sock) {
    char packet[512];
    recv(sock, packet, 1024, 0);  // Reading more than buffer size
}''',
            "function_name": "bad_recv",
            "cwe_id": "CWE-122",
            "sink_functions": ["recv"],
        },
        # fgets with wrong size
        {
            "id": "sample_bad_fgets_1",
            "source_code": '''void bad_fgets(FILE *fp) {
    char line[64];
    fgets(line, 128, fp);  // Size larger than buffer
}''',
            "function_name": "bad_fgets",
            "cwe_id": "CWE-120",
            "sink_functions": ["fgets"],
        },
        # snprintf with wrong size
        {
            "id": "sample_bad_snprintf_1",
            "source_code": '''void bad_snprintf(char *data) {
    char buf[32];
    snprintf(buf, 64, "Data: %s", data);  // Size larger than buffer
}''',
            "function_name": "bad_snprintf",
            "cwe_id": "CWE-120",
            "sink_functions": ["snprintf"],
        },
        # Wide string vulnerability
        {
            "id": "sample_bad_wcscpy_1",
            "source_code": '''void bad_wcscpy(wchar_t *src) {
    wchar_t dest[50];
    wcscpy(dest, src);  // Unbounded wide string copy
}''',
            "function_name": "bad_wcscpy",
            "cwe_id": "CWE-120",
            "sink_functions": ["wcscpy"],
        },
    ]
    
    safe_samples = [
        # strncpy with proper bounds
        {
            "id": "sample_good_strncpy_1",
            "source_code": '''void good_strncpy(char *user_input) {
    char buffer[32];
    strncpy(buffer, user_input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\\0';
    printf("%s", buffer);
}''',
            "function_name": "good_strncpy",
            "cwe_id": "CWE-120",
            "sink_functions": ["strncpy"],
        },
        {
            "id": "sample_good_strncpy_2",
            "source_code": '''void good_strncpy_check(char *src, size_t src_len) {
    char dest[100];
    size_t copy_len = (src_len < sizeof(dest)) ? src_len : sizeof(dest) - 1;
    strncpy(dest, src, copy_len);
    dest[copy_len] = '\\0';
}''',
            "function_name": "good_strncpy_check",
            "cwe_id": "CWE-121",
            "sink_functions": ["strncpy"],
        },
        # memcpy with bounds check
        {
            "id": "sample_good_memcpy_1",
            "source_code": '''void good_memcpy(char *src, size_t len) {
    char dest[64];
    if (len <= sizeof(dest)) {
        memcpy(dest, src, len);
    }
}''',
            "function_name": "good_memcpy",
            "cwe_id": "CWE-120",
            "sink_functions": ["memcpy"],
        },
        {
            "id": "sample_good_memcpy_2",
            "source_code": '''void good_memcpy_min(char *data, size_t data_len) {
    char buffer[128];
    size_t safe_len = (data_len < sizeof(buffer)) ? data_len : sizeof(buffer);
    memcpy(buffer, data, safe_len);
}''',
            "function_name": "good_memcpy_min",
            "cwe_id": "CWE-122",
            "sink_functions": ["memcpy"],
        },
        # snprintf safe usage
        {
            "id": "sample_good_snprintf_1",
            "source_code": '''void good_snprintf(char *name) {
    char buffer[100];
    snprintf(buffer, sizeof(buffer), "Hello, %s!", name);
}''',
            "function_name": "good_snprintf",
            "cwe_id": "CWE-120",
            "sink_functions": ["snprintf"],
        },
        {
            "id": "sample_good_snprintf_2",
            "source_code": '''void good_snprintf_check(char *user, char *msg) {
    char log_entry[256];
    int written = snprintf(log_entry, sizeof(log_entry), "[%s]: %s", user, msg);
    if (written >= sizeof(log_entry)) {
        // Handle truncation
        log_entry[sizeof(log_entry) - 1] = '\\0';
    }
}''',
            "function_name": "good_snprintf_check",
            "cwe_id": "CWE-121",
            "sink_functions": ["snprintf"],
        },
        # fgets safe usage
        {
            "id": "sample_good_fgets_1",
            "source_code": '''void good_fgets() {
    char buffer[256];
    if (fgets(buffer, sizeof(buffer), stdin) != NULL) {
        process(buffer);
    }
}''',
            "function_name": "good_fgets",
            "cwe_id": "CWE-120",
            "sink_functions": ["fgets"],
        },
        {
            "id": "sample_good_fgets_2",
            "source_code": '''void good_fgets_trim(FILE *fp) {
    char line[512];
    if (fgets(line, sizeof(line), fp)) {
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\\n') {
            line[len-1] = '\\0';
        }
        process_line(line);
    }
}''',
            "function_name": "good_fgets_trim",
            "cwe_id": "CWE-121",
            "sink_functions": ["fgets"],
        },
        # scanf with width specifier
        {
            "id": "sample_good_scanf_1",
            "source_code": '''void good_scanf() {
    char name[32];
    scanf("%31s", name);  // Width limit set
    printf("Hello %s", name);
}''',
            "function_name": "good_scanf",
            "cwe_id": "CWE-120",
            "sink_functions": ["scanf"],
        },
        {
            "id": "sample_good_scanf_2",
            "source_code": '''void good_scanf_format() {
    char command[16];
    char arg[64];
    scanf("%15s %63s", command, arg);  // Both with limits
    execute(command, arg);
}''',
            "function_name": "good_scanf_format",
            "cwe_id": "CWE-121",
            "sink_functions": ["scanf"],
        },
        # strncat safe usage
        {
            "id": "sample_good_strncat_1",
            "source_code": '''void good_strncat(char *prefix, char *suffix) {
    char result[64];
    strncpy(result, prefix, sizeof(result) - 1);
    result[sizeof(result) - 1] = '\\0';
    size_t remaining = sizeof(result) - strlen(result) - 1;
    strncat(result, suffix, remaining);
}''',
            "function_name": "good_strncat",
            "cwe_id": "CWE-120",
            "sink_functions": ["strncpy", "strncat"],
        },
        # read with bounds
        {
            "id": "sample_good_read_1",
            "source_code": '''void good_read(int fd) {
    char buffer[256];
    ssize_t n = read(fd, buffer, sizeof(buffer) - 1);
    if (n > 0) {
        buffer[n] = '\\0';
        process(buffer);
    }
}''',
            "function_name": "good_read",
            "cwe_id": "CWE-120",
            "sink_functions": ["read"],
        },
        # recv with proper size
        {
            "id": "sample_good_recv_1",
            "source_code": '''void good_recv(int sock) {
    char packet[512];
    ssize_t received = recv(sock, packet, sizeof(packet) - 1, 0);
    if (received > 0) {
        packet[received] = '\\0';
    }
}''',
            "function_name": "good_recv",
            "cwe_id": "CWE-122",
            "sink_functions": ["recv"],
        },
        # Dynamic allocation with check
        {
            "id": "sample_good_dynamic_1",
            "source_code": '''void good_dynamic_copy(char *src, size_t len) {
    if (len > 0 && len < SIZE_MAX) {
        char *dest = malloc(len + 1);
        if (dest) {
            memcpy(dest, src, len);
            dest[len] = '\\0';
            process(dest);
            free(dest);
        }
    }
}''',
            "function_name": "good_dynamic_copy",
            "cwe_id": "CWE-122",
            "sink_functions": ["memcpy"],
        },
        # Wide string with bounds
        {
            "id": "sample_good_wcsncpy_1",
            "source_code": '''void good_wcsncpy(wchar_t *src, size_t src_len) {
    wchar_t dest[50];
    size_t copy_len = (src_len < 49) ? src_len : 49;
    wcsncpy(dest, src, copy_len);
    dest[copy_len] = L'\\0';
}''',
            "function_name": "good_wcsncpy",
            "cwe_id": "CWE-120",
            "sink_functions": ["wcsncpy"],
        },
    ]
    
    # Add all samples with is_vulnerable flag
    for sample in vulnerable_samples:
        sample["is_vulnerable"] = True
        sample["file_origin"] = "sample"
        samples.append(sample)
    
    for sample in safe_samples:
        sample["is_vulnerable"] = False
        sample["file_origin"] = "sample"
        samples.append(sample)
    
    # Calculate stats
    cwe_stats = {}
    for sample in samples:
        cwe = sample['cwe_id']
        if cwe not in cwe_stats:
            cwe_stats[cwe] = {"vulnerable": 0, "safe": 0}
        if sample['is_vulnerable']:
            cwe_stats[cwe]["vulnerable"] += 1
        else:
            cwe_stats[cwe]["safe"] += 1
    
    dataset = {
        'metadata': {
            'source': 'Extended hand-crafted samples',
            'cwe_types': list(cwe_stats.keys()),
            'total_samples': len(samples),
            'vulnerable_count': sum(1 for s in samples if s['is_vulnerable']),
            'safe_count': sum(1 for s in samples if not s['is_vulnerable']),
            'per_cwe_stats': cwe_stats,
        },
        'samples': samples,
    }
    
    # Save dataset
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(dataset, f, indent=2)
    
    print(f"Extended sample dataset saved to {output_path}")
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
        default=200,
        help="Number of samples to extract (default: 200)"
    )
    parser.add_argument(
        "--cwe",
        type=str,
        nargs="+",
        default=["CWE121", "CWE122"],
        choices=list(CWE_MAPPING.keys()),
        help="CWE types to extract"
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for reproducibility"
    )
    parser.add_argument(
        "--extended-samples",
        action="store_true",
        help="Create extended sample dataset (no Juliet required)"
    )
    
    args = parser.parse_args()
    
    if args.extended_samples:
        create_extended_sample_dataset(args.output)
    else:
        create_dataset(
            juliet_path=args.juliet_path,
            output_path=args.output,
            count=args.count,
            cwe_keys=args.cwe,
            seed=args.seed,
        )
