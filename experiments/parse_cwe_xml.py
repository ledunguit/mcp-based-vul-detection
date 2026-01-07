"""Parse MITRE CWE XML and extract knowledge for buffer overflow CWEs.

This script parses the official MITRE CWE database XML file and extracts
structured knowledge for CWE-120, CWE-121, CWE-122 (buffer overflow variants).
"""

import xml.etree.ElementTree as ET
import json
from pathlib import Path
from typing import Any


def parse_cwe_xml(xml_path: Path) -> dict[str, Any]:
    """Parse CWE XML file and extract relevant weakness entries."""
    print(f"Parsing {xml_path}...")
    tree = ET.parse(xml_path)
    root = tree.getroot()
    
    # Define namespace
    ns = {'cwe': 'http://cwe.mitre.org/cwe-7'}
    
    # CWEs we want to extract (buffer overflow related)
    target_cwes = {'120', '121', '122', '124', '125', '126', '127', '131', '680', '787', '788'}
    
    cwe_data = {}
    
    # Find all Weakness elements
    for weakness in root.findall('.//cwe:Weakness', ns):
        cwe_id = weakness.get('ID')
        
        if cwe_id not in target_cwes:
            continue
        
        entry = {
            'id': f"CWE-{cwe_id}",
            'name': weakness.get('Name', ''),
            'abstraction': weakness.get('Abstraction', ''),
            'status': weakness.get('Status', ''),
        }
        
        # Description
        desc = weakness.find('cwe:Description', ns)
        if desc is not None and desc.text:
            entry['description'] = desc.text.strip()
        
        # Extended Description
        ext_desc = weakness.find('cwe:Extended_Description', ns)
        if ext_desc is not None:
            entry['extended_description'] = ''.join(ext_desc.itertext()).strip()
        
        # Common Consequences
        consequences = []
        for cons in weakness.findall('.//cwe:Consequence', ns):
            c = {}
            scopes = [s.text for s in cons.findall('cwe:Scope', ns) if s.text]
            impacts = [i.text for i in cons.findall('cwe:Impact', ns) if i.text]
            note = cons.find('cwe:Note', ns)
            
            if scopes:
                c['scopes'] = scopes
            if impacts:
                c['impacts'] = impacts
            if note is not None and note.text:
                c['note'] = note.text.strip()
            
            if c:
                consequences.append(c)
        
        if consequences:
            entry['consequences'] = consequences
        
        # Potential Mitigations
        mitigations = []
        for mit in weakness.findall('.//cwe:Mitigation', ns):
            m = {}
            phase = mit.find('cwe:Phase', ns)
            desc = mit.find('cwe:Description', ns)
            effectiveness = mit.find('cwe:Effectiveness', ns)
            
            if phase is not None and phase.text:
                m['phase'] = phase.text
            if desc is not None:
                m['description'] = ''.join(desc.itertext()).strip()
            if effectiveness is not None and effectiveness.text:
                m['effectiveness'] = effectiveness.text
            
            if m:
                mitigations.append(m)
        
        if mitigations:
            entry['mitigations'] = mitigations
        
        # Detection Methods
        detection = []
        for det in weakness.findall('.//cwe:Detection_Method', ns):
            d = {}
            method = det.find('cwe:Method', ns)
            desc = det.find('cwe:Description', ns)
            effectiveness = det.find('cwe:Effectiveness', ns)
            
            if method is not None and method.text:
                d['method'] = method.text
            if desc is not None:
                d['description'] = ''.join(desc.itertext()).strip()
            if effectiveness is not None and effectiveness.text:
                d['effectiveness'] = effectiveness.text
            
            if d:
                detection.append(d)
        
        if detection:
            entry['detection_methods'] = detection
        
        # Demonstrative Examples
        examples = []
        for ex in weakness.findall('.//cwe:Demonstrative_Example', ns):
            example = {}
            intro = ex.find('cwe:Intro_Text', ns)
            
            if intro is not None:
                example['intro'] = ''.join(intro.itertext()).strip()
            
            # Get code examples
            code_examples = []
            for code in ex.findall('.//cwe:Example_Code', ns):
                ce = {
                    'nature': code.get('Nature', ''),
                    'language': code.get('Language', ''),
                }
                # Extract code from xhtml:div
                code_text = ''.join(code.itertext()).strip()
                if code_text:
                    ce['code'] = code_text
                    code_examples.append(ce)
            
            if code_examples:
                example['code_examples'] = code_examples
            
            if example:
                examples.append(example)
        
        if examples:
            entry['examples'] = examples
        
        # Related Weaknesses
        related = []
        for rel in weakness.findall('.//cwe:Related_Weakness', ns):
            related.append({
                'nature': rel.get('Nature', ''),
                'cwe_id': f"CWE-{rel.get('CWE_ID', '')}",
            })
        
        if related:
            entry['related_weaknesses'] = related
        
        # Applicable Platforms
        platforms = []
        for lang in weakness.findall('.//cwe:Language', ns):
            name = lang.get('Name') or lang.get('Class')
            if name:
                platforms.append({'type': 'language', 'name': name})
        
        if platforms:
            entry['applicable_platforms'] = platforms
        
        cwe_data[f"CWE-{cwe_id}"] = entry
        print(f"  Extracted CWE-{cwe_id}: {entry['name']}")
    
    return cwe_data


def create_knowledge_base(cwe_data: dict, output_path: Path):
    """Create a structured knowledge base JSON from parsed CWE data."""
    # Add metadata
    knowledge_base = {
        'source': 'MITRE CWE Database',
        'version': '4.19',
        'url': 'https://cwe.mitre.org',
        'description': 'Official CWE data for buffer overflow vulnerabilities',
        'weaknesses': cwe_data,
    }
    
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(knowledge_base, f, indent=2)
    
    print(f"\nKnowledge base saved to {output_path}")
    print(f"Total CWEs extracted: {len(cwe_data)}")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Parse MITRE CWE XML")
    parser.add_argument(
        "--input",
        type=Path,
        default=Path("data/cwe_mitre/cwec_v4.19.xml"),
        help="Path to CWE XML file"
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data/cwe_knowledge_mitre.json"),
        help="Output JSON path"
    )
    
    args = parser.parse_args()
    
    cwe_data = parse_cwe_xml(args.input)
    create_knowledge_base(cwe_data, args.output)
