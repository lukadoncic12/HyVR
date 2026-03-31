import json
import os
import sys
import argparse
import threading

# Add project root directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import utils.llm_client as llm_client

# Global variables
LLM_CLIENT = None
output_lock = threading.Lock()

# CWE list with definitions
CWE_LIST = {
    "CWE-119": {
        "NAME": "Improper Restriction of Operations within the Bounds of a Memory Buffer",
        "DEFINITION": "The software performs operations on a memory buffer, but it can read from or write to a memory location that is outside of the intended boundary of the buffer."
    },
    "CWE-125": {
        "NAME": "Out-of-bounds Read",
        "DEFINITION": "The software reads data past the end, or before the beginning, of the intended buffer."
    },
    "CWE-20": {
        "NAME": "Improper Input Validation",
        "DEFINITION": "The product receives input or data, but it does not validate or incorrectly validates that the input has the properties that are required to process the data safely and correctly."
    },
    "CWE-200": {
        "NAME": "Exposure of Sensitive Information to an Unauthorized Actor",
        "DEFINITION": "The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information."
    },
    "CWE-264": {
        "NAME": "Permissions, Privileges, and Access Controls",
        "DEFINITION": "The product does not properly enforce limitations on what authenticated users are allowed to do."
    },
    "CWE-362": {
        "NAME": "Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')",
        "DEFINITION": "The product contains a race condition in a shared resource that cannot be accessed safely by multiple threads of execution at the same time."
    },
    "CWE-401": {
        "NAME": "Improper Release of Memory Before Removing Last Reference ('Memory Leak')",
        "DEFINITION": "The software does not release memory after it has finished using it, which can lead to memory exhaustion and possibly denial of service."
    },
    "CWE-416": {
        "NAME": "Use After Free",
        "DEFINITION": "Referencing memory after it has been freed can cause a program to crash, use unexpected values, or execute code."
    },
    "CWE-476": {
        "NAME": "NULL Pointer Dereference",
        "DEFINITION": "A NULL pointer dereference occurs when the application dereferences a pointer that it expects to be valid, but is NULL."
    },
    "CWE-787": {
        "NAME": "Out-of-bounds Write",
        "DEFINITION": "The software writes data past the end, or before the beginning, of the intended buffer."
    }
}

# Generate code behavior extraction prompt
def generate_code_behavior_extraction_prompt(cve_instances, cwe_id, cwe_name, cwe_definition):
    instances_text = "\n".join([f"Instance {i+1}:\nCode before change:\n{instance['code_before_change']}\n\nVulnerability behavior:\n{json.dumps(instance['vulnerability_behavior'], indent=2)}" for i, instance in enumerate(cve_instances)])
    
    prompt = f"""You are a security researcher and vulnerability expert. Your task is to analyze {len(cve_instances)} code examples containing {cwe_id} ({cwe_name}) vulnerabilities and extract the general code behavior patterns that indicate this vulnerability type.

{cwe_id} Definition: {cwe_definition}

Please analyze the following code examples:

{instances_text}

Your task is to identify and describe the common code behavior patterns that are characteristic of {cwe_id} vulnerabilities. Focus on describing the code's behavior rather than implementation details.

Please provide your analysis in exactly the following JSON format:
{{
  "common_code_behavior": "A concise description of the general code behavior patterns that indicate {cwe_id} vulnerabilities",
  "vulnerability_logic_pattern": "A concise description of the vulnerability's logical pattern as a sequence of steps",
  "reasoning_checklist": [
    "Question 1 about code behavior",
    "Question 2 about control flow",
    "Question 3 about validation",
    "Question 4 about edge cases"
  ],
  "standard_fix_principle": "Clear principles for fixing this vulnerability type"
}}

Requirements:
1. Write everything in English
2. common_code_behavior: Describe the general code behavior patterns that are common across all {cwe_id} vulnerabilities. This should be abstract enough to match different implementations but specific enough to be recognizable.
3. vulnerability_logic_pattern: Describe the vulnerability as a sequence of logical steps
4. reasoning_checklist: Provide 4-6 specific questions to verify the vulnerability based on code behavior
5. standard_fix_principle: Describe the fundamental principles for fixing this vulnerability

Focus on abstract code behavior patterns, not specific implementation details. Make your analysis applicable to all {cwe_id} vulnerabilities."""
    
    return prompt

# Extract CVE instances from knowledge file
def extract_cve_instances(knowledge_file, num_instances=10):
    with open(knowledge_file, 'r') as f:
        knowledge_data = json.load(f)
    
    # Select first N instances
    selected_instances = knowledge_data[:num_instances]
    return selected_instances

# Build principle entry with common code behavior
def build_principle_entry(cve_instances, cwe_id, cwe_name, cwe_definition, model_name, model_settings):
    global LLM_CLIENT
    
    # Generate extraction prompt
    prompt = generate_code_behavior_extraction_prompt(cve_instances, cwe_id, cwe_name, cwe_definition)
    
    # Call LLM to extract pattern
    prompt_dict = llm_client.generate_simple_prompt(prompt)
    output = LLM_CLIENT.generate_text(prompt_dict, model_settings)
    
    # Parse LLM output
    try:
        # Try to parse JSON directly
        pattern_data = json.loads(output)
    except json.JSONDecodeError:
        # If direct parsing fails, try to extract JSON part
        import re
        json_match = re.search(r'\{[\s\S]*\}', output)
        if json_match:
            try:
                pattern_data = json.loads(json_match.group(0))
            except json.JSONDecodeError:
                # Use default values if still fails
                pattern_data = {
                    "common_code_behavior": f"{cwe_id} vulnerabilities exhibit specific code behaviors related to {cwe_name}.",
                    "vulnerability_logic_pattern": f"{cwe_id} vulnerabilities involve {cwe_name}.",
                    "reasoning_checklist": [
                        "Identify the vulnerable code behavior",
                        "Check for proper validation",
                        "Verify boundary conditions",
                        "Review error handling"
                    ],
                    "standard_fix_principle": f"Implement proper security measures to prevent {cwe_id} vulnerabilities."
                }
        else:
            # Use default values
            pattern_data = {
                "common_code_behavior": f"{cwe_id} vulnerabilities exhibit specific code behaviors related to {cwe_name}.",
                "vulnerability_logic_pattern": f"{cwe_id} vulnerabilities involve {cwe_name}.",
                "reasoning_checklist": [
                    "Identify the vulnerable code behavior",
                    "Check for proper validation",
                    "Verify boundary conditions",
                    "Review error handling"
                ],
                "standard_fix_principle": f"Implement proper security measures to prevent {cwe_id} vulnerabilities."
            }
    
    # Build principle entry with common code behavior
    principle_entry = {
        "cwe_id": cwe_id,
        "name": cwe_name,
        "definition": cwe_definition,
        "common_code_behavior": pattern_data.get("common_code_behavior", ""),
        "vulnerability_logic_pattern": pattern_data.get("vulnerability_logic_pattern", ""),
        "reasoning_checklist": pattern_data.get("reasoning_checklist", []),
        "standard_fix_principle": pattern_data.get("standard_fix_principle", ""),
        "source_instances": {
            "cve_ids": [instance.get("CVE_id", "Unknown") for instance in cve_instances],
            "sample_count": len(cve_instances)
        }
    }
    
    return principle_entry

# Main function
def build_principle_knowledge(args):
    global LLM_CLIENT
    
    # Initialize LLM client
    LLM_CLIENT = llm_client.get_llm_client(args.model_name)
    print(f"Using model: {LLM_CLIENT.model_name}")
    
    # Ensure output directory exists
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Process each CWE
    for cwe_id, cwe_info in CWE_LIST.items():
        cwe_name = cwe_info["NAME"]
        cwe_definition = cwe_info["DEFINITION"]
        
        # Build knowledge file path
        knowledge_file = os.path.join(args.knowledge_dir, f"linux_kernel_{cwe_id}_knowledge.json")
        output_file = os.path.join(args.output_dir, f"cwe_{cwe_id.replace('-', '_')}_principle_knowledge.json")
        
        # Force regeneration
        if os.path.exists(output_file):
            print(f"Principle knowledge file {output_file} exists. Overwriting {cwe_id}...")
        
        # Check if knowledge file exists
        if not os.path.exists(knowledge_file):
            print(f"Knowledge file {knowledge_file} not found for {cwe_id}. Skipping...")
            continue
        
        print(f"\nProcessing {cwe_id} ({cwe_name})...")
        
        # Extract CVE instances
        print(f"Extracting CVE instances from {knowledge_file}")
        cve_instances = extract_cve_instances(knowledge_file, args.num_instances)
        
        if not cve_instances:
            print(f"No CVE instances found in knowledge file for {cwe_id}")
            continue
        
        print(f"Extracted {len(cve_instances)} CVE instances")
        
        # Build principle entry with common code behavior
        print(f"Building principle entry with common code behavior for {cwe_id}")
        principle_entry = build_principle_entry(cve_instances, cwe_id, cwe_name, cwe_definition, args.model_name, args.model_settings)
        
        # Save principle knowledge
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump([principle_entry], f, indent=4, ensure_ascii=False)
        
        print(f"Principle knowledge base with common code behavior saved to {output_file}")
        print("\nGenerated principle entry:")
        print(json.dumps(principle_entry, indent=2, ensure_ascii=False))

# Parse command line arguments
def parse_args():
    parser = argparse.ArgumentParser(description="Build principle knowledge base with common code behavior field")
    parser.add_argument("--knowledge_dir", type=str, default="src/output/knowledge/baseline_knowledge", help="Directory containing CWE knowledge files")
    parser.add_argument("--output_dir", type=str, default="IdeaB/data/knowledge/principle_knowledge_with_code_behavior", help="Directory to save principle knowledge files")
    parser.add_argument("--model_name", type=str, default="gpt-4", help="Name of the LLM model to use")
    parser.add_argument("--num_instances", type=int, default=10, help="Number of CVE instances to use for pattern extraction")
    parser.add_argument("--model_settings", type=str, default=None, help="Model settings in key=value format separated by semicolons")
    args = parser.parse_args()
    if args.model_settings:
        args.model_settings = llm_client.parse_kv_string_to_dict(args.model_settings)
    else:
        args.model_settings = {}
    return args

if __name__ == "__main__":
    args = parse_args()
    build_principle_knowledge(args)
