#!/usr/bin/env python3
import yaml
import argparse
import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

def load_yaml_metadata(file_path):
    """
    Load only the YAML metadata from a file.
    Assumes the YAML metadata is between the first two '---'.
    """
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    # Split content by the '---'
    # Note: Will later be replaced by using yaml.load_all instead of splitting
    # to avoid issues with '---' in the content.
    parts = content.split('---')
    if len(parts) >= 3:
        metadata = parts[1]
    else:
        # If no metadata is found, assume whole file is YAML
        metadata = content
    try:
        data = yaml.safe_load(metadata)
        return data
    except Exception as e:
        logging.error(f"Error parsing YAML metadata in {file_path}: {e}")
        return None

def merge_rule_data(scapolite_data):
    """
    If a 'scapolite' key is found, merge the content with the rest of the document.
    """
    if 'scapolite' in scapolite_data:
        rule_data = scapolite_data.get('scapolite').copy()
        # Merge
        for key, value in scapolite_data.items():
            if key != 'scapolite':
                rule_data[key] = value
        return rule_data
    return scapolite_data

def convert_rule_to_ansible(scapolite_data):
    """
    Convert a Scapolite rule (YAML data) to an Ansible playbook.

    """
    # Merge scapolite metadata with the rest of the document
    rule_data = merge_rule_data(scapolite_data)

    play = {
        'hosts': 'windows',
        'gather_facts': False,
        'tasks': []
    }
    
    tasks_added = False

    # Search the implementations block for automations
    implementations = rule_data.get('implementations', [])
    for impl in implementations:
        automations = impl.get('automations', [])
        if not automations:
            continue
        for automation in automations:
            # Expect a registry-based automation to include a 'registry_key'
            registry_key = automation.get('registry_key')
            if not registry_key:
                logging.warning("No 'registry_key' found in automation; skipping this automation.")
                continue

            values = automation.get('values', {})
            if not values:
                logging.warning("No 'values' found in automation; skipping this automation.")
                continue

            # Create a task for each registry value setting
            for name, value in values.items():
                task = {
                    'name': f"Set {name} to {value}",
                    'ansible.windows.win_regedit': {
                        'path': f"HKLM:\\{registry_key}",
                        'name': name,
                        'data': value,
                        'type': 'dword' if isinstance(value, int) else 'string'
                    }
                }
                play['tasks'].append(task)
                tasks_added = True

    if not tasks_added:
        logging.error("No valid automation data found in file. No tasks were generated.")
    
    return play

def convert_directory(input_dir, output_file):
    """
    Convert all YAML files in the given input directory to a combined Ansible playbook.
    """
    plays = []
    if not os.path.exists(input_dir):
        logging.error(f"Input directory '{input_dir}' does not exist.")
        return

    for filename in os.listdir(input_dir):
        if filename.endswith(('.yml', '.yaml')):
            input_path = os.path.join(input_dir, filename)
            logging.info(f"Processing: {input_path}")
            scapolite_data = load_yaml_metadata(input_path)
            if scapolite_data is None:
                logging.error(f"Skipping file {filename} due to YAML parse error.")
                continue
            
            try:
                play = convert_rule_to_ansible(scapolite_data)
                if play['tasks']:
                    plays.append(play)
                else:
                    logging.warning(f"No tasks generated for {filename}.")
            except Exception as e:
                logging.error(f"Error converting {filename}: {e}")
    
    # Create output directory if needed
    output_dir = os.path.dirname(output_file)
    if output_dir and not os.path.exists(output_dir):
        try:
            os.makedirs(output_dir)
            logging.info(f"Created directory {output_dir}.")
        except Exception as e:
            logging.error(f"Error creating directory {output_dir}: {e}")
            return

    if plays:
        try:
            with open(output_file, 'w', encoding='utf-8') as out_f:
                yaml.dump(plays, out_f, sort_keys=False, allow_unicode=True)
            logging.info(f"Playbook saved successfully: {output_file}")
        except Exception as e:
            logging.error(f"Error writing {output_file}: {e}")
    else:
        logging.warning("No valid plays generated.")
    logging.info(f"Converted documents: {len(plays)}")

def main():
    """
    Parse command-line arguments and execute the conversion.
    """
    parser = argparse.ArgumentParser(
        description="Convert Scapolite YAML files (using YAML metadata) to a combined Ansible playbook."
    )
    parser.add_argument('-i', '--input', required=True,
                        help="Directory containing Scapolite YAML files (e.g., 'rules/').")
    parser.add_argument('-o', '--output', required=True,
                        help="Output file for the Ansible playbook (e.g., 'generated/automated_hardening.yml').")
    args = parser.parse_args()
    convert_directory(args.input, args.output)

if __name__ == '__main__':
    main()
