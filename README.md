# Scapolite-to-Ansible Converter

## Überblick

Dieses Projekt basiert auf dem Ansatz der Dissertation _"A Holistic Approach for Security Configuration"_. Ziel ist es, Sicherheitskonfigurationen – insbesondere für Windows – in einem einheitlichen, leicht wartbaren YAML-Format (dem **Scapolite-Format**) zu erfassen und daraus automatisch ausführbare Ansible-Playbooks zu generieren.

Der Aufbau umfasst:

- **Maschinenlesbare Regeln:** In einzelnen Scapolite-Dateien werden alle relevanten Informationen wie Metadaten, Beschreibungen und technische Automationsdetails zusammengeführt.
- **Automatische Transformation:** Ein Python-Konverter liest die YAML-Dateien ein, extrahiert die im `automations`-Block hinterlegten technischen Daten (z. B. Registry-Pfad und Werte) und wandelt diese in konkrete Ansible-Aufgaben um.
- **Automatisierter Einsatz:** Über eine CI/CD-Pipeline (GitHub Actions) werden die Regeln automatisch verarbeitet, ein kombiniertes Ansible-Playbook generiert und auf den Zielsystemen (Windows) ausgeführt – gesteuert von einem Linux-Controller.  
  _Hinweis:_ Bei öffentlich erreichbaren Endpunkten sollten winrm-Zertifikate konfiguriert werden.

---

## Wie funktioniert die Automatisierung?

1. **Erfassung im Scapolite-Format:**  
   Jede Regel wird in einer eigenen YAML-Datei definiert. Der obere Teil (zwischen den ersten `---`) enthält maschinenlesbare Daten, während der untere Teil die Regel in natürlicher Sprache beschreibt.

   **Beispiel einer Regel (Datei: `rules/passwortrichtlinie.yml`):**

   ```yaml
   ---
   scapolite:
       class: rule
       version: '0.51'
   id: BL942-1101
   id_namespace: org.scapolite.example
   title: Configure use of passwords for removable data drives
   rule: <see below>
   implementations:
     - relative_id: '01'
       description: <see below>
       automations:
         - system: org.scapolite.implementation.win_gpo
           registry_key: "Software\\Policies\\Microsoft\\FVE"
           values:
             RDVPassphraseComplexity: 1
             RDVPassphraseLength: 15
   history:
     - version: '1.0'
       action: created
       description: Added so as to mitigate risk SR-2018-0144.
   ---
   ## /rule
   Enable the setting 'Configure use of passwords for removable data drives' and set the options as follows:
      * Select `Require password complexity`
      * Set the option 'Minimum password length for removable data drive' to `15`.
   ## /implementations/0/description
   To set the protection level to the desired state, enable the policy
   `Computer Configuration\...\Configure use of passwords for removable data drives`
   and set the options as specified above in the rule.
   ```

2. **Transformation in ein Ansible-Playbook:**  
   Das Python-Skript unter `converter/scapolite2ansible.py` liest die YAML-Dateien ein, extrahiert die technischen Details aus dem `automations`-Block und erstellt daraus Ansible-Tasks zur Konfiguration von Registry-Einstellungen auf Windows-Systemen.

   **Beispiel des Konverters (`converter/scapolite2ansible.py`):**

   ```python
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

       # Suche in der implementations-Sektion nach Automations
       implementations = rule_data.get('implementations', [])
       for impl in implementations:
           automations = impl.get('automations', [])
           if not automations:
               continue
           for automation in automations:
               registry_key = automation.get('registry_key')
               if not registry_key:
                   logging.warning("No 'registry_key' found in automation; skipping this automation.")
                   continue

               values = automation.get('values', {})
               if not values:
                   logging.warning("No 'values' found in automation; skipping this automation.")
                   continue

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
   ```

3. **Transformation und Deployment über CI/CD:**  
   Über GitHub Actions wird folgender Prozess automatisiert:

   - **Repository-Checkout und Caching:** Das Repository wird ausgecheckt und pip-Abhängigkeiten werden zwischengespeichert.
   - **Erstellung der virtuellen Umgebung:** Eine neue Python-Umgebung wird erstellt und die Pakete aus der Datei _requirements.txt_ installiert.
   - **Transformation:** Der Konverter wandelt die Scapolite-YAML-Dateien in ein kombiniertes Ansible-Playbook um.
   - **Deployment:** Das generierte Playbook wird mittels Ansible auf den Zielsystemen (definiert im Inventory) ausgeführt.

   **Beispiel der CI-Pipeline (`.github/workflows/ci.yml`):**

   ```yaml
   name: CI Pipeline

   on:
     push:
       branches: [main]
     pull_request:
       branches: [main]

   jobs:
     build:
       runs-on: self-hosted

       steps:
         - name: Checkout Repository
           uses: actions/checkout@v2

         - name: Cache pip dependencies
           uses: actions/cache@v4
           with:
             path: ~/.cache/pip
             key: ${{ runner.os }}-pip-${{ hashFiles('requirements.txt') }}
             restore-keys: |
               ${{ runner.os }}-pip-

         - name: Create Virtual Environment and Install Dependencies
           run: |
             python3 -m venv venv
             . venv/bin/activate
             pip install --upgrade pip
             pip install -r requirements.txt

         - name: Run Transformation Script
           run: |
             . venv/bin/activate
             python converter/scapolite2ansible.py -i rules/ -o "${{ github.workspace }}/generated/automated_hardening.yml"

         - name: Run Combined Playbook
           run: |
             . venv/bin/activate
             ansible-playbook -i "${{ github.workspace }}/inventory.ini" "${{ github.workspace }}/generated/automated_hardening.yml"
   ```

4. **Ansible Inventory:**  
   Das Inventory definiert die Zielsysteme (Windows).

   **Beispiel eines Inventory (`inventory.ini`):**

   ```ini
   [windows]
   winhost1 ansible_host=HOST_IP ansible_user=USER ansible_password=PASSWORD ansible_connection=winrm ansible_port=5985 ansible_winrm_transport=basic ansible_winrm_server_cert_validation=ignore
   winhost2 ...
   ```

   Ersetze `HOST_IP`, `USER` und `PASSWORD` durch die für deine Umgebung gültigen Werte.

---

## Repository-Struktur

```
scapolite-ansible/
├── .github/workflows/ci.yml         # CI/CD Pipeline-Konfiguration
├── converter/scapolite2ansible.py    # Python-Konverter-Skript
├── rules/passwortrichtlinie.yml      # Beispiel-Regel im Scapolite-Format
├── inventory.ini                     # Ansible Inventory (Beispiel)
├── requirements.txt                  # Abhängigkeiten (z. B. pyyaml, ansible, pywinrm)
└── README.md                         # Dokumentation
```

---

## Voraussetzungen

- **Betriebssystem:** Linux (z. B. Debian 12)
- **Python 3.x** und **pip**

Die in _requirements.txt_ definierten Pakete umfassen:

- [PyYAML](https://pyyaml.org/wiki/PyYAMLDocumentation)
- [Ansible](https://docs.ansible.com/)
- [pywinrm](https://pypi.org/project/pywinrm/)

---

## Installation und Setup

### 1. Repository klonen

Das Projekt von GitHub klonen:

```bash
git clone https://github.com/yungtristxn/Automated-Security-Hardening.git
```

### 2. Repository kopieren und eigenes Repository erstellen

```bash
cp -r /Automated-Security-Hardening /destination/path/
```

**Wichtig:** Für die Nutzung des CI/CD-Runners muss ein eigenes Repository in GitHub erstellt und der kopierte Ordner in das Repository werdenübertragen. Dadurch werden die Dateien gepusht und die CI/CD-Pipeline kann automatisch gestartet werden.

### 3. CI/CD-Setup und Runner-Konfiguration

- **Selbstgehosteter Runner:** Dieses Projekt sieht einen lokal laufenden selbstgehosteten Runner vor. Weitere Informationen dazu: [GitHub Actions-Dokumentation zu selbstgehosteten Runnern](https://docs.github.com/en/actions/hosting-your-own-runners).
- **GitHub-gehosteter Runner:** Alternativ kann auch ein GitHub-gehosteten Runner (z. B. `ubuntu-latest`) verwendet werden. In diesem Fall muss sichergestellt werden, dass die Ziel-Windows-Maschinen (über WinRM) erreichbar sind.

Außerdem muss die (`inventory.ini`) und weitere Konfigurationsdateien an Ihre Umgebung an.

Beim Push in den `main`-Branch oder bei Pull Requests wird die Pipeline in `.github/workflows/ci.yml` automatisch ausgeführt, wodurch:

- Das Repository ausgecheckt wird.
- Eine virtuelle Python-Umgebung erstellt und die Abhängigkeiten installiert werden.
- Der Konverter die Scapolite-YAML-Dateien in ein kombiniertes Ansible-Playbook umwandelt.
- Das Playbook mittels Ansible auf den Zielsystemen ausgeführt wird.

### 4. Manuelle Ausführung

Das Skript kann auch manuell ausgeführt werden, um Änderungen zu testen oder spezielle Szenarien durchzuführen:

```bash
# Virtuelle Umgebung erstellen und aktivieren
python3 -m venv venv
source venv/bin/activate

# Abhängigkeiten installieren
pip install -r requirements.txt

# Konverter ausführen und das Ansible-Playbook generieren
python converter/scapolite2ansible.py -i rules/ -o generated/automated_hardening.yml

# Das generierte Playbook mit Ansible ausführen
ansible-playbook -i inventory.ini generated/automated_hardening.yml
```

---

## Externe Ressourcen

- [GitHub Actions – Selbstgehostete Runner](https://docs.github.com/en/actions/hosting-your-own-runners)
- [Ansible Dokumentation](https://docs.ansible.com/)
- [PyYAML Dokumentation](https://pyyaml.org/wiki/PyYAMLDocumentation)
- [pywinrm auf PyPI](https://pypi.org/project/pywinrm/)
- [Dissertation "A Holistic Approach for Security Configuration" und verwandte Publikationen](https://i4.pages.gitlab.lrz.de/conferences-public/preprints/2022/CODASPY/hardening-with-scapolite.pdf)

---

## Lizenz

Dieses Projekt steht unter der Apache-2.0 Lizenz.
