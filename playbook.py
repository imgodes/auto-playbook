import os
import re
from dotenv import load_dotenv
from datetime import datetime
from mitreattack.stix20 import MitreAttackData
import logging
import argparse

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Carrega variáveis de ambiente
load_dotenv()

def setup_arg_parser():
    """Configura o parser de argumentos de linha de comando"""
    parser = argparse.ArgumentParser(description='Generate MITRE ATT&CK playbooks')
    parser.add_argument('--technique', help='Generate playbook for a specific technique ID')
    parser.add_argument('--techniques', nargs='+', help='Generate playbooks for multiple techniques')
    parser.add_argument('--output', default='playbooks', help='Output directory for playbooks')
    parser.add_argument('--force', action='store_true', help='Overwrite existing playbooks')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
    return parser

def sanitize_filename(name):
    """Remove caracteres inválidos e substitui espaços por underscores"""
    name = name.replace(' ', '_')
    return re.sub(r'[\\/*?:"<>|]', "", name)

def convert_markdown_links(text):
    """Converte links Markdown [texto](URL) para HTML"""
    if not text:
        return text
    
    pattern = r'\[([^\]]+)\]\(([^)]+)\)'
    
    def replace_match(match):
        text = match.group(1)
        url = match.group(2)
        if url.startswith('/'):
            url = f'https://attack.mitre.org{url}'
        return f'[{text}]({url})'
    
    return re.sub(pattern, replace_match, text)

def get_technique_details(attack_data, technique_id):
    """Obtém detalhes completos de uma técnica do MITRE ATT&CK"""
    try:
        technique = attack_data.get_object_by_attack_id(technique_id, "attack-pattern")
        
        if not technique:
            raise ValueError(f"Technique {technique_id} not found")
        
        # Get tactics from kill chain phases
        tactic_phases = []
        if hasattr(technique, 'kill_chain_phases'):
            for phase in technique.kill_chain_phases:
                if phase.kill_chain_name == 'mitre-attack':
                    tactic_phases.append(phase.phase_name)
        
        # Get related mitigations
        mitigations = attack_data.get_mitigations_mitigating_technique(technique.id)
        mitigation_details = []
        
        for mitigation in mitigations:
            mitigation_obj = mitigation["object"] if isinstance(mitigation, dict) and "object" in mitigation else mitigation
            
            if hasattr(mitigation_obj, "external_references"):
                mitigation_refs = mitigation_obj.external_references
                mitigation_attack_id = None
                
                for ref in mitigation_refs:
                    if hasattr(ref, "source_name") and ref.source_name == "mitre-attack":
                        mitigation_attack_id = getattr(ref, "external_id", None)
                        break
                
                if mitigation_attack_id:
                    mitigation_details.append({
                        'id': mitigation_attack_id,
                        'name': getattr(mitigation_obj, "name", "Unknown"),
                        'description': convert_markdown_links(
                            getattr(mitigation_obj, "description", "No description available")
                        ),
                        'url': f"https://attack.mitre.org/mitigations/{mitigation_attack_id}"
                    })
        
        # Get sub-techniques
        subtechniques = attack_data.get_subtechniques_of_technique(technique.id)
        subtechnique_ids = []
        
        for sub in subtechniques:
            sub_obj = sub["object"] if isinstance(sub, dict) and "object" in sub else sub
            if hasattr(sub_obj, "external_references"):
                sub_refs = sub_obj.external_references
                sub_attack_id = next(
                    (ref.external_id for ref in sub_refs 
                     if hasattr(ref, "source_name") and ref.source_name == "mitre-attack"),
                    None
                )
                if sub_attack_id:
                    subtechnique_ids.append(sub_attack_id)
        
        # Get technique URL
        technique_url = next(
            (ref.url for ref in technique.external_references 
             if hasattr(ref, "source_name") and ref.source_name == "mitre-attack"),
            f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}"
        )
        
        # Build details dictionary
        technique_details = {
            'id': technique_id,
            'name': technique.name,
            'description': convert_markdown_links(
                getattr(technique, "description", "No description available")
            ),
            'url': technique_url,
            'data_sources': getattr(technique, 'x_mitre_data_sources', []),
            'tactics': tactic_phases,
            'subtechniques': subtechnique_ids,
            'mitigations': mitigation_details,
            'platforms': getattr(technique, 'x_mitre_platforms', []),
            'detection': convert_markdown_links(
                getattr(technique, 'x_mitre_detection', "No detection information available")
            ),
            'references': [
                {
                    'source': ref.source_name,
                    'url': ref.url,
                    'description': convert_markdown_links(
                        getattr(ref, "description", "")
                    )
                }
                for ref in getattr(technique, "external_references", [])
                if hasattr(ref, "source_name") 
                and ref.source_name != 'mitre-attack' 
                and hasattr(ref, 'url') 
                and ref.url
            ]
        }
        
        return technique_details
    
    except Exception as e:
        logger.error(f"Error getting details for technique {technique_id}: {str(e)}")
        raise

def create_markdown_content(technique_details):
    """Cria o conteúdo do playbook em formato Markdown com seções expansíveis"""
    try:
        # Format lists
        subtechs = ', '.join(technique_details['subtechniques']) if technique_details['subtechniques'] else 'None'
        tactics = ', '.join(technique_details['tactics']) if technique_details['tactics'] else 'N/A'
        
        # Front matter
        front_matter = f"""---
title: Playbook for {technique_details['id']} - {technique_details['name']}
id: playbook_{technique_details['id']}
date: {datetime.now().strftime('%Y-%m-%d')}
---
"""
        # Main content
        content = f"""# {technique_details['id']} - {technique_details['name']}

**Platforms:** {', '.join(technique_details['platforms']) or 'N/A'}  
**Created:** {datetime.now().strftime('%Y-%m-%d')}

## Description
{technique_details['description']}

[View on MITRE ATT&CK]({technique_details['url']})

## Details

| Category          | Details                  |
|-------------------|--------------------------|
| Related Tactics   | {tactics}                |
| Data Sources      | {', '.join(technique_details['data_sources'])} |
| Sub-techniques    | {subtechs}               |

## Recommended Mitigations
"""

        # Add mitigations sections with <details>
        for mitigation in technique_details['mitigations']:
            description_lines = mitigation['description'].split('\n')
            formatted_content = ""
            
            current_header = ""
            current_items = []
            
            for line in description_lines:
                stripped = line.strip()
                if not stripped:
                    continue
                    
                if stripped.startswith('-'):
                    # Item de lista
                    clean_line = stripped[1:].strip()
                    current_items.append(clean_line)
                else:
                    # Novo cabeçalho - processa o anterior primeiro
                    if current_header:
                        formatted_content += f"\n**{current_header}**\n"
                        for item in current_items:
                            formatted_content += f"- {item}\n"
                        current_items = []
                    
                    current_header = stripped
                    if not current_header.endswith((':', '.', ';')):
                        current_header += ':'
            
            # Processa o último cabeçalho
            if current_header:
                formatted_content += f"\n**{current_header}**\n"
                for item in current_items:
                    formatted_content += f"- {item}\n"
            
            content += f"""
### {mitigation['id']} - {mitigation['name']}

<details>
<summary>{mitigation['name']}</summary>

{formatted_content}

[View mitigation on MITRE ATT&CK]({mitigation['url']})
</details>
"""

        # Add remaining sections
        content += f"""
## Detection
{technique_details['detection']}

## Response Procedures
Customize these procedures for your organization:

1. **Detection**: 
   - Add your detection methods here
   
2. **Containment**:
   - Outline containment steps

3. **Eradication**:
   - Specify eradication actions

4. **Recovery**:
   - Document recovery procedures

## References
"""

        for ref in technique_details['references']:
            content += f"""
- [{ref['source']}]({ref['url']}){f" - {ref['description']}" if ref.get('description') else ''}
"""

        return front_matter + content
    
    except Exception as e:
        logger.error(f"Error creating markdown content: {str(e)}")
        raise

def save_playbook(attack_data, output_dir, technique_id, content, force=False):
    """Salva o playbook como arquivo .md"""
    try:
        os.makedirs(output_dir, exist_ok=True)
        
        # Get technique name for filename
        technique = attack_data.get_object_by_attack_id(technique_id, "attack-pattern")
        safe_name = sanitize_filename(technique.name)
        filename = f"playbook_{technique_id}_{safe_name}.md"
        filepath = os.path.join(output_dir, filename)
        
        if os.path.exists(filepath) and not force:
            logger.warning(f"Playbook {filepath} already exists. Use --force to overwrite.")
            return None
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        
        logger.info(f"Playbook saved to: {filepath}")
        return filepath
    
    except Exception as e:
        logger.error(f"Error saving playbook: {str(e)}")
        raise

def generate_playbook(attack_data, technique_id, output_dir, force=False):
    """Gera um playbook para uma técnica específica"""
    try:
        logger.info(f"Processing technique {technique_id}...")
        technique_details = get_technique_details(attack_data, technique_id)
        content = create_markdown_content(technique_details)
        return save_playbook(attack_data, output_dir, technique_id, content, force)
    except Exception as e:
        logger.error(f"Error processing technique {technique_id}: {str(e)}")
        return None

def main():
    """Função principal"""
    try:
        # Parse command line arguments
        parser = setup_arg_parser()
        args = parser.parse_args()
        
        if args.verbose:
            logger.setLevel(logging.DEBUG)
        
        # Initialize MITRE ATT&CK data
        attack_data = MitreAttackData("enterprise-attack.json")
        
        # Determine techniques to process
        techniques = []
        if args.technique:
            techniques.append(args.technique)
        elif args.techniques:
            techniques = args.techniques
        else:
            # Default techniques if none specified
            techniques = [
                "T1059",  # Command-Line Interface
                "T1078",  # Valid Accounts
                "T1195"   # Supply Chain Compromise
            ]
        
        logger.info(f"Generating {len(techniques)} playbooks in {args.output}")
        
        # Generate playbooks
        for technique_id in techniques:
            generate_playbook(
                attack_data=attack_data,
                technique_id=technique_id,
                output_dir=args.output,
                force=args.force
            )
        
        logger.info(f"Playbook generation complete. Files saved to: {args.output}")
    
    except Exception as e:
        logger.error(f"Error in main execution: {str(e)}")
        return 1

if __name__ == "__main__":
    main()