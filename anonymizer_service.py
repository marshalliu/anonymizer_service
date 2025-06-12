import yaml
import argparse
import logging
import os
from typing import List, Dict, Any
from sys import exit

from presidio_analyzer import Pattern, PatternRecognizer
from langchain_experimental.data_anonymizer import PresidioReversibleAnonymizer
from langdetect import detect, LangDetectException

# Configure logging to show info-level messages
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class AnonymizerService:
    """
    A service to handle multi-language PII and custom sensitive content anonymization.
    This service uses a stateful PresidioReversibleAnonymizer instance with persistent mapping.
    """
    def __init__(self, config_path: str, mapping_file: str = None):
        """
        Initializes the AnonymizerService with a configuration file.
        
        :param config_path: Path to the YAML configuration file.
        :param mapping_file: Path to the mapping file for persistence.
        """
        self.config = self._load_config(config_path)
        self.mapping_file = mapping_file
        
        # Build the language configuration for PresidioReversibleAnonymizer
        languages_config = {
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": lang, "model_name": self._get_spacy_model_name(lang)} for lang in self.config['languages']]
        }
        
        # We get the list of entities to look for just once.
        self.entities_to_anonymize = self._get_all_entities_from_config()
        
        # Initialize the PresidioReversibleAnonymizer with proper configuration
        self.reversible_anonymizer = PresidioReversibleAnonymizer(
            analyzed_fields=self.entities_to_anonymize,
            languages_config=languages_config
        )
        
        # Add custom recognizers if they exist
        if 'custom_entities' in self.config:
            logging.info(f"Adding {len(self.config['custom_entities'])} custom recognizers.")
            for entity_spec in self.config['custom_entities']:
                recognizer = PatternRecognizer(
                    supported_entity=entity_spec['name'],
                    patterns=[Pattern(name=entity_spec['name'], regex=entity_spec['regex'], score=entity_spec['score'])],
                    supported_language='zh'
                )
                self.reversible_anonymizer.add_recognizer(recognizer)

    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Loads the YAML configuration file with error handling."""
        try:
            with open(config_path, 'r', encoding='utf-8') as file:
                config = yaml.safe_load(file)
                logger.info(f"Configuration loaded from {config_path}")
                return config
        except FileNotFoundError:
            logger.error(f"Configuration file not found: {config_path}")
            raise
        except yaml.YAMLError as e:
            logger.error(f"Error parsing YAML configuration: {e}")
            raise

    def _get_all_entities_from_config(self) -> List[str]:
        """
        Extracts all entity names from the configuration.
        
        :return: List of all entity names to anonymize.
        """
        entities = self.config.get('pii_entities', []).copy()
        
        # Add custom entity names if they exist
        if 'custom_entities' in self.config:
            custom_entity_names = [spec['name'] for spec in self.config['custom_entities']]
            entities.extend(custom_entity_names)
        
        return entities

    def _get_spacy_model_name(self, lang_code: str) -> str:
        """Returns the default spaCy model name for a given language code."""
        model_map = {
            'en': 'en_core_web_lg',
            'fr': 'fr_core_news_lg',
            'zh': 'zh_core_web_lg',
        }
        return model_map.get(lang_code, f"{lang_code}_core_news_sm")

    def save_mapping(self, mapping_file: str = None):
        """
        Saves the current anonymization mapping to a file.
        
        :param mapping_file: Path to save the mapping. If None, uses self.mapping_file.
        """
        if mapping_file is None:
            mapping_file = self.mapping_file
        
        if mapping_file:
            try:
                # Use the built-in method to save the mapping
                self.reversible_anonymizer.save_deanonymizer_mapping(mapping_file)
                logger.info(f"Mapping saved to {mapping_file}")
            except Exception as e:
                logger.error(f"Failed to save mapping to {mapping_file}: {e}")
        else:
            logger.warning("No mapping file specified")

    def load_mapping(self, mapping_file: str = None):
        """
        Loads an existing anonymization mapping from a file.
        
        :param mapping_file: Path to load the mapping from. If None, uses self.mapping_file.
        """
        if mapping_file is None:
            mapping_file = self.mapping_file
        
        if mapping_file and os.path.exists(mapping_file):
            try:
                # Use the built-in method to load the mapping
                self.reversible_anonymizer.load_deanonymizer_mapping(mapping_file)
                logger.info(f"Mapping loaded from {mapping_file}")
                return True
            except Exception as e:
                logger.error(f"Failed to load mapping from {mapping_file}: {e}")
                return False
        else:
            logger.info(f"Mapping file {mapping_file} not found, starting with empty mapping")
            return False

    def anonymize_text(self, text: str) -> str:
        """
        Anonymizes a single piece of text. The anonymizer instance stores the mapping.
        
        :param text: The text to anonymize.
        :return: The anonymized text.
        """
        try:
            language = detect(text)
            if len(language) > 2:
                language = language[:2] 
            if language not in self.config['languages']:
                logging.warning(f"Detected language '{language}' is not supported by config. Defaulting to 'en'.")
                language = 'en'
        except LangDetectException:
            logging.warning(f"Could not detect language for text: '{text[:50]}...'. Defaulting to 'en'.")
            language = 'en'

        # Use the correct API: anonymize(text, language=language)
        return self.reversible_anonymizer.anonymize(text, language=language)

    def deanonymize_text(self, anonymized_text: str) -> str:
        """
        Reverses the anonymization using the internal map stored in the anonymizer instance.
        
        :param anonymized_text: The text that was previously anonymized.
        :return: The original, deanonymized text.
        """
        # Call deanonymize without any extra arguments
        # The object already knows the mapping from the previous anonymize calls.
        return self.reversible_anonymizer.deanonymize(anonymized_text)

def load_content_lines(content_file: str) -> List[str]:
    """Loads content from a text file, returning a list of lines."""
    try:
        with open(content_file, 'r', encoding='utf-8') as file:
            lines = file.readlines()
            logger.info(f"Loaded {len(lines)} lines from {content_file}")
            return lines
    except FileNotFoundError:
        logger.error(f"Content file not found: {content_file}")
        raise
    except UnicodeDecodeError as e:
        logger.error(f"Error reading file {content_file}: {e}")
        raise

def save_results(result_lines: List[str], output_file: str):
    """Saves the processed content to a file."""
    with open(output_file, 'w', encoding='utf-8') as file:
        for line in result_lines:
            file.write(f"{line.rstrip()}\n")
    logging.info(f"Results saved to {output_file}")

def anonymize_mode(service: AnonymizerService, input_file: str, output_file: str, map_file: str):
    """
    Handles the anonymization process.
    
    :param service: AnonymizerService instance
    :param input_file: Path to input file
    :param output_file: Path to output file
    :param map_file: Path to mapping file
    """
    logger.info("Starting anonymization process...")
    
    # Load existing mapping if available
    service.load_mapping(map_file)
    
    # Load and process content
    original_lines = load_content_lines(input_file)
    anonymized_lines = []
    
    for i, line in enumerate(original_lines, 1):
        if line.strip():  # Only process non-empty lines
            anonymized = service.anonymize_text(line.strip())
            anonymized_lines.append(anonymized)
            logger.debug(f"Processed line {i}/{len(original_lines)}")
        else:
            anonymized_lines.append(line.strip())
    
    # Save results and mapping
    save_results(anonymized_lines, output_file)
    service.save_mapping(map_file)
    
    logger.info(f"Anonymization completed. {len(anonymized_lines)} lines processed.")
    logger.info(f"Anonymized content saved to: {output_file}")
    logger.info(f"Mapping saved to: {map_file}")

def deanonymize_mode(service: AnonymizerService, input_file: str, output_file: str, map_file: str):
    """
    Handles the deanonymization process.
    
    :param service: AnonymizerService instance
    :param input_file: Path to input file (anonymized content)
    :param output_file: Path to output file (restored content)
    :param map_file: Path to mapping file
    """
    logger.info("Starting deanonymization process...")
    
    # Load mapping - this is required for deanonymization
    if not service.load_mapping(map_file):
        logger.error(f"Cannot deanonymize without mapping file: {map_file}")
        raise FileNotFoundError(f"Mapping file {map_file} is required for deanonymization")
    
    # Load and process anonymized content
    anonymized_lines = load_content_lines(input_file)
    deanonymized_lines = []
    
    for i, line in enumerate(anonymized_lines, 1):
        if line.strip():  # Only process non-empty lines
            try:
                deanonymized = service.deanonymize_text(line.strip())
                deanonymized_lines.append(deanonymized)
                logger.debug(f"Processed line {i}/{len(anonymized_lines)}")
            except Exception as e:
                logger.warning(f"Failed to deanonymize line {i}: {e}")
                # Keep the original line if deanonymization fails
                deanonymized_lines.append(line.strip())
        else:
            deanonymized_lines.append(line.strip())
    
    # Save results
    save_results(deanonymized_lines, output_file)
    
    logger.info(f"Deanonymization completed. {len(deanonymized_lines)} lines processed.")
    logger.info(f"Restored content saved to: {output_file}")

def main():
    """Main function with separated anonymize and deanonymize modes."""
    parser = argparse.ArgumentParser(
        description="""
Reversible Anonymization Tool
============================

This tool provides reversible anonymization of text files with support for:
- Multiple languages (English, French, Chinese)
- Built-in PII detection (names, emails, phone numbers, etc.)
- Custom corporate-sensitive content patterns
- Full reversibility through persistent mapping files
- Confidence threshold filtering
- Automatic language detection

Examples:
---------
Anonymize a file:
    python anonymizer_service.py anonymize --input content.txt --output anonymized.txt --config config.yaml --map mapping.json

Deanonymize a file:
    python anonymizer_service.py deanonymize --input anonymized.txt --output restored.txt --config config.yaml --map mapping.json

Configuration file example (config.yaml):
-----------------------------------------
languages: ["en", "fr", "zh"]
pii_entities:
  - PERSON
  - EMAIL_ADDRESS
  - PHONE_NUMBER
  - ORGANIZATION
custom_entities:
  - name: "EMPLOYEE_ID"
    regex: "EMP-\\d{6}"
    score: 0.8

Required spaCy models:
---------------------
Install models for your target languages:
    python -m spacy download en_core_web_lg
    python -m spacy download fr_core_news_lg
    python -m spacy download zh_core_web_lg
        """,
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument("mode", choices=['anonymize', 'deanonymize'],
                       help="Mode: 'anonymize' to anonymize text, 'deanonymize' to restore original text")
    parser.add_argument("--config", default="config.yaml",
                       help="Path to YAML configuration file (default: config.yaml)")
    parser.add_argument("--input", required=True,
                       help="Path to input text file")
    parser.add_argument("--output", required=True,
                       help="Path to output file")
    parser.add_argument("--map", default="mapping.json",
                       help="Path to mapping file for reversible anonymization (default: mapping.json)")
    parser.add_argument("--verbose", "-v", action="store_true",
                       help="Enable verbose logging")
    
    args = parser.parse_args()
    
    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        # Initialize service
        try:
            service = AnonymizerService(args.config, args.map)
        except Exception as e:
            logger.error(f"Failed to initialize AnonymizerService: {e}")
            logger.error("Please ensure all required spaCy models are installed.")
            return 1

        # Execute the appropriate mode
        if args.mode == 'anonymize':
            anonymize_mode(service, args.input, args.output, args.map)
        elif args.mode == 'deanonymize':
            deanonymize_mode(service, args.input, args.output, args.map)

        logger.info("Operation completed successfully!")

    except KeyboardInterrupt:
        logger.info("Operation cancelled by user")
        return 1
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())