# anonymizer_service
Reversible Anonymization Tool

### Download spaCy models defined in the config
python -m spacy download en_core_web_lg
python -m spacy download fr_core_news_lg
python -m spacy download zh_core_web_lg

## Anonymize Example:
   
### On Windows
.\anonymizer_service.exe anonymize --input content.txt --output anonymized.txt --config config.yaml --map mapping.json

### On macOS/Linux
./anonymizer_service anonymize --input content.txt --output anonymized.txt --config config.yaml --map mapping.json

    
## Deanonymize Example:
     
### On Windows
.\anonymizer_service.exe deanonymize --input anonymized.txt --output restored.txt --config config.yaml --map mapping.json

### On macOS/Linux
./anonymizer_service deanonymize --input anonymized.txt --output restored.txt --config config.yaml --map mapping.json

