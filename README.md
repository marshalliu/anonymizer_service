# anonymizer_service
Reversible Anonymization Tool

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

