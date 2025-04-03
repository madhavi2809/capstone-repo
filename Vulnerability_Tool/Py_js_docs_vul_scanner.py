import os
import re
import docx

# Define text colors
class Colour:
    GREEN = '\033[92m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    YELLOW = '\033[93m'
    V_PATTERN_NAME = '\033[38;5;208m'  # Orange names
    NORMAL = '\033[0m'

# Define Vulnerability Patterns for JS files
JS_Patterns = {
    "Sql_Injection": re.compile(r'\.query\s*\(.*\+.*\)'),
    "XSS": re.compile(r'res\.send\s*\(.*\+.*\)'),
    "Command_Injection": re.compile(r'exec\s*\(.*\+.*\)'),
    "insecure_file_handling": re.compile(r'fs\.unlink\s*\(.*\)'),
    "insecure_file_upload": re.compile(r'multer\s*\(\s*{.*dest.*}\s*\)'),
    "Eval_Function": re.compile(r'eval\s*\(.*\)'),
    "Directory_Movement": re.compile(r'fs\.readFile\s*\(.*\.\./.*\)'),
    "Insecure_Token_Generation": re.compile(r'Math\.random\s*\(\)'),
    "Dangerous_Permission_Level": re.compile(r'fs\.chmod\s*\(.*\)'),
    "Redirects": re.compile(r'res\.redirect\s*\(.*req\.query\..*\)'),
    "API_Key_Hardcoded": re.compile(r'api_key\s*=\s*[\'"].*[\'\"]'),
    "Weak_Hashing_Algorithm": re.compile(r'(md5|sha1|des)\s*\('),
    "Planetext_Credentials": re.compile(r'(username|password)\s*=\s*[\'"].*[\'\"]'),
    "Insecure_SSL_Configeration": re.compile(r'server\.listen\s*\(.*http.*\)'),
    "HTTP_Called": re.compile(r'http\.get\s*\(.*\)'),
    "Sensitive_Data_Logging": re.compile(r'console\.(log|debug|error|warn)\s*\(.*(password|secret|key|token).*\)'),
    "JSON_Parsing_No_Validation": re.compile(r'JSON\.parse\s*\(.*req\.(body|query|params).*\)'),
    "Environment_Variables_In_Planetext": re.compile(r'process\.env\.[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*[\'"].+[\'\"]'),
    "Debug_Left_Exposed": re.compile(r'app\.get\s*\([\'"].*debug.*[\'"],.*\)'),
    "Insecure_File_Paths": re.compile(r'(fs\.(readFile|writeFile))\s*\(.*req\.(body|query|params)\.path.*\)'),
    "Unsecured_Spawn": re.compile(r'spawn\s*\(.*\)')
}

# Python-specific patterns
Python_Patterns = {
    "Eval_Function": re.compile(r'eval\s*\(.*\)'),
    "Exec_Function": re.compile(r'exec\s*\(.*\)'),
    "OS_Command_Injection": re.compile(r'os\.(system|popen)\s*\(.*\)'),
    "Subprocess_Injection": re.compile(r'subprocess\.(Popen|call|run)\s*\(.*\)'),
    "Pickle_Load": re.compile(r'pickle\.load\s*\(.*\)'),
    "Hardcoded_Credentials": re.compile(r'(username|password)\s*=\s*[\'"].*[\'\"]'),
    "Weak_Hashing_Algorithm": re.compile(r'(md5|sha1|des)\s*\('),
    "Insecure_Random": re.compile(r'random\.randint\s*\(.*\)'),
    "Unverified_SSL": re.compile(r'requests\.get\s*\(.*verify\s*=\s*False\)'),
    "Dangerous_File_Access": re.compile(r'open\s*\(.*\)'),
    "Environment_Variables_Exposure": re.compile(r'os\.environ\[\s*[\'"].+[\'\"]\s*\]'),
    "Debug_Logging": re.compile(r'print\s*\(.*(password|secret|key|token).*[\)]'),
    "Deserialization_Risk": re.compile(r'json\.loads\s*\(.*\)'),
    "Unsecured_Spawn": re.compile(r'os\.spawn\s*\(.*\)')
}
# Define Vulnerability Patterns for Word files
Word_Patterns = {
    "Hardcoded_Credentials": re.compile(r'(username|password)\s*=\s*[\'"].*[\'"]'),
    "Sensitive_Keywords": re.compile(r'(confidential|private|classified|top secret)', re.IGNORECASE),
    "Email_Addresses": re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'),
    "Phone_Numbers": re.compile(r'\b(?:\+\d{1,3})?[-.\s]?(\d{2,4})?[-.\s]?\d{3}[-.\s]?\d{4}\b'),
    "URLs": re.compile(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
}

# Opening the files for processing
def AnalyseFile(FileLocation, patterns):
    vulnerabilities = {key: [] for key in patterns.keys()}    
    try:
        with open(FileLocation, 'r', encoding='utf-8') as file:
            Data = file.read()
    except Exception as e:
        print(f"Error reading file {FileLocation}: {e}")
        return None

    # Check for vulnerabilities based on pre-set patterns
    for key, pattern in patterns.items():
        matches = pattern.findall(Data)
        if matches:
            vulnerabilities[key].extend(matches)
    
    return vulnerabilities

# Function to analyze a Word file for vulnerabilities
def AnalyseWordFile(FileLocation):
    vulnerabilities = {key: [] for key in Word_Patterns.keys()}
    try:
        doc = docx.Document(FileLocation)
        text_data = "\n".join([para.text for para in doc.paragraphs])
    except Exception as e:
        print(f"Error reading file {FileLocation}: {e}")
        return None
    
    for key, pattern in Word_Patterns.items():
        matches = pattern.findall(text_data)
        if matches:
            vulnerabilities[key].extend(matches)
    
    return vulnerabilities

# Formatting files for list
def list_files():
    return [f for f in os.listdir('.') if os.path.isfile(f) and (f.endswith('.js') or f.endswith('.py') or f.endswith('.docx'))]

# Function to display available Word files for analysis
def OrderedF(Dataset):
    print("|-------------------------------------|")
    print("|  JS, PY & Word files for Analysis:  |")
    print("|-------------------------------------|")
    for i, file in enumerate(Dataset, 1):
        print(f"{i} - {file}")

# Function to print the analysis outcome
def PrintOutcome(Data):
    Outside = max(len(line) for line in Data.splitlines()) + 4
    print('|' + '-' * (Outside - 2) + '|')
    for line in Data.splitlines():
        print(f"| {line.ljust(Outside - 4)} |")
    print('|' + '-' * (Outside - 2) + '|')

# Main function to scan Word files
def main():
    Dataset = list_files()
    if not Dataset:
        print("No .js, .py or .docx files found")
        return
    
    while True:
        OrderedF(Dataset)
        User_Input = input("\nPlease enter a file number from the listed options\nor\nType 'end' to quit the application \n> ")
        if User_Input.lower() == 'end':
            break
        
        try:
            file_index = int(User_Input) - 1
            if file_index < 0 or file_index >= len(Dataset):
                print(f"\n{Colour.BLUE}|---------------|\n| Invalid input |\n|---------------|{Colour.NORMAL}\nPlease enter the file number from the listed options")
                continue
            
            SelectedFile = Dataset[file_index]
            # WordFile = Dataset[file_index]
            print(f"{Colour.YELLOW}\nAnalysing: {Colour.NORMAL}{SelectedFile}")

            # Determine which patterns to use
            if SelectedFile.endswith('.js'):
                patterns = JS_Patterns
                vulnerabilities = AnalyseFile(SelectedFile, patterns)
            elif SelectedFile.endswith('.py'):
                patterns = Python_Patterns
                vulnerabilities = AnalyseFile(SelectedFile, patterns)
            else :
                vulnerabilities = AnalyseWordFile(SelectedFile)
            
            if not vulnerabilities:
                Outcome = f"Could not read file: {SelectedFile}"
            elif not any(vulnerabilities.values()):
                Outcome = f"{Colour.GREEN}No vulnerabilities found.{Colour.NORMAL}"
            else:
                Outcome = f"{Colour.RED}Potential Vulnerability Found:  {Colour.NORMAL}\n"
                for key, found in vulnerabilities.items():
                    if found:
                        Outcome += f"{Colour.V_PATTERN_NAME} {key.replace('_', ' ').title()} vulnerabilities:{Colour.NORMAL}\n"
                        for q in found:
                            Outcome += f"    - {q}\n"
            
            PrintOutcome(Outcome)
        except ValueError:
            print(f"\n{Colour.BLUE}|---------------|\n| Invalid input |\n|---------------|{Colour.NORMAL}\nPlease Input a number.")

if __name__ == "__main__":
    main()
