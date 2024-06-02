import re

def remove_proxy_code(input_file, output_file):
    with open(input_file, 'r', encoding='utf-8') as file:
        code = file.read()

    # Define a regex pattern to match proxy-related code blocks
    # This is a simplistic approach; you may need to adjust the patterns based on actual code structure
    proxy_patterns = [
        re.compile(r'#ifdef USE_PROXY.*?#endif', re.DOTALL),  # For C preprocessor conditional compilation
        re.compile(r'proxy_[^\s]+\s*=\s*.*?;', re.DOTALL),    # Proxy variable assignments
        re.compile(r'PROXY_.*', re.DOTALL)                    # Proxy related defines and macros
    ]

    # Remove the matched proxy-related code blocks
    for pattern in proxy_patterns:
        code = re.sub(pattern, '', code)

    with open(output_file, 'w', encoding='utf-8') as file:
        file.write(code)

    print(f"Proxy-related code removed and saved to {output_file}")

# Example usage:
input_file = 'init.c'
output_file = 'init_no_proxy.c'
remove_proxy_code(input_file, output_file)
