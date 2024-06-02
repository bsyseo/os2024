import re

def remove_ssl_functions_and_save(http_c_file, new_http_c_file):
    # 정규 표현식 패턴으로 SSL 관련 함수들을 찾습니다.
    ssl_function_pattern = r"\b(?:ssl|SSL)_\w+\s*\([^;{}]*\)\s*{[^{}]*}"
    
    with open(http_c_file, 'r') as f:
        content = f.read()

    # SSL 관련 함수들을 삭제합니다.
    content = re.sub(ssl_function_pattern, '', content)

    # 수정된 내용을 새 파일에 씁니다.
    with open(new_http_c_file, 'w') as f:
        f.write(content)

# 기존 http.c 파일의 경로와 새 파일의 경로를 입력하세요.
http_c_file_path = "http.c"
new_http_c_file_path = "http_no_ssl.c"

remove_ssl_functions_and_save(http_c_file_path, new_http_c_file_path)
print("SSL 관련 함수가 삭제되고 수정된 내용이 새 파일에 저장되었습니다.")
