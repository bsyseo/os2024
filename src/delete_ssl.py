import re
import os

# 소스 파일 목록 - http.c만 포함
source_files = [
    'http.c'
]

def comment_ssl_code(filename):
    new_filename = filename.replace(".c", "_modified.c")  # 수정된 파일 이름
    try:
        with open(filename, 'r') as file:
            content = file.readlines()
        
        new_content = []
        inside_ssl_block = False
        
        for line in content:
            # SSL 관련 코드 블록 시작 확인
            if re.search(r'#ifdef.*SSL', line):
                inside_ssl_block = True
            # SSL 관련 코드 블록 종료 확인
            if re.search(r'#endif', line) and inside_ssl_block:
                inside_ssl_block = False
                new_content.append("//" + line)  # 이 라인도 주석 처리
                continue
            
            # SSL 블록 내부라면 모든 라인을 주석 처리
            if inside_ssl_block:
                new_content.append("//" + line)
            else:
                new_content.append(line)
        
        # 수정 내용을 새 파일에 쓰기
        with open(new_filename, 'w') as new_file:
            new_file.writelines(new_content)

        return new_filename
    except IOError as e:
        print(f"Error processing the file {filename}: {e}")
        return None

# 파일 처리
for source_file in source_files:
    modified_file = comment_ssl_code(source_file)
    if modified_file:
        print(f"Created modified file: {modified_file}")