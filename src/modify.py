import re
import os

def remove_ssl_related_code(init_c_path):
    try:
        with open(init_c_path, 'r') as file:
            init_c_content = file.read()

        # HTTPS, OpenSSL, FTP, SSL/TLS와 관련된 부분 제거
        patterns = [
            r'#ifdef HAVE_SSL.*?#endif',  # #ifdef HAVE_SSL ... #endif 블록 제거
            r'#ifdef HAVE_SSL',  # #ifdef HAVE_SSL 단독 제거
            r'#endif\s*// HAVE_SSL',  # #endif // HAVE_SSL 제거
            r'#define HAVE_SSL.*',  # #define HAVE_SSL ... 제거
            r'\bSSL_.*?\b',  # SSL 관련 함수, 매크로, 상수 제거
            r'\bhttps?_.*?\b',  # HTTP/HTTPS 관련 함수, 매크로, 상수 제거
            r'\bftp_.*?\b',  # FTP 관련 함수, 매크로, 상수 제거
            r'\bssl_.*?\b',  # ssl 접두사가 있는 함수, 매크로, 상수 제거
        ]

        for pattern in patterns:
            init_c_content = re.sub(pattern, '', init_c_content, flags=re.DOTALL)

        # 새로운 파일로 저장
        new_init_c_path = os.path.splitext(init_c_path)[0] + "_lightweight.c"
        with open(new_init_c_path, 'w') as file:
            file.write(init_c_content)

        print("HTTPS, OpenSSL, FTP, SSL/TLS와 관련된 부분을 제거하여 새 파일에 저장했습니다.")
    except Exception as e:
        print("오류 발생:", e)

if __name__ == "__main__":
    init_c_path = "init.c"  # init.c 파일의 경로
    remove_ssl_related_code(init_c_path)
