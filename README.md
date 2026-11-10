# 도란도란 동물의숲

모여봐요 동물의 숲 카탈로그·박물관·주민·꿈번지·할 일·섬 꾸미기를 한곳에서 체크하는 사이트예요.

## 가지(branch)

- `main`: 카카오톡 미리보기용 대문. 열면 지금 사이트(claude.ai artifact)로 넘어가요. GitHub Pages가 이 가지를 보여 줘요.
- `cf-pages`: 사이트 전체. Cloudflare Pages가 이 가지를 배포해요. 로그인·거래·쪽지·알림은 이 가지에 차례로 붙여요.

## cf-pages 가지 파일

- index.html: 사이트 본체 (artifact와 같은 코드, 미리보기 정보 포함)
- details.js, isl-data.js: 아이템 자세한 정보, 섬 꾸미기 자료
- img/: 게임 그림 묶음 (webp)
- ocr/: 사진에서 글자 읽기 (tesseract.js, 한국어 자료)
- _headers: Cloudflare Pages 캐시 설정
- functions/api/[[route]].js: 서버 (가입·로그인·프로필·기록 맞추기·관리자 임시 비밀번호). D1 데이터베이스를 DB라는 이름으로 연결해야 켜져요. 표는 처음 요청 때 스스로 만들어요.
- og.jpg, icon.svg, icon-180.png: 미리보기 그림과 아이콘

## Cloudflare Pages 설정값

- 프로젝트 이름: doran-nook (주소 https://doran-nook.pages.dev/)
- 운영 가지(Production branch): cf-pages
- 프레임워크: 없음, 빌드 명령: 비움, 출력 폴더: /
- 바인딩: D1 데이터베이스, 변수 이름 DB

## 로그인

- 아이디(2~16자, 한글·영문 소문자·숫자·_)와 비밀번호(8자 이상). 이메일·전화번호는 받지 않아요.
- 비밀번호는 PBKDF2-SHA256(10만 번)으로 바꿔 저장, 5번 틀리면 10분 잠김.
- 처음 가입한 계정이 관리자. 관리자는 친구 계정에 임시 비밀번호를 만들어 줄 수 있어요.
- 보기와 체크는 로그인 없이 그대로. 로그인하면 체크 기록(백업 코드와 같은 내용)이 기기끼리 맞춰져요.

출처와 저작권: 팬이 만든 비공식 도구예요. 아이템 이름과 이미지의 저작권은 Nintendo에 있어요.
