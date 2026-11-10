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
- og.jpg, icon.svg, icon-180.png: 미리보기 그림과 아이콘

## Cloudflare Pages 설정값

- 프로젝트 이름: doran-nook (주소 https://doran-nook.pages.dev/)
- 운영 가지(Production branch): cf-pages
- 프레임워크: 없음, 빌드 명령: 비움, 출력 폴더: /

출처와 저작권: 팬이 만든 비공식 도구예요. 아이템 이름과 이미지의 저작권은 Nintendo에 있어요.
