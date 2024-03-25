# Django-Rest
로그인, 회원가입, CRUD, 댓글, 장바구니, 카카오 페이 결제 기능이 가능한 쇼핑몰 api를 만드려고 합니다.

# 사용한 기술스택
---
- Python
- Django

# 기능
## 로그인
- dj_rest_auth를 이용한 로그인 all-auth를 이용한 회원가입 기능
- token을 이용하여 구글, 네이버, 카카오 소셜로그인

프로필 
- 회원가입, 소셜로그인으로 회원가입 시 이메일과 provider 저장

## CRUD
- apiview를 이용하여 글쓰기 CRUD기능
- user와 post 모델의 1:N 관계를 맺음
- 글 주인만 수정/삭제 가능

## 댓글
- apiview를 이용하여 CURD 기능
- 댓글이 user와 post에 1:N 관계를 맺음
- 댓글 작성자만 수정/삭제 가능

## 장바구니
- 장바구니 추가하면  post title, post id, 수량, 총 금액이 저장

## 결제(추가 예정)