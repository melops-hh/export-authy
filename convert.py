# Modified from https://help.ente.io/auth/migration-guides/authy/#method-2-1-if-the-export-worked-but-the-import-didn-t
import json
import os

totp = []

accounts = json.load(open('./bitwarden.json','r',encoding='utf-8'))

for account in accounts['decrypted_authenticator_tokens']:
    totp.append('otpauth://totp/'+account['name']+'?secret='+account['decrypted_seed']+'\n')

writer = open('auth_codes.txt','w+',encoding='utf-8')
writer.writelines(totp)
writer.close()

print('Saved to ' + os.getcwd() + '/auth_codes.txt')
