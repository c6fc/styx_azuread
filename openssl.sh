openssl req -x509 -sha256 -nodes -days 3652 -newkey rsa:2048 -keyout key.key -out certificate.crt -subj /C=US/ST=Colorado/L=Longmont/CN=styx
openssl x509 -new -key key.key -subj /C=US/ST=Colorado/L=Longmont/CN=styx -force_pubkey styx.cer -days 365 -out styx.x509
openssl x509 -in styx.x509 -inform pem -text -noout -purpose

openssl req -x509 -sha256 -nodes -days 3652 -newkey rsa:2048 -keyout - -subj /C=US/ST=Colorado/L=Longmont/CN=styx | openssl x509 -new -subj /C=US/ST=Colorado/L=Longmont/CN=styx -force_pubkey styx.cer -days 365 -out styx.x509
openssl x509 -in styx.x509 -inform pem -text -noout -purpose


openssl req -x509 -sha256 -nodes -days 3652 -newkey rsa:2048 -keyout - -out /dev/null -subj /C=US/ST=Colorado/L=Longmont/CN=styx | openssl x509 -new -key /dev/stdin -subj /C=US/ST=Colorado/L=Longmont/CN=styx -force_pubkey styx.cer -days 365 -outform der | base64 -w0