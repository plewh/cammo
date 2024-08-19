## Cammo.py
- A small, self-contained python tool to help pentesters defeat Time-of-Click security controls (e.g. Microsoft Safe Links, Mimecast URL Protection etc.)

## Usage
- Run with `-h` for options
    - By default, will start a plain-text HTTP listener on port 80
- Provide valid TLS certificate (e.g. `fullchain.pem` from LetsEncrypt) using `-sc <cert_file>` and certificate key using `-sk <privkey_file>` to enable a HTTPS web server
- By default, the web server will respond to everything with a 200 OK
    - Use `-m <ip>` to provide an IP address that you want to match on
    - Use `-mf <file_path>` to load the contents of a file to include as the body in responses that match the IP supplied in `-m`
    - Use `-nf <file_path>` to load the contents of a file to include as the body in any responses that DO NOT match the IP supplied in `-m`
