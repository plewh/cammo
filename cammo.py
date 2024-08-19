# openssl req -x509 -newkey rsa:4096 -keyout privkey.pem -out cert.pem -sha256 -days 3650 -nodes -subj '/CN=rawr.com'

import socket
import select
import ssl
import datetime
import signal
import argparse
import ipaddress

RED = "\033[1;31m"
GRN = "\033[1;32m"
YEL = "\033[1;33m"
END = "\033[0m"

class server:
	def __init__(self):
		self.l_max_recv = 4096
		self.l_max_conns = 5
		self.resp_bytes_pos = None
		self.resp_bytes_neg = None
		self.readers = []
		self.targets = []

	def clean_up(self):
		for r_sock in self.readers:
			r_sock.close()
		print(END)

	def create_socket(self, l_host, l_port):
		print("[+] creating listening socket...")
		l_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #todo: exception handling
		l_sock.bind((l_host, l_port))
		l_sock.listen(self.l_max_conns)

		print(f"[+] fd {l_sock.fileno()}: binding listening socket to {l_host}:{l_port}")
		return l_sock

	def start_tls(self, l_sock, server_cert, server_privkey):
		try:
			tls_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
			tls_ctx.load_cert_chain(server_cert, server_privkey)
		except ssl.SSLError as e:
			print_err(f"[!]oh noes! couldn't init TLS crypto, check cert files & permissions!")
			exit(1)
		except Exception as e:
			print_err(f"[+] oh noes! something broke trying to init TLS crypto!")
			print(e)
			exit(1)

		sl_sock = tls_ctx.wrap_socket(l_sock, server_side=True)
		return sl_sock

	def srv_handle_conns(self, r_sock):
		try:
			(c_sock, address) = r_sock.accept()
			print(f"[+] fd {r_sock.fileno()}: caught new conn from {c_sock.getpeername()[0]}! allocating to fd {c_sock.fileno()}")
			self.readers.append(c_sock)
		except ssl.SSLError as e:
			print_err(f"[!] fd {r_sock.fileno()}: oh noes! couldn't encrypt connection!")
			for arg in e.args:
				if "TLSV1_ALERT_UNKNOWN_CA" in str(arg):
					print(f"[+] fd {r_sock.fileno()}: peer rejected cert")
		except Exception as e:
			print("[+] fd {r_sock.fileno()}: oh noes! something broke the socket!")
			print(e)

	def srv_handle_resp(self, r_sock):
		peer_addr = r_sock.getpeername()[0]
		match = False
		for t in self.targets:
			if str(t) == peer_addr:
				match = True
		print(f"{GRN}─ Reply to {peer_addr}{'─' * (80 - len(peer_addr) - 11)}{END}")
		send_bytes = self.send_bytes_pos if match else self.send_bytes_neg
		r_sock.send(send_bytes)
		print(send_bytes.decode())
		print(f"{GRN}{'─' * 80}{END}")

	def srv_handle_req(self, r_sock, recv_bytes):
		t_stamp = datetime.datetime.now().strftime("%y-%m-%d %H:%M:%S")
		peer_addr = r_sock.getpeername()[0]
		print(f"{RED}─[{t_stamp}] Req from: {peer_addr}{'─' * (80 - (len(t_stamp) + len(peer_addr)) - 14)}{END}")
		print(f"{recv_bytes.decode()}")
		print(f"{RED}{'─' * 80}{END}")
		
	def serve(self, l_sock):

		select_timeout = 5.0 #seconds
		l_sock.setblocking(False)
		self.readers.append(l_sock)

		while True:
			r_socks, w_socks, e_socks = select.select(self.readers, [], [], select_timeout)

			for r_sock in r_socks:
				if r_sock == l_sock:
					self.srv_handle_conns(r_sock)
				else:
					recv_bytes = r_sock.recv(self.l_max_recv)
					if len(recv_bytes) == 0:
						print(f"[+] fd {r_sock.fileno()}: peer sent shutdown! closing fd")
						self.readers.remove(r_sock)
						r_sock.close()
					else:
						print(f"[+] fd {r_sock.fileno()}: recv {len(recv_bytes)} bytes from peer")
						self.srv_handle_req(r_sock, recv_bytes)
						self.srv_handle_resp(r_sock)

	def build_resp(self, code, headers, body):
		send_bytes = b""

		if code == 200:
			send_bytes += "HTTP/1.1 200 OK\n".encode()

		send_bytes += f"Date: {datetime.datetime.now().strftime('%a, %d %b %Y %H:%M:%S GMT')}\n".encode() #todo convert to GMT
		for header in headers:
			send_bytes += header.encode()
			if header[-1] != "\n":
				send_bytes += "\n".encode()

		if body:
			send_bytes += f"Content-Length: {len(body)}\n".encode()
		else:
			send_bytes += "Content-Length: 0\n".encode()

		send_bytes += "\n".encode()

		if body:
			send_bytes += body

		return send_bytes

	def set_pos_bytes(self, code, headers, body):
		self.send_bytes_pos = self.build_resp(code, headers, body)

	def set_neg_bytes(self, code, headers, body):
		self.send_bytes_neg = self.build_resp(code, headers, body)

	def add_target(self, targ):
		self.targets.append(targ)

def print_err(string):
	print(f"{RED}{string}{END}")

def print_warn(string):
	print(f"{YEL}{string}{END}")

def get_file_bytes(fpath):
	if not fpath:
		return None
	f = open(fpath, "r")
	bytez = f.read().encode()
	print(f"[+] loaded {len(bytez)} bytes from {fpath}")
	return bytez

def do_params():
	parser = argparse.ArgumentParser()
	parser.add_argument( \
		"-a", \
		"--bind-address", \
		help="local ip of listening socket (default 0.0.0.0)", \
		type=str, \
		default="0.0.0.0" \
	)
	parser.add_argument( \
		"-p", \
		"--bind-port", \
		help="local port of listening socket (default 80)", \
		type=int, default=80 \
	)
	parser.add_argument( \
		"-sc", \
		"--server-cert", \
		help="path of server certificate (cert.pem), both -sc and -sk required for TLS", \
		type=str \
	)
	parser.add_argument( \
		"-sk", \
		"--server-privkey", \
		help="path of server certificate private key (privkey.pem), both -sc and -sk required for TLS", \
		type=str \
	)
	parser.add_argument( \
		"-mf", \
		"--match-file", \
		help="file to serv if request comes from peer in target ip range", \
		type=str, \
		default=None \
	)
	parser.add_argument( \
		"-nf", \
		"--not-match-file", \
		help="file to serv if request does NOT come from peer in target ip range", \
		type=str, \
		default=None
	)
	parser.add_argument( \
		"-m", \
		"--match", \
		help="ip address to serve match file to", \
		type=str, \
		default=None
	)
	return parser.parse_args()

def main():
	args = do_params()
	if not (args.server_cert and args.server_privkey):
		print_warn(f"[!] warning: starting plain-text HTTP server on port {args.bind_port}, this probs isnt what you want")

	s = server()
	def clean_up(signum, frame):
		print("\n[+] caught SIGINT! cleaning up any open sockets")
		s.clean_up()
		exit(0)
	signal.signal(signal.SIGINT, clean_up)

	if not args.match:
		print_warn(f"[!] warning: no target ip addresses given, matching all connections")
	else:
		try:
			s.add_target(ipaddress.IPv4Address(args.match))
		except Exception as e:
			print_err("[!] oh noes: invalid target ip supplied!")
			exit(1)

	if not args.match_file:
		print_warn(f"[!] warning: no match file supplied, responses to target IPs will have empty body")
	s.set_pos_bytes(200, ["X-Cammo: pos"], get_file_bytes(args.match_file))

	if not args.not_match_file:
		print_warn(f"[!] warning: no not-match file supplied, responses to non-target IPs will have empty body")
	s.set_neg_bytes(200, ["X-Cammo: neg"], get_file_bytes(args.not_match_file))

	l_sock = s.create_socket(args.bind_address, args.bind_port)

	if args.server_cert and args.server_privkey:
		print("[+] TLS certificate and private key provided, enabling TLS")
		if args.bind_port != 443:
			print_warn("[!] warning: starting TLS server on non-standard port, make sure this is what you want")
		sl_sock = s.start_tls(l_sock, args.server_cert, args.server_privkey)
		s.serve(sl_sock)
	elif args.server_cert or args.server_privkey:
		print_err("[!] oh noes: need certificate (-sc) AND private key (-sk) for TLS!")
		exit(1)
	else:
		s.serve(l_sock)

main()
