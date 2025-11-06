"""
@author: Junior Tada, Leonardo Tada

Classe que sobrescreve metodos da lib suds para comunicação via https com certificado digital

"""

import os
import ssl
import sys
import tempfile
from suds.transport.http import HttpTransport
import urllib.request
import http.client


class TempPEMFiles:
    def __init__(self, cert, key):
        self.cert = cert
        self.key = key
        self.cert_path = None
        self.key_path = None

    def __enter__(self):
        # Verifica se é PEM ou caminho de arquivo, lidando com str ou bytes
        if isinstance(self.cert, bytes):
            is_pem_cert = self.cert.startswith(b"-----BEGIN")
        else:
            is_pem_cert = self.cert.startswith("-----BEGIN")
        if isinstance(self.key, bytes):
            is_pem_key = self.key.startswith(b"-----BEGIN")
        else:
            is_pem_key = self.key.startswith("-----BEGIN")

        if is_pem_cert and is_pem_key:
            # Cria arquivos temporários para PEM
            with tempfile.NamedTemporaryFile(
                mode="wb" if isinstance(self.cert, bytes) else "w", suffix=".pem", delete=False
            ) as cert_file:
                cert_file.write(self.cert)
                self.cert_path = cert_file.name
            with tempfile.NamedTemporaryFile(
                mode="wb" if isinstance(self.key, bytes) else "w", suffix=".key", delete=False
            ) as key_file:
                key_file.write(self.key)
                self.key_path = key_file.name
        else:
            # Assume caminhos de arquivo
            self.cert_path = self.cert
            self.key_path = self.key
        return self.cert_path, self.key_path

    def __exit__(self, exc_type, exc_val, exc_tb):
        # Limpa arquivos temporários se foram criados
        if self.cert_path and self.cert_path != self.cert:
            os.unlink(self.cert_path)
        if self.key_path and self.key_path != self.key:
            os.unlink(self.key_path)


class HTTPSClientAuthHandler(urllib.request.HTTPSHandler):
    def __init__(self, key, cert):
        urllib.request.HTTPSHandler.__init__(self)
        self.key = key
        self.cert = cert

    def https_open(self, req):
        # Rather than pass in a reference to a connection class, we pass in
        # a reference to a function which, for all intents and purposes,
        # will behave as a constructor
        return self.do_open(self.getConnection, req)

    def getConnection(self, host, timeout=300):
        with TempPEMFiles(self.cert, self.key) as (cert_path, key_path):
            if sys.version_info >= (3, 8):
                context = ssl.create_default_context()
                context.load_cert_chain(certfile=cert_path, keyfile=key_path)
                return http.client.HTTPSConnection(host, timeout=timeout, context=context)
            else:
                return http.client.HTTPSConnection(
                    host, timeout=timeout, key_file=key_path, cert_file=cert_path
                )


class PreserveMethodRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Preserva o método, dados e cabeçalhos originais em redirecionamentos
        new_req = urllib.request.HTTPRedirectHandler.redirect_request(
            self, req, fp, code, msg, headers, newurl
        )
        if new_req:
            if req.get_method() == "POST":
                new_req.get_method = lambda: "POST"
            new_req.data = req.data  # Preserva o corpo da solicitação
            new_req.headers = req.headers.copy()  # Preserva os cabeçalhos
        return new_req


class HttpAuthenticated(HttpTransport):
    def __init__(self, key, cert, endereco, *args, **kwargs):
        HttpTransport.__init__(self, *args, **kwargs)
        self.key = key
        self.cert = cert
        self.endereco = endereco

    # def open(self, request):
    #     opener = urllib.request.build_opener(HTTPSClientAuthHandler(self.key, self.cert))
    #     return opener.open(self.endereco)

    def u2handlers(self):
        return [HTTPSClientAuthHandler(self.key, self.cert), PreserveMethodRedirectHandler()]
