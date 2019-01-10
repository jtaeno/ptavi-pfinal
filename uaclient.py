
"""Programa Cliente."""

import socket
import sys
import os

from proxy import LOG, contra
from xml.sax import make_parser
from xml.sax.handler import ContentHandler


class XmlHandler(ContentHandler):
    """Crea un Diccionario y guarda los valores del xml."""

    def __init__(self):
        self.dicc = {}
        self.list = []
        self.etiq = []

    def startElement(self, atributo, attrs):
        self.list = ["account", "uaserver", "rtpaudio", "regproxy",
                     "log", "audio"]

        self.dicc = {'account': ['username', 'passwd'],
                     'uaserver': ['ip', 'puerto'],
                     'rtpaudio': ['puerto'],
                     'regproxy': ['ip', 'puerto'],
                     'log': ['path'],
                     'audio': ['path']}

        self.diccionario = {}
        if atributo in self.list:
            self.diccionario = {'etiqueta': atributo}
            for objeto in self.dicc[atributo]:
                self.diccionario[objeto] = attrs.get(objeto, "")
            self.etiq.append(self.diccionario)

    def get_tags(self):
        return self.etiq


if __name__ == "__main__":

    try:
        (Programa, Config, Metod, Opcion) = sys.argv

        parser = make_parser()
        xmlhandler = XmlHandler()
        parser.setContentHandler(xmlhandler)
        parser.parse(open(Config))
        DICCIONARIO = xmlhandler.get_tags()

        account_username = DICCIONARIO[0]['username']
        account_passwd = DICCIONARIO[0]['passwd']
        uaserver_ip = DICCIONARIO[1]['ip']
        uaserver_puerto = int(DICCIONARIO[1]['puerto'])
        rtpaudio_puerto = int(DICCIONARIO[2]['puerto'])
        regproxy_ip = DICCIONARIO[3]['ip']
        regproxy_puerto = int(DICCIONARIO[3]['puerto'])
        log_path = DICCIONARIO[4]['path']
        audio_path = DICCIONARIO[5]['path']

        LINEA = ""
        texto = ''
        METODO = Metod.upper()
        V = 'v = 0\r\n'
        O = 'o = ' + account_username + ' ' + uaserver_ip + '\r\n'
        S = 's = misesion' + '\r\n'
        T = 't = 0' + '\r\n'
        M = 'm = audio ' + str(rtpaudio_puerto) + ' RTP\r\n'

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as my_socket:
            my_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            my_socket.connect((regproxy_ip, regproxy_puerto))

            if METODO == 'REGISTER':
                LOG.fich_log(log_path, "starting", regproxy_ip,
                             regproxy_puerto, texto)
                LINE = 'REGISTER ' + 'sip:' + account_username + ':'
                LINE += str(uaserver_puerto) + ' SIP/2.0\r\n'
                LINE += 'Expires: ' + Opcion + '\r\n'
            elif METODO == 'INVITE':
                LINE = 'INVITE ' + 'sip:' + Opcion + ' SIP/2.0\r\n'
                LINE += 'Content-Type: application/sdp\r\n' + V + O + S + T + M
            elif METODO == 'BYE':
                LINE = 'BYE ' + 'sip: ' + Opcion + ' SIP/2.0\r\n'
            elif METODO != ['INVITE', 'ACK', ' BYE']:
                LINE = Metod + ' sip: ' + Opcion + ' SIP/2.0\r\n'
            else:
                LINE = Opcion

            print("Enviando: " + LINE + "\r\n")
            my_socket.send(bytes(LINE, 'utf-8') + b'\r\n')
            texto = " ".join(LINE.split("\r\n"))
            LOG.fich_log(log_path, "sent_to", regproxy_ip,
                         regproxy_puerto, texto)
            try:
                data = my_socket.recv(1024)
            except ConnectionRefusedError or ConnectionResetError:
                texto = "ERROR: No Connection"
                LOG.fich_log(log_path, "received",
                             regproxy_ip, regproxy_puerto, texto)
                sys.exit("ERROR: No Connection")
            respuesta = data.decode('utf-8')
            resultado = data.decode('utf-8').split('\r\n')
            resultado1 = data.decode('utf-8').split(' ')
            supuestos = "SIP/2.0 100 Trying"
            texto = " ".join(respuesta.split('\r\n'))
            LOG.fich_log(log_path, "received",
                         regproxy_ip, regproxy_puerto, texto)
            if "BYE RECIBIDO" in respuesta:
                texto = ''
                LOG.fich_log(log_path, "finishing", regproxy_ip,
                             regproxy_puerto, texto)
                respuesta = respuesta
            if "405" in respuesta:
                texto = ' '.join(respuesta.split("\r\n"))
                respuesta = "METODO INCORRECTO\r\n" + respuesta
                LOG.fich_log(log_path, "error",
                             regproxy_ip, regproxy_puerto, texto)
            if resultado1[1] == '401':
                respuesta = "/// NECESITA AUTORIZACION ///\r\n" + respuesta

            print("Recibido: ")
            print(respuesta + '\r\n')

            if "401" in respuesta:
                contraseña_regis = respuesta.split(' ')[13].split('\r\n\r\n')[0]
                nonce = contra(account_passwd, contraseña_regis)
                LINE = 'REGISTER ' + 'sip:' + account_username + ':'
                LINE += str(uaserver_puerto) + ' SIP/2.0\r\n'
                LINE += 'Expires: ' + Opcion + '\r\n'
                LINE += 'Authorization: Digest response = ' + nonce
                texto = ' '.join(LINE.split("\r\n"))
                LOG.fich_log(log_path, "sent_to",
                             regproxy_ip, regproxy_puerto, texto)
                print("Enviando: " + LINE + "\r\n")
                my_socket.send(bytes(LINE, 'utf-8') + b'\r\n')
            if supuestos == resultado[1]:
                print("Enviando ACK...", 'ACK sip:' + Opcion + ' SIP/2.0')
                ACK = 'ACK sip: ' + Opcion + ' SIP/2.0', 'utf-8'
                texto = str(ACK)
                LOG.fich_log(log_path, "sent_to",
                             regproxy_ip, regproxy_puerto, texto)
                my_socket.send(bytes('ACK sip: ' + Opcion +
                                     ' SIP/2.0', 'utf-8') +
                               b'\r\n')

    except FileNotFoundError:
        sys.exit("Usage: python3 .xml file")
    except ValueError:
        sys.exit("Usage: python uaclient.py config method option")
