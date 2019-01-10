
"""Programa Server."""

import socketserver
import sys
import os

from xml.sax import make_parser
from xml.sax.handler import ContentHandler
from uaclient import XmlHandler
from proxy import LOG


class EchoHandler(socketserver.DatagramRequestHandler):
    info_invite = {'IP': '', 'PUERTO': ''}

    def handle(self):
        """Maneja Toda la informacion que le llega al server."""

        texto = ''
        ip_client = self.client_address[0]
        puerto_client = self.client_address[1]
        while 1:
            line = self.rfile.read().decode('utf-8')
            print("El cliente nos manda: " + '\r\n' + line)
            METODO = line.split()[6]
            recibido = line.split()
            texto = ' '.join(line.split("\r\n"))
            LOG.fich_log(log_path, "received",
                         regproxy_ip, regproxy_puerto, texto)
            if METODO == 'INVITE':
                self.info_invite['IP'] = recibido[17]
                self.info_invite['PUERTO'] = recibido[27]
                V = 'v = 0\r\n'
                O = 'o = ' + recibido[10] + ' ' + recibido[11] + '\r\n'
                S = 's = misesion' + '\r\n'
                T = 't = 0' + '\r\n'
                M = 'm = audio ' + recibido[21] + ' RTP\r\n'
                SDP = 'Content-Type: application/sdp\r\n' + V + O + S + T + M
                enviar = "SIP/2.0 100 Trying\r\n" + "SIP/2.0 180 Ringing\r\n"
                enviar += "SIP/2.0 200 OK\r\n" + SDP
                self.wfile.write(b"SIP/2.0 100 Trying\r\n")
                self.wfile.write(b"SIP/2.0 180 Ringing\r\n")
                self.wfile.write(b"SIP/2.0 200 OK\r\n")
                self.wfile.write(bytes(SDP, 'utf-8'))
                texto = ' '.join(enviar.split("\r\n"))
                LOG.fich_log(log_path, "sent_to",
                             regproxy_ip, regproxy_puerto, texto)
                print("Enviamos: " + '\r\n' + enviar)
            elif METODO == 'ACK':
                aEjecutarVLC = 'cvlc rtp://@' + self.info_invite['IP'] + ':'
                aEjecutarVLC += self.info_invite['PUERTO']
                print("Vamos a ejecutar", aEjecutarVLC)
                os.system(aEjecutarVLC + '&')
                aEjecutar = "./mp32rtp -i " + self.info_invite['IP'] + " -p "
                aEjecutar += self.info_invite['PUERTO'] + " < " + audio_path
                print("Vamos a ejecutar", aEjecutar)
                os.system(aEjecutar)
            elif METODO == 'BYE':
                self.wfile.write(b"BYE RECIBIDO\r\nSIP/2.0 200 OK \r\n")
                print("SIP/2.0 200 OK \r\n\r\n")
                texto = ' '.join(line.split("\r\n"))
                LOG.fich_log(log_path, "sent_to",
                             regproxy_ip, regproxy_puerto, texto)

            elif METODO != ['INVITE', 'ACK', ' BYE']:
                self.wfile.write(b"SIP/2.0 405 Method Not Allowed\r\n")
                texto = ' '.join(line.split("\r\n"))
                LOG.fich_log(log_path, "sent_to",
                             regproxy_ip, regproxy_puerto, texto)
            else:
                self.wfile.write(b"SIP/2.0 400 Bad Request\r\n")
                texto = ' '.join(line.split("\r\n"))
                LOG.fich_log(log_path, "sent_to",
                             regproxy_ip, regproxy_puerto, texto)

            if not line or len(line):
                        break


if __name__ == "__main__":
    try:
        (Programa, Config) = sys.argv
    except ValueError or IndexError:
            sys.exit("Usage: python uaserver.py config")

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

    serv = socketserver.UDPServer((uaserver_ip, uaserver_puerto), EchoHandler)
    print('Listening...' + '\n')

    try:
        serv.serve_forever()
    except KeyboardInterrupt:
        print('\n' + "Finalizado servidor")
