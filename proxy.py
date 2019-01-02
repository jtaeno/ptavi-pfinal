import sys
import time
import socket
import socketserver
import json

from xml.sax import make_parser
from xml.sax.handler import ContentHandler

class XmlHandler(ContentHandler):

    def __init__(self):
        self.dicc = {}
        self.list = []
        self.etiq = []

    def startElement(self, atributo, attrs):
        self.list = ["server", "database", "log"]

        self.dicc = {
                     'server': ['name', 'ip', 'puerto'],
                     'database': ['path', 'passwdpath'],
                     'log': ['path'],
                     }

        self.diccionario = {}
        if atributo  in self.list:
            self.diccionario = {'etiqueta': atributo}
            for objeto in self.dicc[atributo]:
                self.diccionario[objeto] = attrs.get(objeto, "")
            self.etiq.append(self.diccionario)

    def get_tags(self):
        return self.etiq

class LOG:

    def fich_log(fich, Metodo_fich, Text, Ip, Port):

        fichero_log = open(fich, 'a')
        actualtime = time.strftime('%Y-%m-%d %H:%M:%S',
                                   time.gmtime(time.time()))

        if Metodo_fich == "sent_to":
            mensaje = " Sent to " + str(Ip) + ":" + str(Port) + ":  " + Text + "\r\n"
            fichero_log.write(actualtime + mensaje)

        elif Metodo_fich == "received":
            mensaje = " received " + str(Ip) + ":" + str(Port) + ":  " + Text + "\r\n"
            fichero_log.write(actualtime + mensaje)
        elif Metodo_fich == "error":
            mensaje = " error " + str(Ip) + ":" + str(Port) + ":  " + Text + "\r\n"
            fichero_log.write(actualtime + mensaje)
        elif Metodo_fich == "starting":
            mensaje = " starting " + str(Ip) + ":" + str(Port) + ":  " + Text + "\r\n"
            fichero_log.write(actualtime + mensaje)
        elif Metodo_fich == "finishing":
            mensaje = " finishing " + str(Ip) + ":" + str(Port) + ":  " + Text + "\r\n"
            fichero_log.write(actualtime + mensaje)
        fichero_log.close()

class SIPRegisterHandler(socketserver.DatagramRequestHandler):

    Dicc = {}
    register_recibidos = {}

    def register2json(self):
        with open('registered.json', 'w') as jsonfile:
            json.dump(self.Dicc, jsonfile, indent=3)

    def json2register(self):
        try:
            with open('registered.json', 'r') as jsonfile:
                self.Dicc = json.load(jsonfile)
        except:
            pass

    def handle(self):
        self.json2register()

        line = self.rfile.read()
        print("El cliente nos manda: ", line.decode('utf-8'))

        nonce = '91691692'
        linea = line.decode('utf-8')
        METODO = linea.split(' ')[0]

        ip_client = self.client_address[0]
        puerto_client = self.client_address[1]

        while 1:
            try:
                if METODO  == 'REGISTER':
                    linea = line.decode('utf-8')
                    sip = linea.split(' ')[1]
                    servidor_port = sip.split(':')[2]
                    direccion = sip.split(':')[1]
                    texto = linea.split("\r\n")
                    LOG.fich_log(database_path, "received",
                                ip_client , puerto_client, texto)

                    expires = int(linea.split(' ')[3].split('\r\n')[0])
                    actualtime = time.strftime('%Y-%m-%d %H:%M:%S',
                                               time.gmtime(time.time()))
                    exptime = time.strftime('%Y-%m-%d %H:%M:%S',
                                            time.gmtime(time.time() + expires))
                    tiempo_restante = time.strftime('%Y-%m-%d %H:%M:%S',time.gmtime((time.time() + expires) - (time.time())))

                    self.register_recibidos = self.Dicc

                    if not direccion in self.register_recibidos:
                        self.register_recibidos[direccion] = [exptime]
                        respuesta = ("SIP/2.0 401 Unauthorized" + "\r\n")
                        respuesta += "WWW Authenticate: Digest nonce = "
                        respuesta += nonce + "\r\n"
                        self.wfile.write(bytes(respuesta, 'utf-8') + b'\r\n')
                        print("Enviando: \r\n" + respuesta)
                        texto = "SIP/2.0 401 Unauthorized"
                        LOG.fich_log(database_path, "sent_to",
                                    ip_client , puerto_client, texto)

                    else:
                        if expires != 0:
                            self.Dicc[direccion] = ['IP: ' + ip_client, 'PORT: ' + servidor_port,'Tiempo: ' + exptime, 'Tiempo restante: ' + tiempo_restante]
                            self.wfile.write(b"SIP/2.0 200 OK\r\n")
                            texto = "SIP/2.0 200 OK"
                            LOG.fich_log(database_path, "sent_to",
                                        ip_client , puerto_client, texto)
                            print("SIP/2.0 200 OK\r\n")
                            print(" ")
                        if expires == 0:
                            try:
                                self.wfile.write(b"SIP/2.0 200 OK\r\n")
                                texto = "SIP/2.0 200 OK"
                                LOG.fich_log(database_path, "sent_to",
                                            ip_client , puerto_client, texto)
                                del self.register_recibidos[direccion]
                                del self.Dicc[direccion]
                            except KeyError:
                                print("Se ha eliminado: " + direccion)
                        self.Borrar = []
                        for user in self.Dicc:
                            if actualtime >= self.Dicc[user][1]:
                                self.Borrar.append(user)
                                print("Se ha eliminado: ", self.Borrar)
                                print(" ")
                        for users in self.Borrar:
                            del self.register_recibidos[users]
                            del self.Dicc[users]
                elif METODO == 'INVITE':
                    linea = line.decode('utf-8')
                    texto = linea.split("\r\n")
                    LOG.fich_log(database_path, "received",
                                ip_client , puerto_client, texto)
                    name = linea.split(' ')[1].split(':')[1]
                    with open('registered.json') as file:
                        fichero = json.load(file)
                    if name in fichero:
                        ip_server = fichero[name][0].split(' ')[1]
                        puerto_server = fichero[name][1].split(' ')[1]
                        print("Se lo enviamos a: ", name,"\r\n")
                        texto = linea.split("\r\n")
                        LOG.fich_log(database_path, "sent_to",
                                    ip_server , puerto_server, texto )
                        my_socket = socket.socket(socket.AF_INET,
                                                  socket.SOCK_DGRAM)
                        my_socket.setsockopt(socket.SOL_SOCKET,
                                             socket.SO_REUSEADDR, 1)
                        my_socket.connect((ip_server, int(puerto_server)))
                        my_socket.send(bytes(linea,  'utf-8'))
                        data = my_socket.recv(1024)
                        print("Recibido: \r\n", data.decode('utf-8'))
                        self.wfile.write(data)
                        texto = data.decode('utf-8').split('\r\n')
                        LOG.fich_log(database_path, "received",
                                    ip_server , puerto_server, texto)
                        print("Enviando: \r\n" + data.decode("utf-8"))
                        texto =  data.decode('utf-8').split('\r\n')
                        LOG.fich_log(database_path, "sent_to",
                                    ip_client , puerto_client, texto)
                    else:
                        self.wfile.write(b"SIP/2.0 404 User Not Found\r\n")
                        print("Enviando: \r\n" + "SIP/2.0 404 User Not Found\r\n")
                        texto = "SIP/2.0 404 User Not Found"
                        LOG.fich_log(database_path, "sent_to",
                                    ip_client , puerto_client, texto)
                elif METODO == 'ACK':
                    linea = line.decode('utf-8')
                    name = linea.split(' ')[2]
                    texto = linea.split("\r\n")
                    LOG.fich_log(database_path, "received",
                                ip_client , puerto_client, texto)

                    with open('registered.json') as file:
                        fichero = json.load(file)

                    ip_server = fichero[name][0].split(' ')[1]
                    puerto_server = fichero[name][1].split(' ')[1]

                    if name in fichero:
                        my_socket = socket.socket(socket.AF_INET,
                                                  socket.SOCK_DGRAM)
                        my_socket.setsockopt(socket.SOL_SOCKET,
                                             socket.SO_REUSEADDR, 1)
                        my_socket.connect((ip_server, int(puerto_server)))
                        my_socket.send(bytes(line))
                        texto = linea.split("\r\n")
                        LOG.fich_log(database_path, "sent_to",
                                    ip_server , puerto_server, texto)
                elif METODO == 'BYE':
                    linea = line.decode('utf-8')
                    name = linea.split(' ')[2]
                    texto = linea.split("\r\n")
                    LOG.fich_log(database_path, "received",
                                ip_client , puerto_client, texto)
                    with open('registered.json') as file:
                        fichero = json.load(file)
                    if name in fichero:
                        ip_server = fichero[name][0].split(' ')[1]
                        puerto_server = fichero[name][1].split(' ')[1]
                        my_socket = socket.socket(socket.AF_INET,
                                                  socket.SOCK_DGRAM)
                        my_socket.setsockopt(socket.SOL_SOCKET,
                                             socket.SO_REUSEADDR, 1)
                        my_socket.connect((ip_server, int(puerto_server)))
                        my_socket.send(bytes(linea,  'utf-8'))
                        texto =  linea.split("\r\n")
                        LOG.fich_log(database_path, "sent_to",
                                    ip_server, puerto_server, texto)
                        data = my_socket.recv(1024)
                        texto = data.decode('utf-8').split("\r\n")
                        LOG.fich_log(database_path, "received",
                                    ip_server , puerto_server, texto)
                        print("Recibido: \r\n", data.decode('utf-8'))
                        self.wfile.write(data)
                        texto = data.decode('utf-8').split("\r\n")
                        LOG.fich_log(database_path, "sent_to",
                                    ip_client , puerto_client, texto)
                        print("Enviando: \r\n" + data.decode("utf-8"))
                elif METODO != ['REGISTER', 'INVITE', 'ACK', ' BYE']:
                    linea = line.decode('utf-8')
                    resultado = line.decode('utf-8')
                    name = linea.split(' ')[2]
                    texto = linea.split('\r\n')
                    LOG.fich_log(database_path, "received",
                                ip_client, puerto_client, texto)
                    print("Recibido: \r\n", linea)
                    texto = ["SIP/2.0 405 Method Not Allowed\r\n"]
                    LOG.fich_log(database_path, "sent_to",
                                ip_client , puerto_client, texto)
                    self.wfile.write(b"SIP/2.0 405 Method Not Allowed\r\n")
                    print("Enviando: \r\n", "SIP/2.0 405 Method Not Allowed\r\n" )
                if not line or len(linea):
                        break
            except ConnectionResetError:
                texto = ["SIP/2.0 400 Bad Request\r\n"]
                LOG.fich_log(database_path, "sent_to",
                            ip_client , puerto_client, texto)
                self.wfile.write(b"SIP/2.0 400 Bad Request\r\n")
                print("Enviando al cliente: \r\n", "SIP/2.0 400 Bad Request\r\n")
                texto = ["ERROR: No Connection"]
                LOG.fich_log(database_path, "received",
                            ip_client, puerto_client, texto)
                sys.exit("ERROR: No Connection")
        self.register2json()

if __name__ == "__main__":
    try:
        (Programa, Config) = sys.argv
    except ValueError or IndexError:
            sys.exit("Usage: python proxy_registrar.py config")

    parser = make_parser()
    xmlhandler = XmlHandler()
    parser.setContentHandler(xmlhandler)
    parser.parse(open(Config))
    DICCIONARIO = xmlhandler.get_tags()

    server_name = DICCIONARIO[0]['name']
    server_ip = DICCIONARIO[0]['ip']
    server_puerto = int(DICCIONARIO[0]['puerto'])
    database_passwdpath =  DICCIONARIO[1]['passwdpath']
    database_path = DICCIONARIO[1]['path']
    log_path = DICCIONARIO[2]['path']

    serv = socketserver.UDPServer((server_ip, server_puerto), SIPRegisterHandler)
    print('Server ' +  server_name + ' listening at port: ' + str(server_puerto)+ '\n')
    try:
        serv.serve_forever()
    except KeyboardInterrupt:
        print('\n' + "Finalizado servidor")
