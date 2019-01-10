import sys
import time
import socket
import socketserver
import json

from hashlib import md5
from xml.sax import make_parser
from xml.sax.handler import ContentHandler

def contra(nonce, passwd, encoding='utf-8'):
    c = md5()
    c.update(bytes(nonce, encoding))
    c.update(bytes(passwd, encoding))
    c.digest()

    return c.hexdigest()

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

    def fich_log(fich, Metodo_fich, Ip, Port , Text):

        fichero_log = open(fich, 'a')
        actualtime = time.strftime('%Y-%m-%d %H:%M:%S',
                                   time.gmtime(time.time()))

        if Metodo_fich == "sent_to":
            mensaje = " Sent to " + str(Ip) + ":" + str(Port) + ":  "
            mensaje += Text + "\r\n"
            fichero_log.write(actualtime + mensaje)

        elif Metodo_fich == "received":
            mensaje = " Received " + str(Ip) + ":" + str(Port) + ":  "
            mensaje += Text + "\r\n"
            fichero_log.write(actualtime + mensaje)
        elif Metodo_fich == "error":
            mensaje = " Error " + str(Ip) + ":" + str(Port) + ":  "
            mensaje += Text + "\r\n"
            fichero_log.write(actualtime + mensaje)
        elif Metodo_fich == "starting":
            mensaje = " Starting ... " + "\r\n"
            fichero_log.write(actualtime + mensaje)
        elif Metodo_fich == "finishing":
            mensaje = " Finishing." + "\r\n"
            fichero_log.write(actualtime + mensaje)
        fichero_log.close()

class SIPRegisterHandler(socketserver.DatagramRequestHandler):

    Dicc = {}
    register_recibidos = {}
    dicc_contra = {}
    nonce = {}

    def json2password(self):
        """Descargo fichero json en el diccionario."""
        try:
            with open(database_passwdpath, 'r') as jsonfile:
                self.dicc_contra = json.load(jsonfile)
        except FileNotFoundError:
            pass

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
        self.json2password()

        line = self.rfile.read()
        print("El cliente nos manda: ", line.decode('utf-8'))

        linea = line.decode('utf-8')
        METODO = linea.split(' ')[0]

        ip_client = self.client_address[0]
        puerto_client = self.client_address[1]
        texto = ''

        while 1:
                if METODO  == 'REGISTER':
                    linea = line.decode('utf-8')
                    lineas = linea.split(' ')
                    sip = linea.split(' ')[1]
                    servidor_port = sip.split(':')[2]
                    direccion = sip.split(':')[1]
                    texto = ' '.join(linea.split("\r\n"))
                    LOG.fich_log(database_path, "received",
                                ip_client , puerto_client, texto)
                    expires = int(linea.split(' ')[3].split('\r\n')[0])
                    actualtime = time.strftime('%Y-%m-%d %H:%M:%S',
                                               time.gmtime(time.time()))
                    exptime = time.strftime('%Y-%m-%d %H:%M:%S',
                                            time.gmtime(time.time() + expires))
                    tiempo_restante = time.strftime('%Y-%m-%d %H:%M:%S',
                                                    time.gmtime((time.time()
                                                    + expires) -
                                                    (time.time())))
                    cabecera_proxy = "VIA Proxy IP: " + server_ip + " PORT: "
                    cabecera_proxy += str(server_puerto) + ' ' "\r\n"
                    self.register_recibidos = self.Dicc
                    if expires != 0:
                        if len(lineas) >= 7:
                            nonce_recv = linea.split(' ')[7].split('\r\n')[0]
                            passwd = self.dicc_contra[direccion]['contrasena']
                            nonce = contra(passwd, self.nonce[direccion])
                            if nonce == nonce_recv:
                                self.Dicc[direccion] = ['IP= ' + ip_client, 'PORT= '
                                                       + servidor_port,'Tiempo= '
                                                       + exptime,
                                                       'Tiempo restante= '
                                                       + tiempo_restante]
                                self.wfile.write(bytes(cabecera_proxy , 'utf-8'))
                                self.wfile.write(b"SIP/2.0 200 OK\r\n")
                                texto = "SIP/2.0 200 OK"
                                LOG.fich_log(database_path, "sent_to",
                                            ip_client , puerto_client, texto)
                                print("SIP/2.0 200 OK\r\n")
                                print(" ")
                        elif len(lineas) <= 5:
                            if direccion in self.register_recibidos:
                                self.Dicc[direccion] = ['IP= ' + ip_client, 'PORT= '
                                                       + servidor_port,'Tiempo= '
                                                       + exptime,
                                                       'Tiempo restant=: '
                                                       + tiempo_restante]
                                self.wfile.write(bytes(cabecera_proxy , 'utf-8'))
                                self.wfile.write(b"SIP/2.0 200 OK\r\n")
                                texto = "SIP/2.0 200 OK"
                                LOG.fich_log(database_path, "sent_to",
                                            ip_client , puerto_client, texto)
                                print("SIP/2.0 200 OK\r\n")
                                print(" ")
                            else:
                                print("CONTRASEÑA INCORRECTA")
                                self.nonce[direccion] = '91691692'
                                respuesta = cabecera_proxy
                                respuesta += ("SIP/2.0 401 Unauthorized" + "\r\n")
                                respuesta += "WWW Authenticate: Digest nonce = "
                                respuesta += self.nonce[direccion] + "\r\n"
                                self.wfile.write(bytes(respuesta, 'utf-8') + b'\r\n')
                                print("Enviando: \r\n" + respuesta)
                                texto = "SIP/2.0 401 Unauthorized"
                                LOG.fich_log(database_path, "sent_to",
                                            ip_client , puerto_client, texto)
                    if expires == 0:
                        if direccion in self.register_recibidos:
                            try:
                                self.wfile.write(bytes(cabecera_proxy, 'utf-8'))
                                self.wfile.write(b"SIP/2.0 200 OK\r\n")
                                texto = "SIP/2.0 200 OK"
                                LOG.fich_log(database_path, "sent_to",
                                            ip_client , puerto_client, texto)
                                del self.register_recibidos[direccion]
                                del self.Dicc[direccion]
                            except KeyError:
                                print("Se ha eliminado: " + direccion)
                        else:
                            self.wfile.write(bytes(cabecera_proxy , 'utf-8'))
                            self.wfile.write(b"SIP/2.0 200 OK\r\n")
                            texto = "SIP/2.0 200 OK"
                            LOG.fich_log(database_path, "sent_to",
                                        ip_client , puerto_client, texto)
                            print("SIP/2.0 200 OK\r\n")
                    Borrar = []
                    for user in self.Dicc:
                        print(user)
                        tempo_user = self.Dicc[user][2].split('= ')[1]
                        if actualtime >= tempo_user:
                            Borrar.append(user)

                            print("Se ha eliminado: ", Borrar)
                            print(" ")
                    for user in Borrar:
                        print(Borrar)
                        print(self.Dicc[user])
                        del self.register_recibidos[user]
                        del self.Dicc[user]
                elif METODO == 'INVITE':
                    linea = line.decode('utf-8')
                    cabecera_proxy = "VIA Proxy IP: " + server_ip + " PORT: "
                    cabecera_proxy += str(server_puerto) + "\r\n"
                    juntar = linea.split("\r\n")
                    texto = ' '.join(linea.split("\r\n"))
                    LOG.fich_log(database_path, "received",
                                ip_client , puerto_client, texto)
                    name = linea.split(' ')[1].split(':')[1]
                    with open('registered.json') as file:
                        fichero = json.load(file)
                    if name in fichero:
                        ip_server = fichero[name][0].split(' ')[1]
                        puerto_server = fichero[name][1].split(' ')[1]
                        print("Se lo enviamos a: ", name,"\r\n")
                        texto = ' '.join(linea.split("\r\n"))
                        LOG.fich_log(database_path, "sent_to",
                                    ip_server , puerto_server, texto )
                        my_socket = socket.socket(socket.AF_INET,
                                                  socket.SOCK_DGRAM)
                        my_socket.setsockopt(socket.SOL_SOCKET,
                                             socket.SO_REUSEADDR, 1)
                        my_socket.connect((ip_server, int(puerto_server)))
                        linea = cabecera_proxy + linea
                        my_socket.send(bytes(linea,  'utf-8'))
                        try:
                            data = my_socket.recv(1024)
                        except ConnectionRefusedError or ConnectionResetError:
                            texto = "SIP/2.0 400 Bad Request\r\n"
                            LOG.fich_log(database_path, "sent_to",
                                        ip_client , puerto_client, texto)
                            self.wfile.write(b"SIP/2.0 400 Bad Request\r\n")
                            print("Enviando al cliente: \r\n",
                            "SIP/2.0 400 Bad Request\r\n")
                            texto = ["ERROR: No Connection"]
                            LOG.fich_log(database_path, "received",
                                        ip_client, puerto_client, texto)
                            sys.exit("ERROR: No Connection")
                        print("Recibido: \r\n", data.decode('utf-8'))
                        juntar = data.decode('utf-8').split('\r\n')
                        texto = ' '.join(juntar)
                        LOG.fich_log(database_path, "received",
                                    ip_server , puerto_server, texto)
                        datas = cabecera_proxy +  data.decode('utf-8')
                        self.wfile.write(bytes(datas, 'utf-8'))
                        print("Enviando: \r\n" + data.decode("utf-8"))
                        juntar =  data.decode('utf-8').split('\r\n')
                        texto = ' '.join(juntar)
                        LOG.fich_log(database_path, "sent_to",
                                    ip_client , puerto_client, texto)
                    else:
                        texto = cabecera_proxy
                        texto += "SIP/2.0 404 User Not Found\r\n"
                        self.wfile.write(bytes(texto , 'utf-8'))
                        print("Enviando: \r\n"
                             + "SIP/2.0 404 User Not Found\r\n")
                        texto = "SIP/2.0 404 User Not Found"
                        LOG.fich_log(database_path, "sent_to",
                                    ip_client , puerto_client, texto)
                elif METODO == 'ACK':
                    linea = line.decode('utf-8')
                    print(linea)
                    name = linea.split(' ')[2]
                    texto = ' '.join(linea.split("\r\n"))
                    LOG.fich_log(database_path, "received",
                                ip_client , puerto_client, texto)
                    with open('registered.json') as file:
                        fichero = json.load(file)
                    ip_server = fichero[name][0].split(' ')[1]
                    puerto_server = fichero[name][1].split(' ')[1]
                    cabecera_proxy = "VIA Proxy IP: " + server_ip + " PORT: "
                    cabecera_proxy += str(server_puerto) + "\r\n"

                    if name in fichero:
                        my_socket = socket.socket(socket.AF_INET,
                                                  socket.SOCK_DGRAM)
                        my_socket.setsockopt(socket.SOL_SOCKET,
                                             socket.SO_REUSEADDR, 1)
                        my_socket.connect((ip_server, int(puerto_server)))
                        line = cabecera_proxy + line.decode('utf-8')
                        my_socket.send(bytes(line, 'utf-8'))
                        texto = ' '.join(linea.split("\r\n"))
                        LOG.fich_log(database_path, "sent_to",
                                    ip_server , puerto_server, texto)
                elif METODO == 'BYE':
                    linea = line.decode('utf-8')
                    name = linea.split(' ')[2]
                    texto = ' '.join(linea.split("\r\n"))
                    LOG.fich_log(database_path, "received",
                                ip_client , puerto_client, texto)
                    with open('registered.json') as file:
                        fichero = json.load(file)
                    cabecera_proxy = "VIA Proxy IP: " + server_ip + " PORT: "
                    cabecera_proxy += str(server_puerto) + "\r\n"

                    if name in fichero:
                        ip_server = fichero[name][0].split(' ')[1]
                        puerto_server = fichero[name][1].split(' ')[1]
                        my_socket = socket.socket(socket.AF_INET,
                                                  socket.SOCK_DGRAM)
                        my_socket.setsockopt(socket.SOL_SOCKET,
                                             socket.SO_REUSEADDR, 1)
                        my_socket.connect((ip_server, int(puerto_server)))
                        linea = cabecera_proxy + linea
                        my_socket.send(bytes(linea,  'utf-8'))
                        texto = ' '.join(linea.split("\r\n"))
                        LOG.fich_log(database_path, "sent_to",
                                    ip_server, puerto_server, texto)
                        try:
                            data = my_socket.recv(1024)
                        except ConnectionRefusedError or ConnectionResetError:
                            texto = "SIP/2.0 400 Bad Request\r\n"
                            LOG.fich_log(database_path, "sent_to",
                                        ip_client , puerto_client, texto)
                            self.wfile.write(b"SIP/2.0 400 Bad Request\r\n")
                            print("Enviando al cliente: \r\n",
                            "SIP/2.0 400 Bad Request\r\n")
                            texto = ["ERROR: No Connection"]
                            LOG.fich_log(database_path, "received",
                                        ip_client, puerto_client, texto)
                            sys.exit("ERROR: No Connection")
                        juntar = data.decode('utf-8').split("\r\n")
                        texto = ' '.join(juntar)
                        LOG.fich_log(database_path, "received",
                                    ip_server , puerto_server, texto)
                        print("Recibido: \r\n", data.decode('utf-8'))
                        datas = cabecera_proxy + data.decode('utf-8')
                        self.wfile.write(bytes(datas, 'utf-8'))
                        juntar = data.decode('utf-8').split("\r\n")
                        texto = ' '.join(juntar)
                        LOG.fich_log(database_path, "sent_to",
                                    ip_client , puerto_client, texto)
                        print("Enviando: \r\n" + data.decode("utf-8"))
                    else:
                        texto = cabecera_proxy
                        texto += "SIP/2.0 404 User Not Found\r\n"
                        self.wfile.write(bytes(texto , 'utf-8'))
                        print("Enviando: \r\n"
                             + "SIP/2.0 404 User Not Found\r\n")
                        texto = "SIP/2.0 404 User Not Found"
                        LOG.fich_log(database_path, "sent_to",
                                    ip_client , puerto_client, texto)
                elif METODO != ['REGISTER', 'INVITE', 'ACK', ' BYE']:
                    cabecera_proxy = "VIA Proxy IP: " + server_ip + " PORT: "
                    cabecera_proxy += str(server_puerto) + "\r\n"
                    linea = line.decode('utf-8')
                    resultado = line.decode('utf-8')
                    name = linea.split(' ')[2]
                    texto = ' '.join(linea.split("\r\n"))
                    LOG.fich_log(database_path, "received",
                                ip_client, puerto_client, texto)
                    print("Recibido: \r\n", linea)
                    texto = "SIP/2.0 405 Method Not Allowed\r\n"
                    LOG.fich_log(database_path, "sent_to",
                                ip_client , puerto_client, texto)
                    datas = cabecera_proxy
                    datas += 'SIP/2.0 405 Method Not Allowed\r\n'
                    self.wfile.write(bytes(datas, 'utf-8'))
                    print("Enviando: \r\n",
                         "SIP/2.0 405 Method Not Allowed\r\n" )
                if not line or len(linea):
                        break

        self.register2json()

if __name__ == "__main__":
    try:
        (Programa, Config) = sys.argv
    except ValueError or IndexError or FileNotFoundError:
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

    serv = socketserver.UDPServer((server_ip, server_puerto),
                                 SIPRegisterHandler)
    print('Server ' +  server_name + ' listening at port: '
         + str(server_puerto)+ '\n')
    try:
        serv.serve_forever()
    except KeyboardInterrupt:
        print('\n' + "Finalizado servidor")
