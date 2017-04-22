import sys
import os
import socket
import SocketServer
import threading

import time

import miniRSA
from pyDes import *
from Crypto.Cipher import AES
import base64

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS).encode()
unpad = lambda s: s[:-ord(s[len(s) - 1:])]


def iv():
    """
    The initialization vector to use for encryption or decryption.
    It is ignored for MODE_ECB and MODE_CTR.
    """
    return chr(0) * 16


def main():
    """
    Main - Checks for correct input arguments and runs the appropriate methods
    """

    if (len(sys.argv) < 3):
        print 'Usage: python serverclient.py <server|client> <port>\n'
        return -1
    else:
        if sys.argv[1].lower() == 'server':
            Server(sys.argv[2])
        elif sys.argv[1].lower() == 'client':
            Client(sys.argv[2])
        else:
            print 'Unrecognized argument: ', sys.argv[1]
            return -1
    return 0


def Server(port):
    """
    Creates the server instance, sets it up
    """
    host = 'localhost'
    port = int(port)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(5)

    # blocking call to accept()
    print 'Waiting for partner to join conversation...\n'
    (conn, client_addr) = server.accept()
    print 'Client connected: ', client_addr[0]

    # wait to receive encryption algo
    print 'Waiting for cleint to enter algo type...\n'
    algo = conn.recv(1024)

    if (algo == "rsa"):
        # wait to receive client's public key
        key = conn.recv(1024)
        key = key.split(',')
        keyTuple = (key[0], key[1])
        #print 'Client\'s Public Key received'
        #print keyTuple;

        e, d, c = miniRSA.keygen()
        sendPublic = str(d) + ',' + str(c)
        conn.send(sendPublic)
        #print 'Public Key sent'
        privateTuple = (e, c)

        ReadThread = Thread_Manager('read', conn, algo, keyTuple, None)
        WriteThread = Thread_Manager('write', conn, algo, None, privateTuple)

    if (algo == "des"):
        ReadThread = Thread_Manager('read', conn, algo, None, None)
        WriteThread = Thread_Manager('write', conn, algo, None, None)

    if (algo == "3des"):
        ReadThread = Thread_Manager('read', conn, algo, None, None)
        WriteThread = Thread_Manager('write', conn, algo, None, None)

    if (algo == "aes"):
        ReadThread = Thread_Manager('read', conn, algo, None, None)
        WriteThread = Thread_Manager('write', conn, algo, None, None)

    print 'Type your message below and hit enter to send. Type \'EXIT\' to end conversation.\n'
    ReadThread.start()
    WriteThread.start()

    # wait until client dc's
    ReadThread.join()
    print 'Your partner has left the conversation. Press any key to continue...\n'

    # stop the write thread
    WriteThread.stopWrite()
    WriteThread.join()

    # shut down client connection
    try:
        conn.shutdown(socket.SHUT_RDWR)
        conn.close()
    except:
        # connection already closed
        pass

    # shut down server
    print 'Shutting server down...'
    server.shutdown(socket.SHUT_RDWR)
    server.close()

    return 0


def Client(port):
    """
    Creates the client instance, sets up the client
    """

    host = 'localhost'
    port = int(port)

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((host, port))
    print"DES, 3DES, AES, RSA"
    algo = raw_input("Please enter alog: ")
    if (algo == "rsa"):
        client.send(algo)
        e, d, c = miniRSA.keygen()
        sendPublic = str(d) + "," + str(c)
        client.send(sendPublic)
        #print 'Public key sent'

        key = client.recv(1024)
        key = key.split(',')
        keyTuple = (key[0], key[1])
        #print 'Server\'s Public Key received'

        privateTuple = (e, c)

        ReadThread = Thread_Manager('read', client, algo, keyTuple, None)
        WriteThread = Thread_Manager('write', client, algo, None, privateTuple)
    if (algo == "des"):
        client.send(algo)
        ReadThread = Thread_Manager('read', client, algo, None, None)
        WriteThread = Thread_Manager('write', client, algo, None, None)

    if (algo == "3des"):
        client.send(algo)
        ReadThread = Thread_Manager('read', client, algo, None, None)
        WriteThread = Thread_Manager('write', client, algo, None, None)

    if (algo == "aes"):
        client.send(algo)
        ReadThread = Thread_Manager('read', client, algo, None, None)
        WriteThread = Thread_Manager('write', client, algo, None, None)

    print 'Type your message below and hit enter to send. Type \'EXIT\' to end conversation.\n'
    ReadThread.start()
    WriteThread.start()

    ReadThread.join()
    print 'Your partner has left the conversation. Press any key to continue...\n'

    # stop the write thread
    WriteThread.stopWrite()
    WriteThread.join()

    # shut down client connection
    try:
        client.shutdown(socket.SHUT_RDWR)
        client.close()
    except:
        # connection already killed
        pass


class Thread_Manager(threading.Thread):
    """
    Creates threads for asynchronoues reading and writing
    """

    def __init__(self, action, conn, alog, public, private):
        """
        Constructor for Thread_Manager class
        """

        threading.Thread.__init__(self)
        self.action = action.lower()
        self.conn = conn
        self.algo = alog
        self.dowrite = True
        self.exitcode = 'EXIT'

        if public is not None:
            self.setPublic(public)
        if private is not None:
            self.setPrivate(private)

    def run(self):
        """
        Invoked when new thread is executed
        """

        if (self.action == 'read'):
            self.read()
        else:
            self.write()

    def setPublic(self, public):
        """
        Sets public key from other party for decryption
        """

        self.public = public

    def setPrivate(self, private):
        """
        Sets private key for encryption
        """

        self.private = private

    def stopWrite(self):
        """
        Terminates the write loop
        """

        self.dowrite = False

    def des_encrypt(self, buff):
        start = time.time()
        key = des("DESCRYPT", CBC, "\0\0\0\0\0\0\0\0", pad=None, padmode=PAD_PKCS5)
        end = time.time()
        print "Encrypt time: {0:.10f}".format((end - start))
        return key.encrypt(buff)

    def des_decrypt(self, buff):
        start = time.time()
        key = des("DESCRYPT", CBC, "\0\0\0\0\0\0\0\0", pad=None, padmode=PAD_PKCS5)
        end = time.time()
        print "Decrypt time: {0:.10f}".format((end - start))
        return key.decrypt(buff)

    def triple_des_encrypt(self, buff):
        # print len(buff)
        start = time.time()
        key = triple_des("DESCRYPTDESCRYPT", CBC, "\0\0\0\0\0\0\0\0", pad=None, padmode=PAD_PKCS5)
        end = time.time()
        print "Encrypt time: {0:.10f}".format((end - start))
        return key.encrypt(buff)

    def triple_des_decrypt(self, buff):
        # print len(buff)
        start = time.time()
        key = triple_des("DESCRYPTDESCRYPT", CBC, "\0\0\0\0\0\0\0\0", pad=None, padmode=PAD_PKCS5)
        end = time.time()
        print "Decrypt time: {0:.10f}".format((end - start))
        return key.decrypt(buff)

    def aes_encrypt(self, buff):
        """
        It is assumed that you use Python 3.0+
        , so plaintext's type must be str type(== unicode).
        """
        start = time.time()
        message = buff.encode()
        raw = pad(message)
        cipher = AES.new("DESCRYPTDESCRYPT", AES.MODE_CBC, iv())
        enc = cipher.encrypt(raw)
        end = time.time()
        print "Encrypt time: {0:.10f}".format((end - start))
        return base64.b64encode(enc).decode('utf-8')

    def aes_decrypt(self, buff):
        start = time.time()
        buff = base64.b64decode(buff)
        cipher = AES.new("DESCRYPTDESCRYPT", AES.MODE_CBC, iv())
        dec = cipher.decrypt(buff)
        end = time.time()
        print "Decrypt time: {0:.10f}".format((end - start))
        return unpad(dec).decode('utf-8')

    def rsa_decrypt(self, buff):
        """
        Decrypts input integer list into sentences
        """
        start = time.time()
        words = buff.split(",")
        decrypted_data = ""
        # print words;
        # sys.exit();
        for i in range(0, len(words) - 1):
            decrypted_data += str(miniRSA.decode(miniRSA.endecrypt(words[i], self.public[0], self.public[1])))
        end = time.time()
        print "Decrypt time: {0:.10f}".format((end - start))
        print ""
        #print round((end - start), 10)
        return decrypted_data

    def ras_encrypt(self, data):
        start = time.time()
        encrypted_data = ""
        for i in range(0, len(data)):
            encrypted_data += str(miniRSA.endecrypt(ord(data[i]), self.private[0], self.private[1])) + ","
        end = time.time()
        print "Encrypt time: {0:.10f}".format((end - start))
        return encrypted_data



    def read(self):
        """
        Responsible for reading in data from the client and displaying stdout
        """
        buff = self.conn.recv(4096)
        if (self.algo == "rsa"):
            buff = self.rsa_decrypt(buff)
        if (self.algo == "des"):
            buff = self.des_decrypt(buff)
        if (self.algo == "3des"):
            buff = self.triple_des_decrypt(buff)
        if (self.algo == "aes"):
            buff = self.aes_decrypt(buff)

        while buff.strip() != self.exitcode and len(buff) > 0:
            print 'Message received: ', buff.strip()
            #buff = self.rsa_decrypt(buff)
            buff = self.conn.recv(4096)

            if (self.algo == "rsa"):
                buff = self.rsa_decrypt(buff)
            if (self.algo == "des"):
                buff = self.des_decrypt(buff)
            if (self.algo == "3des"):
                buff = self.triple_des_decrypt(buff)
            if (self.algo == "aes"):
                buff = self.aes_decrypt(buff)
        # client disconnected
        self.stopWrite

    def write(self):
        """
        Responsible for reading in data from stdin and sending to client
        """

        while self.dowrite:
            data = sys.stdin.readline()
            if (self.algo == "rsa"):
                data = self.ras_encrypt(data)
            if (self.algo == "des"):
                data = self.des_encrypt(data)
            if (self.algo == "3des"):
                data = self.triple_des_encrypt(data)
            if (self.algo == "aes"):
                data = self.aes_encrypt(data)
            self.conn.send(data)

            if (data.strip() == self.exitcode):
                self.conn.shutdown(socket.SHUT_RDWR)
                self.conn.close()
                self.dowrite = False


# Entry point
if __name__ == "__main__":
    sys.exit(main())