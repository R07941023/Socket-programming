import socket
import struct
import sys, os, time
import threading
from tqdm import tqdm, trange
import json
import pickle
import hashlib

class tool(object):

    def __init__(self):
        pass

    def getip(self):
        s = socket.socket( socket.AF_INET, socket.SOCK_DGRAM )
        s.connect( ('8.8.8.8', 80) )
        ip_address = s.getsockname()[0]
        s.close()
        return ip_address

    def pwd2encode(self, pwd, type=None):
        if type == 'MD5':
            m = hashlib.md5()
            m.update( pwd.encode( "utf-8" ) )
            pwd = m.hexdigest()
        if type == 'SHA':
            m = hashlib.sha1()
            m.update( pwd.encode( "utf-8" ) )
            pwd = m.hexdigest()
        return pwd

class socket_model(object):

    def __init__(self, host, port, max_transfer_speed=1024):
        self.max_transfer_speed = max_transfer_speed
        self.host = host
        self.port = port

    def MAC_filter(self, whitelist, mac_set):
        validation_results = False
        for mac in mac_set:
            if mac in whitelist:
                validation_results = True
                break
        return validation_results

    def common_filter(self, whitelist, candidate, encode=None):
        candidate = tool().pwd2encode(candidate, encode)
        validation_results = False
        if candidate in whitelist:
            validation_results = True
        return validation_results

    def socket_server(self, channel_max, share_file, filter_IP, ip_whitelist, filter_MAC, mac_whitelist, filter_PWD, pwd_whitelist):
        try:
            s = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
            s.setsockopt( socket.SOL_SOCKET, socket.SO_REUSEADDR, 1 )
            s.bind( (self.host, self.port) )
            s.listen( channel_max )
        except socket.error as msg:
            print( msg )
            sys.exit( 1 )
        print( 'Waiting connection...', '\n'  )
        while True:
            conn, addr = s.accept()
            vert_ip, vert_mac, vert_pwd = True, True, True
            # IP filter
            if filter_IP is True:
                vert_ip = self.common_filter(ip_whitelist, addr[0])
            conn.send( str( vert_ip ).encode() )
            # MAC filter
            mac_set = pickle.loads(conn.recv( 1024 ))
            if filter_MAC is True:
                vert_mac = self.MAC_filter(mac_whitelist, mac_set)
            conn.send( str( vert_mac ).encode() )
            # password filter
            pwd = conn.recv( 1024 ).decode()
            if filter_PWD is True:
                vert_pwd = self.common_filter( pwd_whitelist, pwd, encode='MD5')
            conn.send( str( vert_pwd ).encode() )
            print( 'IP security verification: ', vert_ip )
            print( 'MAC security verification: ', vert_mac )
            print( 'Pwssword security verification: ', vert_pwd )
            if vert_ip or vert_mac or vert_pwd:
                print('Pass security verification...', '\n' )
                t = threading.Thread( target=self.deal_data, args=(conn, addr, share_file) )
                t.start()
            else:
                print('Login block: ', addr[0], '\n' )

    def deal_data(self, conn, addr, share_file):
        ti = time.time()
        # progress = tqdm( total=100 )
        print( 'Accept new connection from {0}'.format( addr ) )
        # conn.settimeout(500)
        conn.send( ('Hi, Welcome to the server!').encode() )
        while True:
            type = conn.recv(1024).decode()
            if type == 'download':
                if len(share_file) == 0:
                    print( 'There is no share file!' )
                    conn.send( ('None').encode() )
                    conn.send( ('None').encode() )
                for mini_share_file in share_file:
                    if os.path.isfile( mini_share_file ):
                        conn.send( ('the file is exist').encode() )
                        fhead = struct.pack( '128sl', (os.path.basename( mini_share_file )).encode(), os.stat( mini_share_file ).st_size )
                        conn.send( fhead )
                        fp = open( mini_share_file, 'rb' )
                        while True:
                            data = fp.read( self.max_transfer_speed )
                            if not data:
                                print( '{0} file send over...'.format( mini_share_file ) )
                                break
                            conn.send( data )
                    else:
                        print('The file: ', mini_share_file, 'is not exist!')
                        conn.send(('None').encode())
                        conn.send( os.path.basename(mini_share_file).encode() )
            elif type == 'upload':
                fileinfo_size = struct.calcsize( '128sl' )
                buf = conn.recv( fileinfo_size )
                if buf:
                    recvd_size = 0
                    filename, filesize = struct.unpack( '128sl', buf )
                    origin_filename = filename.strip( ('\00').encode() )
                    new_filename = os.path.join( './', origin_filename.decode() )
                    print( 'file new name is {0}, filesize if {1}'.format( new_filename, filesize ) )
                    fp = open( new_filename, 'wb' )
                    print( 'start receiving...' )
                    while not recvd_size == filesize:
                        if filesize - recvd_size > 0:
                            data = conn.recv( self.max_transfer_speed )
                            # if recvd_size == 0:
                                # data = data[4:]
                            recvd_size += len( data )
                        else:
                            break
                        if set( data ) != {0}:
                            fp.write( data )
                        progress_rate = round( recvd_size * 100 / filesize, 2 )
                        if progress_rate >= 100:
                            progress_rate = 100
                        elif progress_rate <= 0:
                            progress_rate = 0
                        # progress.update( progress_rate )
                        print( 'progress=', progress_rate, '%' )
                    conn.send(('Success !').encode())
                    fp.close()
                    print( 'end receive...' )
            elif type == 'msg':
                msg = conn.recv( 1024 ).decode()
                conn.send(msg.encode())
                print( "Request: ", msg )
                print( "Response: ", msg )
            conn.close()
            break
        tf = time.time()
        print('Runtime = ', tf-ti, '[s]', '\n' )
        print( '' )

    def socket_client(self, request, pwd='123', type='msg', fileinfo_size='128sl'):
        connect = False
        try:
            s = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
            print( 'Wait to connect the server...\n' )
            s.connect( (self.host, self.port) )
            # IP filter
            vert_ip = json.loads( (s.recv( 1024 ).decode()).lower() )
            # MAC filter
            mac_set = self.MAC_get()
            s.send(pickle.dumps(mac_set))
            vert_mac = json.loads( (s.recv( 1024 ).decode()).lower() )
            # pwd filter
            pwd = tool().pwd2encode(pwd, type='SHA')
            s.send( pwd.encode() )
            vert_pwd = json.loads( (s.recv( 1024 ).decode()).lower() )
            print( 'IP security verification: ', vert_ip )
            print( 'MAC security verification: ', vert_mac )
            print( 'Pwssword security verification: ', vert_pwd )
            if vert_ip or vert_mac or vert_pwd:
                print( 'Success to connect the server', '\n' )
                connect = True
            else:
                print( 'Validation failed (Unregistered) !', '\n' )
                sys.exit( 1 )
        except socket.error as msg:
            print( msg )
            sys.exit( 1 )
        print( "Response: ", s.recv( 1024 ).decode() )
        while connect:
            ti = time.time()
            s.send( type.encode() )
            if type == 'msg':
                s.send( request.encode() )
                print( "Request: ", request )
                print( "Response: ", s.recv( self.max_transfer_speed ).decode() )
                tf = time.time()
                print( 'Runtime = ', (tf - ti), '[s]' )
                break
            if type == 'upload':
                if os.path.isfile( request ):
                    fhead = struct.pack( fileinfo_size, (os.path.basename( request )).encode(), os.stat( request ).st_size )
                    s.send( fhead )
                fp = open( request, 'rb' )
                while True:
                    data = fp.read( self.max_transfer_speed )
                    if not data:
                        print( '{0} file send over...'.format( request ) )
                        break
                    s.send( data )
                print( "Request: ", request )
                print( "Response: ", s.recv( 1024 ).decode() )
                tf = time.time()
                print( 'Runtime = ', (tf - ti), '[s]' )
                break
            if type == 'download':
                print( "Request: ", type )
                fileinfo_size = struct.calcsize('128sl')
                file_exist = s.recv(1024).decode()
                if file_exist == 'None':
                    print( "Response: Download failed:", s.recv( 1024 ).decode() )
                    break
                else:
                    buf = s.recv(fileinfo_size)
                    if buf:
                        recvd_size = 0
                        filename, filesize = struct.unpack('128sl', buf)
                        origin_filename = filename.strip(('\00').encode())
                        new_filename = os.path.join('./', origin_filename.decode())
                        print('file new name is {0}, filesize is {1}'.format(new_filename, filesize))
                        fp = open(new_filename, 'wb')
                        print('start receiving...')
                        while recvd_size <= filesize:
                            if filesize - recvd_size > 0:
                                data = s.recv(self.max_transfer_speed)
                                # if recvd_size == 0:
                                    # data = data[4:]
                                    # pass
                                recvd_size += len(data)
                            else:
                                break
                            if set(data) != {0}:
                                fp.write(data)
                            progress_rate = round( recvd_size * 100 / filesize, 2 )
                            if progress_rate >= 100:
                                progress_rate = 100
                            elif progress_rate <= 0:
                                progress_rate = 0
                            # progress.update( progress_rate )
                            print( 'progress=', progress_rate, '%' )
                        fp.close()
                        print('end receive...')
                    print( 'file path = ', new_filename )
                    tf = time.time()
                    print( 'Runtime = ', (tf - ti), '[s]' , '\n' )
                    break
        s.close()

    def MAC_get(self):
        hostname = socket.gethostname()
        detail = socket.getaddrinfo( hostname, None, 0, socket.SOCK_STREAM )
        result = [x[4][0] for x in detail]
        result = result[:int( len( result ) / 2 )]
        return result

# if __name__ == '__main__':
#     port = 80
#     channel_max = 5
#     max_transfer_speed = 40  # byte/s
#     filter_IP,  ip_whitelist = True, []
#     ip_whitelist.append( '140.112.21.98' )  # NTU Lab425
#     ip_whitelist.append( '115.43.132.160' )  # yenying Lu
#     host = fn.tool().getip()
#     fn.socket_model(host=host, port=port, max_transfer_speed=max_transfer_speed).socket_server(channel_max=channel_max, filter_IP=filter_IP, ip_whitelist=ip_whitelist)

# client
if __name__ == '__main__':
    # client setting
    host = '115.43.132.160'
    port = 80
    max_transfer_speed = 1024
    password = 'NTUS_socket'

    # massage
    request = 'start'
    socket_model( host=host, port=port ).socket_client( request=request, type='msg', pwd=password )

    # upload
    request = 'E:/台灣體育大學/test/log.txt'
    socket_model(host=host, port=port, max_transfer_speed=max_transfer_speed).socket_client(request=request, type='upload', pwd=password)

    # download
    # socket_model(host=host, port=port, max_transfer_speed=max_transfer_speed).socket_client(request=None, type='download', pwd=password)