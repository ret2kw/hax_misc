import os
import sys
import getpass
import argparse
import requests

from fuse import FUSE, Operations, LoggingMixIn

# we do this to shutup urllib3 from bitching about certificate checking
requests.packages.urllib3.disable_warnings()



class httpfs(LoggingMixIn, Operations):

    def __init__(self, args):

        self.url = args.url
        self.name = args.name
        self.user = args.user
        self.passwd = getpass.getpass()
        self.root = '.'
 
        """we do a head request to verify that we can connect and we get the size of the file from
            the Content-Length header. This also sets the initial cookie. VSphere is weird in that
            it sets a new cookie on each request.....""" 
        res = requests.head(self.url, verify=False, auth=(self.user, self.passwd))
        if res.status_code == 200:
            self.size = int(res.headers['Content-Length'])
            self.cookie = res.cookies
            print('[*] Connected to VSphere and creating virtual file')

        else:
            print('[*] Error, unable to connect to VSphere, response code %s' % res.status_code)
            sys.exit(-1)

    # nothing implemented here are we only 'mount' a single file, no directories
    def readdir(self, path, fh):
        #print('[*] Reading a dir')
        return ['.', '..', self.name]


    def read(self, path, size, offset, fh):
        """This is just passing the read through to an HTTP request with a Range: Header"""
        
        # calculate the offsets
        bytes_s = offset
        # minus one because we are counting from zero?
        bytes_e = offset + size -1
        value = 'bytes=%s-%s' % (bytes_s, bytes_e)
        range_h = {'Range' : value}        

        res = requests.get(self.url, verify=False, auth=(self.user, self.passwd), cookies=self.cookie, headers=range_h)
        buf = res.content

        # make sure we set the cookie from the response so we can reuse it for the next request
        self.cookie = res.cookies

        return buf

    def _full_path(self, partial):
        """I forgot where I stole this code from, but creates a full path"""

        if partial.startswith("/"):
            partial = partial[1:]
        path = os.path.join(self.root, partial)
        return path


    def getattr(self, path, fh=None):

        full_path = self._full_path(path)
       
        # check to see if we are trying to access our virtual file
        if self.name in full_path:
            #print('[*] looking for %s' % full_path)
            # hardcoding all of this but size if we are trying to stat our the file we are mounting
            st = dict(st_mode=33204, st_nlink=1, st_uid=1000, st_gid=1000, st_size=self.size, st_atime=1432314649, st_mtime=1432314647, st_ctime=1432314647)
            return st

        # if we aren't looking for our virtual file just passthrough to lstat
        else:
            #print('[*] passing lstat through to os')
            st = os.lstat(full_path)
            return dict((key, getattr(st, key)) for key in ('st_atime', 'st_ctime',
                         'st_gid', 'st_mode', 'st_mtime', 'st_nlink', 'st_size', 'st_uid'))

       



if __name__ == '__main__':


    parser = argparse.ArgumentParser(description='Really basic HTTPS Fuse filesystem made to work with VSphere Datastore browser')

    parser.add_argument('--user', required=True, action='store', dest='user', help='VSphere user that has access to Datastore Browser, for domain users use domain\\\\user format')
    parser.add_argument('--url', required=True, action='store', dest='url', help='The full url for where the file is accessed (this link should trigger a d/l)')
    parser.add_argument('--name', required=True, action='store', dest='name', help='The name of the file as you want it to appear within the directory')
    parser.add_argument('--mountpoint', required=True, action='store', dest='mountpoint', help='Directory where you want to add the virtual file')

    args = parser.parse_args()

    # can't use threading due to the whole vsphere cookie deal
    fuse = FUSE(httpfs(args), args.mountpoint , foreground=True, nothreads=True)


