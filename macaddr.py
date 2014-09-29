import sys
import time
import pickle
import telnetlib
from multiprocessing import Manager
from threading import Thread

class mac_getter(Thread):

    def __init__(self, host, macdb, user, passwd):
        self.host = host
        self.macdb = macdb
        self.user = user
        self.passwd = passwd
        super(mac_getter, self).__init__()

    def run(self):

        self.macdb[self.host] = {}

        try:
            tn = telnetlib.Telnet(self.host)

        except:
            print '[*] Error connecting to:  %s ' % self.host
            sys.exit(-1)

        tn.read_until('Username: ')
        tn.write(self.user + '\n')
        time.sleep(1)
        try:
            tn.read_until('Password: ')
        except:
            print '[*] Error trying to get password prompt on: %s' % self.host
            sys.exit(-1)
        tn.write(self.passwd + '\n')
        time.sleep(1)
        tn.write('terminal length 0\n')
        time.sleep(0.2)
        tn.write('sh mac-address-table\n')
        time.sleep(2)
        output = tn.read_very_eager()
        #print output

        tmp = {}

        for line in output.split('\n'):
            try:
                splitted = line.split('    ')
                macaddr = splitted[1].strip()
                port = splitted[3].strip()
                
                try:
                    #print 'trying to append %s to %s' % (port,self.host)
                    tmp[macaddr].append(port)
                except KeyError:
                    #print 'no previous entry adding %s to %s' % (port,self.host)
                    tmp[macaddr] = [port]

            except IndexError:
                pass

        self.macdb[self.host] = tmp
        time.sleep(0.5)
        tn.write('exit\n')
        time.sleep(0.2)
        tn.close()

if __name__ == "__main__":
   
    macaddr = sys.argv[1]
    print macaddr
 
    mgr = Manager()
    macdb = mgr.dict()

    username = #insert username here
    passwd = #insert password here

    threads = []

    for num in xrange(1,36):
        ip = '10.110.1.' + str(num)
        threads.append(mac_getter(ip, macdb))

    for t in threads:
        t.start()

    for t in threads:
        t.join()

    for ip in macdb.keys():
       try:
           port = macdb[ip][macaddr]
           print ip,port
       except:
           pass

    bar = macdb.copy()
    pickle.dump(bar, open('save.p', 'wb'))


